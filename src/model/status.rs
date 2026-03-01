//
//   Copyright (c) 2026 Basil Crow
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

use std::collections::BTreeSet;
use std::io::BufRead;
use std::io::{self};

use super::FromBufRead;

/// Parsed fields from `/proc/[pid]/status` (or equivalent core data).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Status {
    pub ppid: Option<u64>,
    pub ruid: Option<u32>,
    pub euid: Option<u32>,
    pub suid: Option<u32>,
    pub fsuid: Option<u32>,
    pub rgid: Option<u32>,
    pub egid: Option<u32>,
    pub sgid: Option<u32>,
    pub fsgid: Option<u32>,
    pub groups: Option<Vec<u32>>,
    pub umask: Option<u32>,
    pub threads: Option<usize>,
    pub sig_ign: Option<BTreeSet<usize>>,
    pub sig_cgt: Option<BTreeSet<usize>>,
    pub sig_blk: Option<BTreeSet<usize>>,
    pub sig_pnd: Option<BTreeSet<usize>>,
    pub shd_pnd: Option<BTreeSet<usize>>,
    pub cpus_allowed: Option<BTreeSet<usize>>,
}

/// Build a `BTreeSet<usize>` of 1-indexed signal numbers from an iterator of
/// nibbles (4-bit values) ordered from least-significant to most-significant.
fn nibbles_to_signal_set(nibbles: impl Iterator<Item = u8>) -> BTreeSet<usize> {
    let mut set = BTreeSet::new();
    for (nibble_idx, nibble) in nibbles.enumerate() {
        for bit in 0..4u8 {
            if (nibble & (1 << bit)) != 0 {
                set.insert(nibble_idx * 4 + bit as usize + 1);
            }
        }
    }
    set
}

/// Convert a raw u64 bitmask to a `BTreeSet<usize>` of 1-indexed signal numbers.
pub fn signal_bitmask_to_set(val: u64) -> BTreeSet<usize> {
    nibbles_to_signal_set((0..16).map(|i| ((val >> (i * 4)) & 0xf) as u8))
}

/// Parse a hex signal mask (e.g. from `SigIgn`) into a set of 1-indexed signal numbers.
pub fn parse_signal_mask(s: &str) -> io::Result<BTreeSet<usize>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty signal mask",
        ));
    }
    let nibbles: Vec<u8> = trimmed
        .bytes()
        .rev()
        .map(|ch| match ch {
            b'0'..=b'9' => Ok(ch - b'0'),
            b'a'..=b'f' => Ok(ch - b'a' + 10),
            b'A'..=b'F' => Ok(ch - b'A' + 10),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid hex character '{}' in mask '{}'",
                    ch as char, trimmed
                ),
            )),
        })
        .collect::<io::Result<_>>()?;
    Ok(nibbles_to_signal_set(nibbles.into_iter()))
}

/// Parse a kernel list-format string like `"0-3,5,7-8"` into a `BTreeSet<usize>`.
pub fn parse_cpuset_list(s: &str) -> io::Result<BTreeSet<usize>> {
    let s = s.trim();
    let mut set = BTreeSet::new();
    if s.is_empty() {
        return Ok(set);
    }
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let start_trimmed = start.trim();
            let start: usize = start_trimmed.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid range start '{start_trimmed}': {e}"),
                )
            })?;
            let end_trimmed = end.trim();
            let end: usize = end_trimmed.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid range end '{end_trimmed}': {e}"),
                )
            })?;
            if start > end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid range {start}-{end}: start > end"),
                ));
            }
            const MAX_CPUS: usize = 8192;
            if end - start + 1 > MAX_CPUS {
                let span = end - start + 1;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "range {start}-{end} spans {span} values, exceeding limit of {MAX_CPUS}",
                    ),
                ));
            }
            for cpu in start..=end {
                set.insert(cpu);
            }
        } else {
            let val: usize = part.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid value '{part}': {e}"),
                )
            })?;
            set.insert(val);
        }
    }
    Ok(set)
}

/// Parse a whitespace-separated list of 4 IDs (used for Uid/Gid lines).
fn parse_id_quad(key: &str, value: &str) -> io::Result<[u32; 4]> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{key}: expected 4 fields, got {}", parts.len()),
        ));
    }
    let mut ids = [0u32; 4];
    for (i, part) in parts.iter().enumerate() {
        ids[i] = part.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{key}: invalid value '{part}': {e}"),
            )
        })?;
    }
    Ok(ids)
}

impl FromBufRead for Status {
    fn from_buf_read(reader: impl BufRead) -> io::Result<Self> {
        let mut data = Status::default();

        for line in reader.lines() {
            let line = line?;
            if let Some((key, value)) = line.split_once(':') {
                let value = value.trim();
                match key {
                    "PPid" => {
                        data.ppid = value
                            .parse()
                            .map_err(|e| eprintln!("warning: PPid: invalid value '{value}': {e}"))
                            .ok();
                    }
                    "Uid" => match parse_id_quad("Uid", value) {
                        Ok(ids) => {
                            data.ruid = Some(ids[0]);
                            data.euid = Some(ids[1]);
                            data.suid = Some(ids[2]);
                            data.fsuid = Some(ids[3]);
                        }
                        Err(e) => eprintln!("warning: {e}"),
                    },
                    "Gid" => match parse_id_quad("Gid", value) {
                        Ok(ids) => {
                            data.rgid = Some(ids[0]);
                            data.egid = Some(ids[1]);
                            data.sgid = Some(ids[2]);
                            data.fsgid = Some(ids[3]);
                        }
                        Err(e) => eprintln!("warning: {e}"),
                    },
                    "Groups" => {
                        data.groups = value
                            .split_whitespace()
                            .map(|s| s.parse::<u32>())
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|e| eprintln!("warning: Groups: invalid value: {e}"))
                            .ok();
                    }
                    "Umask" => {
                        data.umask = u32::from_str_radix(value, 8)
                            .map_err(|e| eprintln!("warning: Umask: invalid value '{value}': {e}"))
                            .ok();
                    }
                    "Threads" => {
                        data.threads = value
                            .parse()
                            .map_err(|e| {
                                eprintln!("warning: Threads: invalid value '{value}': {e}")
                            })
                            .ok();
                    }
                    "SigIgn" => {
                        data.sig_ign = parse_signal_mask(value)
                            .map_err(|e| eprintln!("warning: SigIgn: {e}"))
                            .ok();
                    }
                    "SigCgt" => {
                        data.sig_cgt = parse_signal_mask(value)
                            .map_err(|e| eprintln!("warning: SigCgt: {e}"))
                            .ok();
                    }
                    "SigBlk" => {
                        data.sig_blk = parse_signal_mask(value)
                            .map_err(|e| eprintln!("warning: SigBlk: {e}"))
                            .ok();
                    }
                    "SigPnd" => {
                        data.sig_pnd = parse_signal_mask(value)
                            .map_err(|e| eprintln!("warning: SigPnd: {e}"))
                            .ok();
                    }
                    "ShdPnd" => {
                        data.shd_pnd = parse_signal_mask(value)
                            .map_err(|e| eprintln!("warning: ShdPnd: {e}"))
                            .ok();
                    }
                    "Cpus_allowed_list" => {
                        data.cpus_allowed = parse_cpuset_list(value)
                            .map_err(|e| eprintln!("warning: Cpus_allowed_list: {e}"))
                            .ok();
                    }
                    _ => {}
                }
            }
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_signal_mask ---------------------------------------------------

    #[test]
    fn parse_empty_mask() {
        let set = parse_signal_mask("0000000000000000").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn parse_single_signal() {
        // Bit 0 of nibble 0 -> signal 1 (SIGHUP)
        let set = parse_signal_mask("0000000000000001").unwrap();
        assert!(set.contains(&1));
        assert!(!set.contains(&2));
    }

    #[test]
    fn parse_multiple_signals() {
        // 0x3 = bits 0,1 -> signals 1,2
        let set = parse_signal_mask("0000000000000003").unwrap();
        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(!set.contains(&3));
    }

    #[test]
    fn parse_error_on_empty() {
        assert!(parse_signal_mask("").is_err());
    }

    #[test]
    fn parse_error_on_invalid_hex() {
        assert!(parse_signal_mask("xyz").is_err());
    }

    #[test]
    fn parse_yields_correct_signals() {
        // 0x5 = bits 0,2 -> signals 1,3
        let set = parse_signal_mask("5").unwrap();
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![1, 3]);
    }

    // -- FromBufRead for Status ----------------------------------------------

    #[test]
    fn status_parses_uid_gid() {
        let input = "Uid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\n";
        let status = Status::from_buf_read(input.as_bytes()).unwrap();
        assert_eq!(status.ruid, Some(1000));
        assert_eq!(status.euid, Some(1000));
        assert_eq!(status.rgid, Some(100));
    }

    #[test]
    fn status_parses_signal_masks() {
        let input = "SigIgn:\t0000000000000004\nSigCgt:\t0000000000000002\n";
        let status = Status::from_buf_read(input.as_bytes()).unwrap();
        assert_eq!(
            status
                .sig_ign
                .as_ref()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(
            status
                .sig_cgt
                .as_ref()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![2]
        );
    }
}
