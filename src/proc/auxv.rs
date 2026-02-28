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

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::io::{self};
use std::mem::size_of;
use std::path::Path;

use nix::libc;

use super::ProcHandle;

// Not yet in the libc crate for Linux (only Android).
const AT_RSEQ_FEATURE_SIZE: u64 = 27;
const AT_RSEQ_ALIGN: u64 = 28;

/// An auxiliary vector entry type (`AT_*` constant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxvType {
    Null,
    Ignore,
    ExecFd,
    Phdr,
    PhEnt,
    PhNum,
    PageSz,
    Base,
    Flags,
    Entry,
    NotElf,
    Uid,
    Euid,
    Gid,
    Egid,
    ClkTck,
    Platform,
    Hwcap,
    Hwcap2,
    Secure,
    BasePlatform,
    Random,
    ExecFn,
    SysinfoEhdr,
    MinSigStkSz,
    RseqFeatureSize,
    RseqAlign,
    Unknown(u64),
}

#[allow(clippy::unnecessary_cast)]
impl From<u64> for AuxvType {
    fn from(v: u64) -> Self {
        match v {
            x if x == libc::AT_NULL as u64 => Self::Null,
            x if x == libc::AT_IGNORE as u64 => Self::Ignore,
            x if x == libc::AT_EXECFD as u64 => Self::ExecFd,
            x if x == libc::AT_PHDR as u64 => Self::Phdr,
            x if x == libc::AT_PHENT as u64 => Self::PhEnt,
            x if x == libc::AT_PHNUM as u64 => Self::PhNum,
            x if x == libc::AT_PAGESZ as u64 => Self::PageSz,
            x if x == libc::AT_BASE as u64 => Self::Base,
            x if x == libc::AT_FLAGS as u64 => Self::Flags,
            x if x == libc::AT_ENTRY as u64 => Self::Entry,
            x if x == libc::AT_NOTELF as u64 => Self::NotElf,
            x if x == libc::AT_UID as u64 => Self::Uid,
            x if x == libc::AT_EUID as u64 => Self::Euid,
            x if x == libc::AT_GID as u64 => Self::Gid,
            x if x == libc::AT_EGID as u64 => Self::Egid,
            x if x == libc::AT_CLKTCK as u64 => Self::ClkTck,
            x if x == libc::AT_PLATFORM as u64 => Self::Platform,
            x if x == libc::AT_HWCAP as u64 => Self::Hwcap,
            x if x == libc::AT_HWCAP2 as u64 => Self::Hwcap2,
            x if x == libc::AT_SECURE as u64 => Self::Secure,
            x if x == libc::AT_BASE_PLATFORM as u64 => Self::BasePlatform,
            x if x == libc::AT_RANDOM as u64 => Self::Random,
            x if x == libc::AT_EXECFN as u64 => Self::ExecFn,
            x if x == libc::AT_SYSINFO_EHDR as u64 => Self::SysinfoEhdr,
            x if x == libc::AT_MINSIGSTKSZ as u64 => Self::MinSigStkSz,
            x if x == AT_RSEQ_FEATURE_SIZE => Self::RseqFeatureSize,
            x if x == AT_RSEQ_ALIGN => Self::RseqAlign,
            other => Self::Unknown(other),
        }
    }
}

impl AuxvType {
    pub fn is_uid(self) -> bool {
        matches!(self, Self::Uid | Self::Euid)
    }

    pub fn is_gid(self) -> bool {
        matches!(self, Self::Gid | Self::Egid)
    }

    pub fn is_string_pointer(self) -> bool {
        matches!(self, Self::ExecFn | Self::Platform | Self::BasePlatform)
    }
}

/// A single entry from the auxiliary vector.
pub struct AuxvEntry {
    pub key: AuxvType,
    pub value: u64,
}

/// Parsed auxiliary vector with metadata about the originating process.
pub struct AuxvData {
    pub entries: Vec<AuxvEntry>,
    /// Word size of the process (4 for 32-bit, 8 for 64-bit).
    pub word_size: usize,
}

fn parse_word(chunk: &[u8], word_size: usize) -> io::Result<u64> {
    match word_size {
        4 => {
            let raw: [u8; 4] = chunk.try_into().map_err(|_| {
                super::parse_error(
                    "auxv",
                    &format!("invalid 32-bit word length {}", chunk.len()),
                )
            })?;
            Ok(u32::from_ne_bytes(raw) as u64)
        }
        8 => {
            let raw: [u8; 8] = chunk.try_into().map_err(|_| {
                super::parse_error(
                    "auxv",
                    &format!("invalid 64-bit word length {}", chunk.len()),
                )
            })?;
            Ok(u64::from_ne_bytes(raw))
        }
        n => Err(super::parse_error(
            "auxv",
            &format!("unsupported word size {}", n),
        )),
    }
}

fn parse_auxv_records(bytes: &[u8], word_size: usize) -> io::Result<Vec<AuxvEntry>> {
    let record_size = word_size
        .checked_mul(2)
        .ok_or_else(|| super::parse_error("auxv", "record size overflow"))?;
    if record_size == 0 || !bytes.len().is_multiple_of(record_size) {
        return Err(super::parse_error(
            "auxv",
            &format!("unexpected size {}", bytes.len()),
        ));
    }

    let mut result = Vec::new();
    let mut saw_terminator = false;
    for chunk in bytes.chunks_exact(record_size) {
        let raw_key = parse_word(&chunk[..word_size], word_size)?;
        let value = parse_word(&chunk[word_size..record_size], word_size)?;
        if raw_key == 0 {
            saw_terminator = true;
            break;
        }
        result.push(AuxvEntry {
            key: AuxvType::from(raw_key),
            value,
        });
    }

    if !saw_terminator {
        return Err(super::parse_error("auxv", "missing AT_NULL terminator"));
    }

    Ok(result)
}

fn elf_word_size_from_path(exe_path: &Path) -> Option<usize> {
    let mut exe_file = File::open(exe_path).ok()?;
    let mut header = [0u8; 5];
    exe_file.read_exact(&mut header).ok()?;

    if header[..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }

    match header[4] {
        1 => Some(4), // ELFCLASS32
        2 => Some(8), // ELFCLASS64
        _ => None,
    }
}

/// Read and parse the auxiliary vector from a process handle.
pub(crate) fn read_auxv(handle: &ProcHandle) -> io::Result<AuxvData> {
    let bytes = handle.auxv_bytes()?;

    if bytes.is_empty() {
        return Err(super::parse_error("auxv", "empty file"));
    }

    let native_word_size = size_of::<usize>();
    let mut candidate_word_sizes = Vec::new();
    if let Ok(exe_path) = handle.exe() {
        if let Some(ws) = elf_word_size_from_path(&exe_path) {
            candidate_word_sizes.push(ws);
        }
    }
    candidate_word_sizes.push(native_word_size);
    candidate_word_sizes.push(4);
    candidate_word_sizes.push(8);

    let mut seen = HashSet::new();
    for word_size in candidate_word_sizes {
        if !seen.insert(word_size) {
            continue;
        }

        if let Ok(entries) = parse_auxv_records(&bytes, word_size) {
            return Ok(AuxvData { entries, word_size });
        }
    }

    Err(super::parse_error(
        "auxv",
        &format!("unexpected format ({} bytes)", bytes.len()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auxv_records_64_bit() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(6u64).to_ne_bytes()); // AT_PAGESZ
        bytes.extend_from_slice(&(4096u64).to_ne_bytes());
        bytes.extend_from_slice(&(0u64).to_ne_bytes()); // AT_NULL
        bytes.extend_from_slice(&(0u64).to_ne_bytes());

        let auxv = parse_auxv_records(&bytes, 8).expect("parse 64-bit auxv");
        assert_eq!(auxv.len(), 1);
        assert_eq!(auxv[0].key, AuxvType::PageSz);
        assert_eq!(auxv[0].value, 4096);
    }

    #[test]
    fn parse_auxv_records_32_bit() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(6u32).to_ne_bytes()); // AT_PAGESZ
        bytes.extend_from_slice(&(4096u32).to_ne_bytes());
        bytes.extend_from_slice(&(0u32).to_ne_bytes()); // AT_NULL
        bytes.extend_from_slice(&(0u32).to_ne_bytes());

        let auxv = parse_auxv_records(&bytes, 4).expect("parse 32-bit auxv");
        assert_eq!(auxv.len(), 1);
        assert_eq!(auxv[0].key, AuxvType::PageSz);
        assert_eq!(auxv[0].value, 4096);
    }

    #[test]
    fn parse_auxv_records_rejects_missing_terminator() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(6u64).to_ne_bytes());
        bytes.extend_from_slice(&(4096u64).to_ne_bytes());

        assert!(parse_auxv_records(&bytes, 8).is_err());
    }
}
