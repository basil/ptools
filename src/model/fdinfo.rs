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

use std::io::BufRead;
use std::io::{self};

use nix::fcntl::OFlag;

use super::FromBufRead;

/// Parsed fdinfo with structured fields from `/proc/[pid]/fdinfo/<fd>`.
#[derive(Debug, Clone)]
pub struct FdInfo {
    pub pos: u64,
    pub flags: OFlag,
    pub ino: Option<u64>,
    pub mnt_id: Option<u64>,
    pub extra_lines: Vec<String>,
}

impl FromBufRead for FdInfo {
    fn from_buf_read(reader: impl BufRead) -> io::Result<Self> {
        let mut pos: Option<u64> = None;
        let mut flags: Option<OFlag> = None;
        let mut ino: Option<u64> = None;
        let mut mnt_id: Option<u64> = None;
        const MAX_EXTRA_LINES: usize = 128;
        let mut extra_lines: Vec<String> = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let Some((key, value)) = line.split_once(':') else {
                eprintln!("warning: fdinfo: could not parse line: {line}");
                continue;
            };
            let key = key.trim();
            let value = value.trim();

            match key {
                "pos" => {
                    pos = Some(value.parse::<u64>().map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("fdinfo: invalid pos value '{value}': {e}"),
                        )
                    })?);
                }
                "flags" => {
                    let bits = i32::from_str_radix(value, 8).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("fdinfo: invalid flags value '{value}': {e}"),
                        )
                    })?;
                    flags = Some(OFlag::from_bits_retain(bits));
                }
                "ino" => match value.parse::<u64>() {
                    Ok(v) => ino = Some(v),
                    Err(e) => eprintln!("warning: fdinfo: could not parse ino '{value}': {e}"),
                },
                "mnt_id" => match value.parse::<u64>() {
                    Ok(v) => mnt_id = Some(v),
                    Err(e) => eprintln!("warning: fdinfo: could not parse mnt_id '{value}': {e}"),
                },
                _ => {
                    if extra_lines.len() < MAX_EXTRA_LINES {
                        extra_lines.push(line.to_string());
                    }
                }
            }
        }

        let pos = pos.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "fdinfo: missing required field 'pos'",
            )
        })?;
        let flags = flags.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "fdinfo: missing required field 'flags'",
            )
        })?;

        Ok(FdInfo {
            pos,
            flags,
            ino,
            mnt_id,
            extra_lines,
        })
    }
}
