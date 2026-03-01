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

use std::io::{self, Read};

use super::FromRead;

/// Process state from `/proc/[pid]/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    Running,
    Sleeping,
    Waiting,
    Zombie,
    Stopped,
    Tracing,
    Dead,
    Wakekill,
    Waking,
    Parked,
    Idle,
    /// A state character not covered by the known variants.
    Other(char),
}

impl From<char> for ProcState {
    fn from(c: char) -> Self {
        match c {
            'R' => Self::Running,
            'S' => Self::Sleeping,
            'D' => Self::Waiting,
            'Z' => Self::Zombie,
            'T' => Self::Stopped,
            't' => Self::Tracing,
            'X' | 'x' => Self::Dead,
            'K' => Self::Wakekill,
            'W' => Self::Waking,
            'P' => Self::Parked,
            'I' => Self::Idle,
            other => Self::Other(other),
        }
    }
}

/// Parsed fields from `/proc/[pid]/stat` (or equivalent core data).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Stat {
    pub state: Option<ProcState>,
    pub ppid: Option<u64>,
    pub pgrp: Option<u64>,
    pub sid: Option<u64>,
    pub utime: Option<u64>,
    pub stime: Option<u64>,
    pub cutime: Option<u64>,
    pub cstime: Option<u64>,
    pub nice: Option<i32>,
    pub num_threads: Option<u64>,
    pub starttime: Option<u64>,
    pub processor: Option<u32>,
}

impl FromRead for Stat {
    fn from_read(reader: impl Read) -> io::Result<Self> {
        const MAX_STAT_BYTES: u64 = 4096;
        let mut buf = String::new();
        reader.take(MAX_STAT_BYTES).read_to_string(&mut buf)?;

        // The format is:
        // pid (comm) state ppid pgrp session tty_nr tpgid flags
        // minflt cminflt majflt cmajflt utime stime cutime cstime
        // priority nice num_threads itrealvalue starttime vsize rss
        // ... more fields ...
        //
        // The comm field is wrapped in parens and may contain spaces,
        // so we find the last ')' to split reliably.

        let comm_end = buf.rfind(')').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing closing ')' for comm field in stat",
            )
        })?;

        let after_comm = buf[comm_end + 1..].trim();

        // Fields after comm: state ppid pgrp session tty_nr tpgid flags
        //                    minflt cminflt majflt cmajflt utime stime cutime cstime
        //                    priority nice num_threads itrealvalue starttime vsize rss ...
        // Index (0-based):   0      1    2    3       4      5     6
        //                    7      8       9      10      11    12    13     14
        //                    15       16   17          18          19        20   21 ...
        let fields: Vec<&str> = after_comm.split_whitespace().collect();

        fn try_parse<T: std::str::FromStr>(fields: &[&str], idx: usize) -> Option<T> {
            let s = *fields.get(idx)?;
            match s.parse::<T>() {
                Ok(v) => Some(v),
                Err(_) => {
                    eprintln!("warning: stat: could not parse field {idx}: '{s}'");
                    None
                }
            }
        }

        Ok(Stat {
            state: fields
                .first()
                .and_then(|s| s.chars().next())
                .map(ProcState::from),
            ppid: try_parse(&fields, 1),
            pgrp: try_parse(&fields, 2),
            sid: try_parse(&fields, 3),
            utime: try_parse(&fields, 11),
            stime: try_parse(&fields, 12),
            cutime: try_parse(&fields, 13),
            cstime: try_parse(&fields, 14),
            nice: try_parse(&fields, 16),
            num_threads: try_parse(&fields, 17),
            starttime: try_parse(&fields, 19),
            processor: try_parse(&fields, 36),
        })
    }
}
