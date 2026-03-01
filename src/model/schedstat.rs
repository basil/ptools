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

use std::io::Read;
use std::io::{self};

use super::FromRead;

/// Scheduler statistics from `/proc/[pid]/schedstat`.
#[derive(Debug, Clone)]
pub struct SchedStat {
    pub run_time_ns: u64,
    pub wait_time_ns: u64,
    pub timeslices: u64,
}

impl FromRead for SchedStat {
    fn from_read(reader: impl Read) -> io::Result<Self> {
        const MAX_SCHEDSTAT_BYTES: u64 = 4096;
        let mut buf = String::new();
        reader.take(MAX_SCHEDSTAT_BYTES).read_to_string(&mut buf)?;

        let mut parts = buf.split_whitespace();
        let mut next_field = |name: &str| -> io::Result<u64> {
            parts
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("schedstat: missing {name} field"),
                    )
                })?
                .parse::<u64>()
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("schedstat: failed to parse {name}: {e}"),
                    )
                })
        };

        Ok(SchedStat {
            run_time_ns: next_field("run_time_ns")?,
            wait_time_ns: next_field("wait_time_ns")?,
            timeslices: next_field("timeslices")?,
        })
    }
}
