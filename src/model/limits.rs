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
use std::str::FromStr;

use nix::sys::resource::Resource;

use super::FromBufRead;

/// A resource limit value (soft or hard).
///
/// `Unlimited` represents `RLIM_INFINITY`; `Value(n)` represents a finite limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitValue {
    Unlimited,
    Value(u64),
}

impl FromStr for LimitValue {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("unlimited") {
            Ok(LimitValue::Unlimited)
        } else {
            s.parse::<u64>().map(LimitValue::Value)
        }
    }
}

/// Parsed resource limit with soft and hard values and unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limit {
    pub soft: LimitValue,
    pub hard: LimitValue,
    pub unit: Option<String>,
}

/// All resource limits from `/proc/[pid]/limits`.
///
/// Limits are stored as an ordered collection keyed by [`Resource`].
/// Unrecognized kernel limit names are skipped with a warning during
/// parsing, making the parser resilient to kernel version differences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits(Vec<(Resource, Limit)>);

impl Limits {
    /// Iterate over all limits as `(Resource, &Limit)` pairs,
    /// in the order the kernel emits them.
    pub fn iter(&self) -> impl Iterator<Item = (Resource, &Limit)> {
        self.0.iter().map(|(r, l)| (*r, l))
    }

    /// Look up a single resource limit.
    pub fn get(&self, resource: Resource) -> Option<&Limit> {
        self.0
            .iter()
            .find_map(|(r, l)| if *r == resource { Some(l) } else { None })
    }
}

/// Known kernel limit names and their corresponding [`Resource`] variants.
const KERNEL_LIMITS: &[(&str, Resource)] = &[
    ("Max cpu time", Resource::RLIMIT_CPU),
    ("Max file size", Resource::RLIMIT_FSIZE),
    ("Max data size", Resource::RLIMIT_DATA),
    ("Max stack size", Resource::RLIMIT_STACK),
    ("Max core file size", Resource::RLIMIT_CORE),
    ("Max resident set", Resource::RLIMIT_RSS),
    ("Max processes", Resource::RLIMIT_NPROC),
    ("Max open files", Resource::RLIMIT_NOFILE),
    ("Max locked memory", Resource::RLIMIT_MEMLOCK),
    ("Max address space", Resource::RLIMIT_AS),
    ("Max file locks", Resource::RLIMIT_LOCKS),
    ("Max pending signals", Resource::RLIMIT_SIGPENDING),
    ("Max msgqueue size", Resource::RLIMIT_MSGQUEUE),
    ("Max nice priority", Resource::RLIMIT_NICE),
    ("Max realtime priority", Resource::RLIMIT_RTPRIO),
    ("Max realtime timeout", Resource::RLIMIT_RTTIME),
];

/// Map a kernel limit name (e.g. `"Max cpu time"`) to a [`Resource`] variant.
fn kernel_name_to_resource(name: &str) -> Option<Resource> {
    KERNEL_LIMITS
        .iter()
        .find_map(|&(n, r)| if n == name { Some(r) } else { None })
}

/// Parse soft/hard limit values from column strings.
fn parse_limit(soft_str: &str, hard_str: &str, unit: Option<String>) -> io::Result<Limit> {
    let soft = soft_str.parse::<LimitValue>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid soft limit '{soft_str}': {e}"),
        )
    })?;
    let hard = hard_str.parse::<LimitValue>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid hard limit '{hard_str}': {e}"),
        )
    })?;
    Ok(Limit { soft, hard, unit })
}

impl FromBufRead for Limits {
    fn from_buf_read(reader: impl BufRead) -> io::Result<Self> {
        let mut lines = reader.lines();

        // Detect column boundaries from the header.  Columns are separated
        // by runs of 2+ spaces (single spaces appear inside multi-word names
        // like "Soft Limit").  We need at least 3 boundaries (for columns 2-4).
        let header = lines
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "empty limits file"))??;

        let hdr = header.as_bytes();
        let cols: Vec<usize> = (2..header.len())
            .filter(|&i| hdr[i] != b' ' && hdr[i - 1] == b' ' && hdr[i - 2] == b' ')
            .collect();
        if cols.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot detect column boundaries in limits header",
            ));
        }
        let (soft_col, hard_col, units_col) = (cols[0], cols[1], cols[2]);

        let mut limits = Vec::new();

        for line_result in lines {
            let line = line_result?;
            if line.is_empty() {
                continue;
            }

            if line.len() < hard_col {
                eprintln!("warning: skipping malformed limits line: {line}");
                continue;
            }

            let name = line[..soft_col].trim();
            let soft_str = line[soft_col..hard_col].trim();
            let hard_str = line[hard_col..units_col.min(line.len())].trim();
            let unit_str = line.get(units_col..).map(str::trim).unwrap_or("");
            let unit = if unit_str.is_empty() {
                None
            } else {
                Some(unit_str.to_string())
            };

            match kernel_name_to_resource(name) {
                Some(resource) => match parse_limit(soft_str, hard_str, unit) {
                    Ok(limit) => limits.push((resource, limit)),
                    Err(e) => {
                        eprintln!("warning: failed to parse limit values for '{name}': {e}");
                    }
                },
                None => {
                    eprintln!("warning: unknown kernel limit name: '{name}'");
                }
            }
        }

        if limits.len() < KERNEL_LIMITS.len() {
            eprintln!(
                "warning: parsed only {} of {} expected limits",
                limits.len(),
                KERNEL_LIMITS.len()
            );
        }

        Ok(Limits(limits))
    }
}
