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

//! Parser for Ubuntu/Debian apport `.crash` files.
//!
//! Apport stores crash data in Debian control syntax.  Text fields are
//! stored verbatim; large binary fields (like the core dump) are stored
//! as base64-encoded gzip data.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;

/// Mapping from apport field names to COREDUMP_* field names.
const FIELD_MAP: &[(&str, &str)] = &[
    ("ProcCmdline", "COREDUMP_CMDLINE"),
    ("ProcCwd", "COREDUMP_CWD"),
    ("ProcEnviron", "COREDUMP_ENVIRON"),
    ("ExecutablePath", "COREDUMP_EXE"),
    ("ProcMaps", "COREDUMP_PROC_MAPS"),
    ("ProcStatus", "COREDUMP_PROC_STATUS"),
    ("ProcAttrCurrent", "COREDUMP_PROC_ATTR_CURRENT"),
];

/// Quick sniff: check if a file looks like an apport crash file.
pub(super) fn is_apport_crash(path: &Path) -> bool {
    let Ok(f) = File::open(path) else {
        return false;
    };
    let mut reader = BufReader::new(f);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line).is_err() {
        return false;
    }
    first_line.starts_with("ProblemType:")
}

/// Parse text fields from an apport crash file into COREDUMP_* fields.
///
/// Stops at the first binary field (value is literally `base64`).
/// Returns an error if no recognized fields are found.
pub(super) fn parse_crash_fields(path: &Path) -> io::Result<HashMap<String, Vec<u8>>> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut fields = HashMap::new();

    let mut current_key: Option<String> = None;
    let mut current_value = String::new();

    for line in reader.lines() {
        let line = line?;

        if let Some(continuation) = line.strip_prefix(' ') {
            // Continuation line: strip leading space, append to current value.
            if current_key.is_some() {
                if !current_value.is_empty() {
                    current_value.push('\n');
                }
                current_value.push_str(continuation);
            }
        } else if let Some((key, value)) = line.split_once(": ") {
            // Flush previous field.
            if let Some(prev_key) = current_key.take() {
                store_field(&mut fields, &prev_key, &current_value);
            }

            // Binary field marker — stop parsing text fields.
            if value == "base64" {
                break;
            }

            current_key = Some(key.to_string());
            current_value = value.to_string();
        } else if line.ends_with(':') {
            // Key with no inline value (multiline follows).
            if let Some(prev_key) = current_key.take() {
                store_field(&mut fields, &prev_key, &current_value);
            }
            current_key = Some(line[..line.len() - 1].to_string());
            current_value = String::new();
        }
    }

    // Flush final field.
    if let Some(key) = current_key.take() {
        store_field(&mut fields, &key, &current_value);
    }

    if fields.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: no recognized apport fields found", path.display()),
        ));
    }

    Ok(fields)
}

/// Map an apport field to a COREDUMP_* field with format conversions.
fn store_field(fields: &mut HashMap<String, Vec<u8>>, key: &str, value: &str) {
    let coredump_name = match FIELD_MAP.iter().find(|(k, _)| *k == key) {
        Some((_, name)) => *name,
        None => return,
    };

    let bytes = match key {
        "ProcCmdline" => {
            // Apport stores cmdline with spaces; convert to NUL-separated.
            let mut b: Vec<u8> = value
                .bytes()
                .map(|c| if c == b' ' { 0 } else { c })
                .collect();
            b.push(0);
            b
        }
        "ProcEnviron" => {
            // Apport stores environ newline-separated; convert to NUL-separated.
            let mut b: Vec<u8> = value
                .bytes()
                .map(|c| if c == b'\n' { 0 } else { c })
                .collect();
            b.push(0);
            b
        }
        "ProcStatus" => {
            // Extract PID from ProcStatus and store separately.
            for line in value.lines() {
                if let Some(rest) = line.strip_prefix("Pid:") {
                    let pid = rest.trim();
                    fields.insert("COREDUMP_PID".to_string(), pid.as_bytes().to_vec());
                    break;
                }
            }
            value.as_bytes().to_vec()
        }
        _ => value.as_bytes().to_vec(),
    };

    fields.insert(coredump_name.to_string(), bytes);
}

/// Extract the CoreDump from an apport crash file into a memfd.
///
/// Streams base64-encoded gzip data through a decompression pipeline
/// without holding the entire encoded or compressed data in memory.
pub(super) fn extract_core_dump(path: &Path) -> io::Result<File> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);

    // Scan to the "CoreDump: base64" line.
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{}: no CoreDump field found", path.display()),
            ));
        }
        if line.starts_with("CoreDump: base64") {
            break;
        }
    }

    // Build streaming pipeline: each continuation line is independently
    // base64-encoded, so we decode per-line then pipe through gzip.
    let continuation = CrashCoreDumpReader::new(reader);
    let mut gz_decoder = flate2::read::GzDecoder::new(continuation);

    let name = c"ptools-apport-core";
    let memfd = nix::sys::memfd::memfd_create(name, nix::sys::memfd::MFdFlags::empty())
        .map_err(io::Error::from)?;
    let mut memfile = File::from(memfd);
    io::copy(&mut gz_decoder, &mut memfile)?;
    memfile.seek(SeekFrom::Start(0))?;
    Ok(memfile)
}

/// Streaming reader that decodes the CoreDump from an apport crash file.
///
/// Each continuation line is independently base64-encoded (with its own
/// padding).  This reader decodes each line separately and yields the
/// concatenated binary output.
struct CrashCoreDumpReader<R> {
    inner: R,
    line_buf: String,
    decoded_buf: Vec<u8>,
    pos: usize,
    done: bool,
}

impl<R: BufRead> CrashCoreDumpReader<R> {
    fn new(inner: R) -> Self {
        CrashCoreDumpReader {
            inner,
            line_buf: String::new(),
            decoded_buf: Vec::new(),
            pos: 0,
            done: false,
        }
    }
}

impl<R: BufRead> Read for CrashCoreDumpReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        use base64::Engine;

        loop {
            // Drain any buffered decoded data first.
            if self.pos < self.decoded_buf.len() {
                let n = std::cmp::min(out.len(), self.decoded_buf.len() - self.pos);
                out[..n].copy_from_slice(&self.decoded_buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }

            if self.done {
                return Ok(0);
            }

            // Read the next line.
            self.line_buf.clear();
            let n = self.inner.read_line(&mut self.line_buf)?;

            if n == 0 {
                self.done = true;
                return Ok(0);
            }

            // Continuation lines start with a space.
            if !self.line_buf.starts_with(' ') {
                self.done = true;
                return Ok(0);
            }

            // Strip leading space and trailing newline, then base64-decode.
            let b64 = self.line_buf[1..].trim_end_matches('\n');
            self.decoded_buf.clear();
            self.pos = 0;
            base64::engine::general_purpose::STANDARD
                .decode_vec(b64, &mut self.decoded_buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
    }
}
