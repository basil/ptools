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

use std::collections::HashMap;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::path::Path;

// ---------------------------------------------------------------------------
// libsystemd journal FFI (minimal subset)
// ---------------------------------------------------------------------------

/// Opaque journal handle.
enum SdJournal {}

const SD_JOURNAL_LOCAL_ONLY: c_int = 1;

extern "C" {
    fn sd_journal_open(ret: *mut *mut SdJournal, flags: c_int) -> c_int;
    fn sd_journal_close(j: *mut SdJournal);
    fn sd_journal_add_match(j: *mut SdJournal, data: *const c_void, size: usize) -> c_int;
    fn sd_journal_seek_tail(j: *mut SdJournal) -> c_int;
    fn sd_journal_previous(j: *mut SdJournal) -> c_int;
    fn sd_journal_restart_data(j: *mut SdJournal);
    fn sd_journal_enumerate_data(
        j: *mut SdJournal,
        data: *mut *const c_void,
        length: *mut usize,
    ) -> c_int;
}

/// RAII wrapper for `sd_journal *`.
struct Journal {
    ptr: *mut SdJournal,
}

impl Journal {
    fn open() -> Option<Self> {
        let mut ptr: *mut SdJournal = std::ptr::null_mut();
        let rc = unsafe { sd_journal_open(&mut ptr, SD_JOURNAL_LOCAL_ONLY) };
        if rc < 0 {
            return None;
        }
        Some(Journal { ptr })
    }

    fn add_match(&self, field_eq_value: &[u8]) -> bool {
        unsafe {
            sd_journal_add_match(
                self.ptr,
                field_eq_value.as_ptr().cast(),
                field_eq_value.len(),
            ) >= 0
        }
    }

    fn seek_tail(&self) -> bool {
        unsafe { sd_journal_seek_tail(self.ptr) >= 0 }
    }

    fn previous(&self) -> bool {
        unsafe { sd_journal_previous(self.ptr) > 0 }
    }

    /// Iterate over all fields of the current entry, calling `f` for each.
    /// Each invocation receives the raw bytes `FIELD_NAME=value`.
    fn enumerate_data<F: FnMut(&[u8])>(&self, mut f: F) {
        unsafe { sd_journal_restart_data(self.ptr) };
        loop {
            let mut data: *const c_void = std::ptr::null();
            let mut len: usize = 0;
            let rc = unsafe { sd_journal_enumerate_data(self.ptr, &mut data, &mut len) };
            if rc <= 0 {
                break;
            }
            let slice = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
            f(slice);
        }
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        unsafe { sd_journal_close(self.ptr) };
    }
}

// ---------------------------------------------------------------------------
// Journal lookup
// ---------------------------------------------------------------------------

/// The well-known `MESSAGE_ID` for systemd-coredump journal entries.
const SD_MESSAGE_COREDUMP: &str = "fc2e22bc6ee647b6b90729ab34a250b1";

/// Query the systemd journal for the coredump entry matching `path` and return
/// all `COREDUMP_*` fields found. Returns an empty map on any failure.
pub(super) fn lookup_journal_fields(
    path: &Path,
    existing: &HashMap<String, Vec<u8>>,
) -> HashMap<String, Vec<u8>> {
    let empty = HashMap::new();
    let msg_match = format!("MESSAGE_ID={SD_MESSAGE_COREDUMP}");

    // Primary match: by canonical filename.  The journal stores the path
    // with a compression suffix, but the user may pass either the compressed
    // or uncompressed name.  Try the canonical path first, then alternates
    // with the compression extension stripped or appended.
    const COMPRESSION_EXTS: &[&str] = &["zst", "lz4", "xz", "gz", "bz2"];

    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    let mut alternates = Vec::new();
    if canonical
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| COMPRESSION_EXTS.contains(&e))
    {
        // Compressed path given; also try without the compression extension.
        alternates.push(canonical.with_extension(""));
    } else {
        // Uncompressed path given; also try with each compression extension.
        let base_ext = canonical.extension().unwrap_or_default().to_string_lossy();
        for ext in COMPRESSION_EXTS {
            alternates.push(canonical.with_extension(format!("{base_ext}.{ext}")));
        }
    }

    for candidate in std::iter::once(&canonical).chain(alternates.iter()) {
        // Re-open journal for a fresh set of matches each iteration.
        let journal = match Journal::open() {
            Some(j) => j,
            None => return empty,
        };

        if !journal.add_match(msg_match.as_bytes()) {
            continue;
        }

        let file_match = format!("COREDUMP_FILENAME={}", candidate.display());
        if !journal.add_match(file_match.as_bytes()) {
            continue;
        }

        if !journal.seek_tail() {
            continue;
        }

        if journal.previous() {
            return collect_coredump_fields(&journal);
        }
    }

    // Fallback: match on PID + timestamp from xattrs (file may have been
    // moved/renamed since the coredump was written).
    let pid_bytes = match existing.get("COREDUMP_PID") {
        Some(b) => b,
        None => return empty,
    };
    let ts_bytes = match existing.get("COREDUMP_TIMESTAMP") {
        Some(b) => b,
        None => return empty,
    };

    // Re-open journal for a fresh set of matches.
    let journal = match Journal::open() {
        Some(j) => j,
        None => return empty,
    };

    if !journal.add_match(msg_match.as_bytes()) {
        return empty;
    }

    let mut pid_match = b"COREDUMP_PID=".to_vec();
    pid_match.extend_from_slice(pid_bytes);
    if !journal.add_match(&pid_match) {
        return empty;
    }

    let mut ts_match = b"COREDUMP_TIMESTAMP=".to_vec();
    ts_match.extend_from_slice(ts_bytes);
    if !journal.add_match(&ts_match) {
        return empty;
    }

    if !journal.seek_tail() {
        return empty;
    }

    if journal.previous() {
        return collect_coredump_fields(&journal);
    }

    empty
}

/// Extract all `COREDUMP_*` fields from the current journal entry.
fn collect_coredump_fields(journal: &Journal) -> HashMap<String, Vec<u8>> {
    let mut fields = HashMap::new();
    journal.enumerate_data(|raw| {
        // Each datum is `FIELD_NAME=value` (value may be binary).
        if let Some(eq) = raw.iter().position(|&b| b == b'=') {
            if let Ok(key) = std::str::from_utf8(&raw[..eq]) {
                if key.starts_with("COREDUMP_") {
                    fields.insert(key.to_string(), raw[eq + 1..].to_vec());
                }
            }
        }
    });
    fields
}
