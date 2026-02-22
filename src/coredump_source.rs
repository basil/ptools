use std::collections::HashMap;
use std::io;
use std::os::raw::{c_int, c_void};
use std::path::{Path, PathBuf};

use nix::libc;

use crate::proc_source::ProcSource;

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

/// Coredump backend: reads process data from systemd-coredump journal fields.
///
/// Constructed from a core file path. Extended attributes on the file provide
/// initial metadata (pid, comm, exe, etc.). Rich fields (environ, cmdline,
/// auxv, open fds, limits, proc status) are filled in from the systemd
/// journal entry matching the coredump.
pub struct CoredumpSource {
    pid: u64,
    fields: HashMap<String, Vec<u8>>,
}

/// A parsed entry from `COREDUMP_OPEN_FDS`.
struct FdEntry {
    fd: u64,
    path: String,
    fdinfo: String,
}

/// Mapping from `user.coredump.*` extended attributes to `COREDUMP_*` field names.
const XATTR_MAP: &[(&str, &str)] = &[
    ("user.coredump.pid", "COREDUMP_PID"),
    ("user.coredump.uid", "COREDUMP_UID"),
    ("user.coredump.gid", "COREDUMP_GID"),
    ("user.coredump.signal", "COREDUMP_SIGNAL"),
    ("user.coredump.timestamp", "COREDUMP_TIMESTAMP"),
    ("user.coredump.rlimit", "COREDUMP_RLIMIT"),
    ("user.coredump.hostname", "COREDUMP_HOSTNAME"),
    ("user.coredump.comm", "COREDUMP_COMM"),
    ("user.coredump.exe", "COREDUMP_EXE"),
];

impl CoredumpSource {
    /// Create from a core file path.
    ///
    /// Reads `user.coredump.*` extended attributes to populate initial fields
    /// (pid, comm, exe, uid, gid, signal, etc.). Then queries the systemd
    /// journal for the matching coredump entry to fill in rich fields like
    /// `COREDUMP_PROC_STATUS`, `COREDUMP_ENVIRON`, `COREDUMP_CMDLINE`, etc.
    pub fn from_corefile(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{}: no such file", path.display()),
            ));
        }

        // Read what we can from extended attributes.
        let mut fields = HashMap::new();
        for &(xattr_name, field_name) in XATTR_MAP {
            if let Some(value) = get_xattr(path, xattr_name) {
                fields.insert(field_name.to_string(), value);
            }
        }

        // Look up the matching journal entry and merge in all
        // COREDUMP_* fields not already present from xattrs.
        let journal_fields = lookup_journal_fields(path, &fields);
        for (key, value) in journal_fields {
            fields.entry(key).or_insert(value);
        }

        let pid = extract_pid(&fields).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: could not determine PID from xattrs or journal",
                    path.display()
                ),
            )
        })?;
        Ok(CoredumpSource { pid, fields })
    }

    /// Create from a pre-built field map (e.g. from journal bindings).
    pub fn from_fields(fields: HashMap<String, Vec<u8>>) -> io::Result<Self> {
        let pid = extract_pid(&fields)?;
        Ok(CoredumpSource { pid, fields })
    }

    fn get_field(&self, key: &str) -> io::Result<&[u8]> {
        self.fields.get(key).map(|v| v.as_slice()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("field {} not available", key),
            )
        })
    }

    fn get_field_str(&self, key: &str) -> io::Result<&str> {
        let bytes = self.get_field(key)?;
        std::str::from_utf8(bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("field {} is not valid UTF-8: {}", key, e),
            )
        })
    }

    fn parse_open_fds(&self) -> io::Result<Vec<FdEntry>> {
        let text = self.get_field_str("COREDUMP_OPEN_FDS")?;
        Ok(parse_fd_entries(text))
    }

    fn find_fd_entry(&self, fd: u64) -> io::Result<FdEntry> {
        let entries = self.parse_open_fds()?;
        entries.into_iter().find(|e| e.fd == fd).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("fd {} not found in COREDUMP_OPEN_FDS", fd),
            )
        })
    }
}

fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{} not available from coredump", what),
    )
}

impl ProcSource for CoredumpSource {
    fn pid(&self) -> u64 {
        self.pid
    }

    fn read_stat(&self) -> io::Result<String> {
        Err(unsupported("stat"))
    }

    fn read_status(&self) -> io::Result<String> {
        self.get_field_str("COREDUMP_PROC_STATUS")
            .map(str::to_string)
    }

    fn read_comm(&self) -> io::Result<String> {
        self.get_field_str("COREDUMP_COMM").map(str::to_string)
    }

    fn read_cmdline(&self) -> io::Result<Vec<u8>> {
        self.get_field("COREDUMP_CMDLINE").map(|b| b.to_vec())
    }

    fn read_environ(&self) -> io::Result<Vec<u8>> {
        self.get_field("COREDUMP_ENVIRON").map(|b| b.to_vec())
    }

    fn read_auxv(&self) -> io::Result<Vec<u8>> {
        self.get_field("COREDUMP_PROC_AUXV").map(|b| b.to_vec())
    }

    fn read_exe(&self) -> io::Result<PathBuf> {
        let exe = self.get_field_str("COREDUMP_EXE")?;
        Ok(PathBuf::from(exe))
    }

    fn read_limits(&self) -> io::Result<String> {
        self.get_field_str("COREDUMP_PROC_LIMITS")
            .map(str::to_string)
    }

    fn list_tids(&self) -> io::Result<Vec<u64>> {
        Ok(vec![self.pid])
    }

    fn read_tid_stat(&self, tid: u64) -> io::Result<String> {
        if tid == self.pid {
            self.read_stat()
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("thread {} not available from coredump", tid),
            ))
        }
    }

    fn read_tid_status(&self, tid: u64) -> io::Result<String> {
        if tid == self.pid {
            self.read_status()
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("thread {} not available from coredump", tid),
            ))
        }
    }

    fn list_fds(&self) -> io::Result<Vec<u64>> {
        let entries = self.parse_open_fds()?;
        Ok(entries.into_iter().map(|e| e.fd).collect())
    }

    fn read_fd_link(&self, fd: u64) -> io::Result<PathBuf> {
        let entry = self.find_fd_entry(fd)?;
        Ok(PathBuf::from(entry.path))
    }

    fn read_fdinfo(&self, fd: u64) -> io::Result<String> {
        let entry = self.find_fd_entry(fd)?;
        Ok(entry.fdinfo)
    }

    fn read_net_file(&self, _name: &str) -> io::Result<String> {
        Err(unsupported("network info"))
    }
}

// ---------------------------------------------------------------------------
// Journal lookup
// ---------------------------------------------------------------------------

/// The well-known `MESSAGE_ID` for systemd-coredump journal entries.
const SD_MESSAGE_COREDUMP: &str = "fc2e22bc6ee647b6b90729ab34a250b1";

/// Query the systemd journal for the coredump entry matching `path` and return
/// all `COREDUMP_*` fields found. Returns an empty map on any failure.
fn lookup_journal_fields(
    path: &Path,
    existing: &HashMap<String, Vec<u8>>,
) -> HashMap<String, Vec<u8>> {
    let empty = HashMap::new();

    let journal = match Journal::open() {
        Some(j) => j,
        None => return empty,
    };

    // Match coredump entries by MESSAGE_ID.
    let msg_match = format!("MESSAGE_ID={}", SD_MESSAGE_COREDUMP);
    if !journal.add_match(msg_match.as_bytes()) {
        return empty;
    }

    // Primary match: by canonical filename.
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let file_match = format!("COREDUMP_FILENAME={}", canonical.display());
    if !journal.add_match(file_match.as_bytes()) {
        return empty;
    }

    if !journal.seek_tail() {
        return empty;
    }

    if journal.previous() {
        return collect_coredump_fields(&journal);
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

// ---------------------------------------------------------------------------
// Extended attribute helpers
// ---------------------------------------------------------------------------

/// Read a single extended attribute from a file, returning None on any error.
fn get_xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let c_name = CString::new(name).ok()?;

    // First call: get the value size.
    let size = unsafe { libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let n = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

// ---------------------------------------------------------------------------
// Field parsing helpers
// ---------------------------------------------------------------------------

fn extract_pid(fields: &HashMap<String, Vec<u8>>) -> io::Result<u64> {
    let bytes = fields
        .get("COREDUMP_PID")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing COREDUMP_PID field"))?;
    let s = std::str::from_utf8(bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("COREDUMP_PID is not valid UTF-8: {}", e),
        )
    })?;
    s.parse::<u64>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("COREDUMP_PID '{}' is not a valid integer: {}", s, e),
        )
    })
}

/// Parse the `COREDUMP_OPEN_FDS` field into fd entries.
///
/// Format: entries separated by blank lines, each entry is:
/// ```text
/// FD_NUM:PATH
/// key:\tvalue
/// key:\tvalue
/// ```
fn parse_fd_entries(text: &str) -> Vec<FdEntry> {
    let mut entries = Vec::new();

    for block in text.split("\n\n") {
        let block = block.trim();
        if block.is_empty() {
            continue;
        }
        let mut lines = block.lines();
        let header = match lines.next() {
            Some(h) => h,
            None => continue,
        };

        // Parse "FD_NUM:PATH" — split on first ':'
        let (fd_str, path) = match header.split_once(':') {
            Some((f, p)) => (f, p),
            None => continue,
        };

        let fd = match fd_str.trim().parse::<u64>() {
            Ok(fd) => fd,
            Err(_) => continue,
        };

        let path = path.to_string();

        // Remaining lines are fdinfo key-value pairs
        let fdinfo: String = lines
            .map(|l| {
                // Convert "key:\tvalue" to "key:\tvalue\n" (matching /proc fdinfo format)
                format!("{}\n", l)
            })
            .collect();

        entries.push(FdEntry { fd, path, fdinfo });
    }

    entries
}
