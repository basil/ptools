use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use nix::libc;

use crate::proc_source::ProcSource;

/// Coredump backend: reads process data from systemd-coredump journal fields.
///
/// Constructed from a core file path. Extended attributes on the file provide
/// initial metadata (pid, comm, exe, etc.). Remaining fields will be filled
/// in from the systemd journal once that is implemented.
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
    /// (pid, comm, exe, uid, gid, signal, etc.). The xattrs may be absent if
    /// the file was copied without preserving them; we do our best.
    ///
    /// TODO: Page through the systemd journal to find the matching entry and
    /// fill in remaining fields (COREDUMP_PROC_STATUS, COREDUMP_ENVIRON,
    /// COREDUMP_CMDLINE, COREDUMP_OPEN_FDS, COREDUMP_PROC_LIMITS, etc.).
    pub fn from_corefile(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{}: no such file", path.display()),
            ));
        }

        // Phase 1: read what we can from extended attributes.
        let mut fields = HashMap::new();
        for &(xattr_name, field_name) in XATTR_MAP {
            if let Some(value) = get_xattr(path, xattr_name) {
                fields.insert(field_name.to_string(), value);
            }
        }

        // TODO: Phase 2: page through the systemd journal to find the
        // matching entry (keyed by COREDUMP_PID + COREDUMP_TIMESTAMP or
        // similar) and merge in all remaining fields (COREDUMP_PROC_STATUS,
        // COREDUMP_ENVIRON, COREDUMP_CMDLINE, COREDUMP_OPEN_FDS,
        // COREDUMP_PROC_LIMITS, COREDUMP_PROC_AUXV, etc.).

        let pid = extract_pid(&fields).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: could not determine PID (no xattrs and journal lookup \
                     not yet implemented)",
                    path.display(),
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

    /// Synthesize a `/proc/[pid]/stat`-like line from status fields.
    fn synthesize_stat(&self) -> io::Result<String> {
        let status = self.get_field_str("COREDUMP_PROC_STATUS")?;
        let comm = extract_status_field(status, "Name").unwrap_or("?");
        let state = extract_status_field(status, "State")
            .and_then(|s| s.chars().next())
            .unwrap_or('?');
        let ppid = extract_status_field(status, "PPid").unwrap_or("0");
        // Fields 1-44, zeros where unknown.
        let mut stat = format!("{} ({}) {} {}", self.pid, comm, state, ppid);
        for _ in 5..=44 {
            stat.push_str(" 0");
        }
        stat.push('\n');
        Ok(stat)
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
        self.synthesize_stat()
    }

    fn read_status(&self) -> io::Result<String> {
        self.get_field_str("COREDUMP_PROC_STATUS")
            .map(str::to_string)
    }

    fn read_comm(&self) -> io::Result<String> {
        let comm = self.get_field_str("COREDUMP_COMM")?;
        // /proc/[pid]/comm has a trailing newline
        Ok(format!("{}\n", comm))
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

    fn read_mem(&self, _offset: u64, _len: usize) -> io::Result<Vec<u8>> {
        Err(unsupported("process memory"))
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

/// Extract a field value from `/proc/[pid]/status`-formatted text.
fn extract_status_field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix(':') {
                return Some(value.trim());
            }
        }
    }
    None
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
