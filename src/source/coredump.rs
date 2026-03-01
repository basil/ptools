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

use std::cell::OnceCell;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use nix::libc;

use super::dw::CoreDwfl;
use super::elf::CoreElf;
use super::elf::Prpsinfo;
use super::elf::Prstatus;
use super::systemd::lookup_journal_fields;
use super::ProcSource;
use crate::model;
use crate::model::auxv::ByteOrder;
use crate::model::status::signal_bitmask_to_set;
use crate::model::FromBufRead;

/// Coredump backend: reads process data from systemd-coredump journal fields.
///
/// Constructed from a core file path. Extended attributes on the file provide
/// initial metadata (pid, comm, exe, etc.). Rich fields (environ, cmdline,
/// auxv, open fds, limits, proc status) are filled in from the systemd
/// journal entry matching the coredump.
pub(super) struct CoredumpSource {
    fields: HashMap<String, Vec<u8>>,
    core_dwfl: OnceCell<Option<CoreDwfl>>,
    core_elf: Option<Arc<CoreElf>>,
    pid: OnceCell<u64>,
    tids: OnceCell<Vec<u64>>,
    notes: OnceCell<ParsedNotes>,
}

/// Lazily parsed ELF note data, converted to high-level model types.
struct ParsedNotes {
    comm: Option<String>,
    cmdline: Option<Vec<u8>>,
    auxv: Option<model::auxv::Auxv>,
    utime_us: Option<u64>,
    stime_us: Option<u64>,
    cutime_us: Option<u64>,
    cstime_us: Option<u64>,
    num_threads: usize,
    tid_stat: HashMap<u64, model::stat::Stat>,
    tid_status: HashMap<u64, model::status::Status>,
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
    pub(super) fn from_corefile(path: &Path, core_elf: Option<&Arc<CoreElf>>) -> io::Result<Self> {
        let file_exists = path.exists();

        // Read what we can from extended attributes (only possible if
        // the core file is still on disk).
        let mut fields = HashMap::new();
        if file_exists {
            for &(xattr_name, field_name) in XATTR_MAP {
                if let Some(value) = get_xattr(path, xattr_name) {
                    fields.insert(field_name.to_string(), value);
                }
            }
        }

        // Look up the matching journal entry and merge in all
        // COREDUMP_* fields not already present from xattrs.
        let journal_fields = lookup_journal_fields(path, &fields);
        if journal_fields.is_empty() {
            if core_elf.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "{}: core file missing and no matching journal entry found",
                        path.display()
                    ),
                ));
            }
            eprintln!(
                "warning: no matching journal entry found for {}; \
                 output will be limited to core file metadata",
                path.display()
            );
        } else if core_elf.is_none() {
            eprintln!(
                "warning: core file {} no longer exists; \
                 using journal entry only",
                path.display()
            );
        }
        for (key, value) in journal_fields {
            fields.entry(key).or_insert(value);
        }

        Ok(CoredumpSource {
            fields,
            core_dwfl: OnceCell::new(),
            core_elf: core_elf.map(Arc::clone),
            pid: OnceCell::new(),
            tids: OnceCell::new(),
            notes: OnceCell::new(),
        })
    }

    /// Lazily create and cache the dwfl session.
    ///
    /// Returns `None` if there is no core ELF or if creation fails.
    fn ensure_core_dwfl(&self) -> Option<&CoreDwfl> {
        self.core_dwfl
            .get_or_init(|| {
                let core_elf = match self.core_elf.as_ref() {
                    Some(e) => e,
                    None => return None,
                };
                match CoreDwfl::new(Arc::clone(core_elf)) {
                    Ok(d) => Some(d),
                    Err(e) => {
                        eprintln!("warning: failed to create dwfl session: {e}");
                        None
                    }
                }
            })
            .as_ref()
    }

    fn get_field(&self, key: &str) -> io::Result<&[u8]> {
        self.fields.get(key).map(|v| v.as_slice()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("field {key} not available"),
            )
        })
    }

    fn get_field_str(&self, key: &str) -> io::Result<&str> {
        let bytes = self.get_field(key)?;
        std::str::from_utf8(bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("field {key} is not valid UTF-8: {e}"),
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
                format!("fd {fd} not found in COREDUMP_OPEN_FDS"),
            )
        })
    }

    /// Lazily parse all ELF notes and convert to high-level model types.
    fn notes(&self) -> &ParsedNotes {
        self.notes.get_or_init(|| {
            let (prstatus_map, prpsinfo, auxv_bytes) = match self.core_elf.as_ref() {
                Some(elf) => elf.parse_notes(),
                None => (HashMap::new(), None, None),
            };

            let comm = prpsinfo.as_ref().map(|p| p.pr_fname.clone());

            let cmdline = prpsinfo.as_ref().and_then(|p| {
                if p.pr_psargs.is_empty() {
                    None
                } else {
                    let mut bytes = p.pr_psargs.as_bytes().to_vec();
                    bytes.push(0);
                    Some(bytes)
                }
            });

            let auxv = auxv_bytes.and_then(|bytes| {
                model::auxv::Auxv::from_read(bytes.as_slice(), self.word_size(), self.byte_order())
                    .ok()
            });

            let num_threads = prstatus_map.len();

            let mut tid_stat: HashMap<u64, model::stat::Stat> = prstatus_map
                .iter()
                .map(|(&tid, prstatus)| (tid, prstatus_to_stat(prpsinfo.as_ref(), Some(prstatus))))
                .collect();

            let mut tid_status: HashMap<u64, model::status::Status> = prstatus_map
                .iter()
                .map(|(&tid, prstatus)| {
                    (tid, prstatus_to_status(prpsinfo.as_ref(), Some(prstatus)))
                })
                .collect();

            // If prpsinfo exists but no prstatus for the main thread,
            // insert a partial entry derived from prpsinfo alone.
            let pid = self.pid();
            if prpsinfo.is_some() && !tid_stat.contains_key(&pid) {
                tid_stat.insert(pid, prstatus_to_stat(prpsinfo.as_ref(), None));
                tid_status.insert(pid, prstatus_to_status(prpsinfo.as_ref(), None));
            }

            let (utime_us, stime_us, cutime_us, cstime_us) = prstatus_map
                .get(&pid)
                .or_else(|| prstatus_map.values().next())
                .map(|p| {
                    (
                        Some(p.pr_utime_sec * 1_000_000 + p.pr_utime_usec),
                        Some(p.pr_stime_sec * 1_000_000 + p.pr_stime_usec),
                        Some(p.pr_cutime_sec * 1_000_000 + p.pr_cutime_usec),
                        Some(p.pr_cstime_sec * 1_000_000 + p.pr_cstime_usec),
                    )
                })
                .unwrap_or((None, None, None, None));

            ParsedNotes {
                comm,
                cmdline,
                auxv,
                utime_us,
                stime_us,
                cutime_us,
                cstime_us,
                num_threads,
                tid_stat,
                tid_status,
            }
        })
    }
}

/// Build a [`model::stat::Stat`] from prpsinfo and/or prstatus notes.
fn prstatus_to_stat(prpsinfo: Option<&Prpsinfo>, prstatus: Option<&Prstatus>) -> model::stat::Stat {
    model::stat::Stat {
        state: prpsinfo.map(|p| model::stat::ProcState::from(p.pr_sname)),
        ppid: prstatus
            .map(|p| p.pr_ppid as u64)
            .or_else(|| prpsinfo.map(|p| p.pr_ppid as u64)),
        pgrp: prstatus
            .map(|p| p.pr_pgrp as u64)
            .or_else(|| prpsinfo.map(|p| p.pr_pgrp as u64)),
        sid: prstatus
            .map(|p| p.pr_sid as u64)
            .or_else(|| prpsinfo.map(|p| p.pr_sid as u64)),
        nice: prpsinfo.map(|p| p.pr_nice as i32),
        ..model::stat::Stat::default()
    }
}

/// Build a [`model::status::Status`] from prpsinfo and/or prstatus notes.
fn prstatus_to_status(
    prpsinfo: Option<&Prpsinfo>,
    prstatus: Option<&Prstatus>,
) -> model::status::Status {
    model::status::Status {
        ppid: prstatus
            .map(|p| p.pr_ppid as u64)
            .or_else(|| prpsinfo.map(|p| p.pr_ppid as u64)),
        ruid: prpsinfo.map(|p| p.pr_uid),
        rgid: prpsinfo.map(|p| p.pr_gid),
        sig_blk: prstatus.map(|p| signal_bitmask_to_set(p.pr_sighold)),
        sig_pnd: prstatus.map(|p| signal_bitmask_to_set(p.pr_sigpend)),
        ..model::status::Status::default()
    }
}

impl ProcSource for CoredumpSource {
    fn pid(&self) -> u64 {
        *self.pid.get_or_init(|| {
            // Try dwfl first (authoritative pid from core ELF notes).
            if let Some(core_dwfl) = self.ensure_core_dwfl() {
                return core_dwfl.pid() as u64;
            }
            // Fall back to journal/xattr metadata.
            match extract_pid(&self.fields) {
                Ok(pid) => pid,
                Err(_) => {
                    eprintln!("warning: could not determine PID from core file");
                    0
                }
            }
        })
    }

    fn read_comm(&self) -> io::Result<String> {
        if let Ok(s) = self.get_field_str("COREDUMP_COMM") {
            return Ok(s.to_string());
        }
        self.notes().comm.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "comm not available from coredump",
            )
        })
    }

    fn read_cmdline(&self) -> io::Result<Vec<u8>> {
        if let Ok(b) = self.get_field("COREDUMP_CMDLINE") {
            return Ok(b.to_vec());
        }
        self.notes().cmdline.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "cmdline not available from coredump",
            )
        })
    }

    fn read_environ(&self) -> io::Result<Vec<u8>> {
        self.get_field("COREDUMP_ENVIRON").map(|b| b.to_vec())
    }

    fn read_auxv(&self) -> io::Result<model::auxv::Auxv> {
        // Try the journal field first, then fall back to the ELF NT_AUXV note.
        if let Ok(bytes) = self.get_field("COREDUMP_PROC_AUXV") {
            return model::auxv::Auxv::from_read(bytes, self.word_size(), self.byte_order());
        }
        self.notes().auxv.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "auxv data not found in coredump",
            )
        })
    }

    fn read_stat(&self) -> io::Result<model::stat::Stat> {
        let notes = self.notes();
        let pid = self.pid();
        match notes.tid_stat.get(&pid) {
            Some(stat) => {
                let mut stat = stat.clone();
                if notes.num_threads > 0 {
                    stat.num_threads = Some(notes.num_threads as u64);
                }
                Ok(stat)
            }
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "stat not available from coredump",
            )),
        }
    }

    fn read_status(&self) -> io::Result<model::status::Status> {
        // Prefer the journal's COREDUMP_PROC_STATUS (full /proc/pid/status snapshot).
        if let Ok(text) = self.get_field_str("COREDUMP_PROC_STATUS") {
            return model::status::Status::from_buf_read(text.as_bytes());
        }
        // Fall back to prstatus/prpsinfo notes for the main thread.
        let notes = self.notes();
        let pid = self.pid();
        match notes.tid_status.get(&pid) {
            Some(status) => {
                let mut status = status.clone();
                if notes.num_threads > 0 {
                    status.threads = Some(notes.num_threads);
                }
                Ok(status)
            }
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "status not available from coredump",
            )),
        }
    }

    fn read_utime_us(&self) -> io::Result<u64> {
        self.notes().utime_us.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "high-precision utime not available from coredump",
            )
        })
    }

    fn read_stime_us(&self) -> io::Result<u64> {
        self.notes().stime_us.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "high-precision stime not available from coredump",
            )
        })
    }

    fn read_cutime_us(&self) -> io::Result<u64> {
        self.notes().cutime_us.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "high-precision cutime not available from coredump",
            )
        })
    }

    fn read_cstime_us(&self) -> io::Result<u64> {
        self.notes().cstime_us.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "high-precision cstime not available from coredump",
            )
        })
    }

    fn read_exe(&self) -> io::Result<PathBuf> {
        let exe = self.get_field_str("COREDUMP_EXE")?;
        Ok(PathBuf::from(exe))
    }

    fn read_limits(&self) -> io::Result<model::limits::Limits> {
        let text = self.get_field_str("COREDUMP_PROC_LIMITS")?;
        model::limits::Limits::from_buf_read(text.as_bytes())
    }

    fn read_schedstat(&self) -> io::Result<model::schedstat::SchedStat> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "schedstat not available from coredump",
        ))
    }

    fn list_tids(&self) -> io::Result<Vec<u64>> {
        Ok(self
            .tids
            .get_or_init(|| {
                // Try dwfl first (actual threads from core file).
                if let Some(core_dwfl) = self.ensure_core_dwfl() {
                    match core_dwfl.collect_tids() {
                        Ok(tids) => return tids,
                        Err(e) => {
                            eprintln!("warning: could not enumerate threads from core: {e}");
                        }
                    }
                }
                // Fall back to just the main thread.
                vec![self.pid()]
            })
            .clone())
    }

    fn read_tid_stat(&self, tid: u64) -> io::Result<model::stat::Stat> {
        self.notes().tid_stat.get(&tid).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("thread {tid} not available from coredump"),
            )
        })
    }

    fn read_tid_status(&self, tid: u64) -> io::Result<model::status::Status> {
        // Main thread: prefer journal string, fall back to notes.
        if tid == self.pid() {
            if let Ok(text) = self.get_field_str("COREDUMP_PROC_STATUS") {
                return model::status::Status::from_buf_read(text.as_bytes());
            }
        }
        self.notes().tid_status.get(&tid).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("thread {tid} not available from coredump"),
            )
        })
    }

    fn list_fds(&self) -> io::Result<Vec<u64>> {
        let entries = self.parse_open_fds()?;
        Ok(entries.into_iter().map(|e| e.fd).collect())
    }

    fn read_fd_link(&self, fd: u64) -> io::Result<PathBuf> {
        let entry = self.find_fd_entry(fd)?;
        Ok(PathBuf::from(entry.path))
    }

    fn read_fdinfo(&self, fd: u64) -> io::Result<model::fdinfo::FdInfo> {
        let entry = self.find_fd_entry(fd)?;
        model::fdinfo::FdInfo::from_buf_read(entry.fdinfo.as_bytes())
    }

    fn read_net_file(&self, _name: &str) -> io::Result<Box<dyn io::BufRead>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "network info not available from coredump",
        ))
    }

    fn word_size(&self) -> usize {
        self.core_elf
            .as_ref()
            .and_then(|elf| elf.word_size())
            .unwrap_or(std::mem::size_of::<usize>())
    }

    fn byte_order(&self) -> ByteOrder {
        self.core_elf
            .as_ref()
            .and_then(|elf| elf.byte_order())
            .unwrap_or(if cfg!(target_endian = "big") {
                ByteOrder::Big
            } else {
                ByteOrder::Little
            })
    }

    fn read_memory(&self, addr: u64, buf: &mut [u8]) -> bool {
        match self.core_elf.as_ref() {
            Some(elf) => elf.read_memory(addr, buf),
            None => false,
        }
    }

    fn trace_thread(
        &self,
        tid: u32,
        options: &crate::stack::TraceOptions,
    ) -> Vec<crate::stack::Frame> {
        let core_dwfl = match self.ensure_core_dwfl() {
            Some(d) => d,
            None => {
                eprintln!("warning: error tracing thread {tid}: no dwfl session");
                return Vec::new();
            }
        };
        match core_dwfl.walk_thread_frames(tid, options) {
            Ok(frames) => frames,
            Err(e) => {
                eprintln!("warning: error tracing thread {tid}: {e}");
                Vec::new()
            }
        }
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
            format!("COREDUMP_PID is not valid UTF-8: {e}"),
        )
    })?;
    s.parse::<u64>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("COREDUMP_PID '{s}' is not a valid integer: {e}"),
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

        // Parse "FD_NUM:PATH" -- split on first ':'
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
                format!("{l}\n")
            })
            .collect();

        entries.push(FdEntry { fd, path, fdinfo });
    }

    entries
}
