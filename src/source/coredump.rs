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
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use nix::libc;

use super::dw::CoreDwfl;
use super::elf::CoreElf;
use super::elf::Prpsinfo;
use super::elf::Prstatus;
use super::ProcSource;
use crate::model;
use crate::model::auxv::ByteOrder;
use crate::model::status::signal_bitmask_to_set;
use crate::model::FromBufRead;

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
pub(super) struct CoredumpSource {
    fields: HashMap<String, Vec<u8>>,
    core_dwfl: OnceCell<Option<CoreDwfl>>,
    core_elf: Option<Arc<CoreElf>>,
    pid: OnceCell<u64>,
    tids: OnceCell<Vec<u64>>,
    prpsinfo: OnceCell<Option<Prpsinfo>>,
    auxv_bytes: OnceCell<Option<Vec<u8>>>,
    prstatus_map: OnceCell<HashMap<u64, Prstatus>>,
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
            prpsinfo: OnceCell::new(),
            auxv_bytes: OnceCell::new(),
            prstatus_map: OnceCell::new(),
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

    /// Lazily parse and cache all ELF notes (prstatus, prpsinfo, auxv).
    fn ensure_notes(&self) {
        self.prstatus_map
            .get_or_init(|| match self.core_elf.as_ref() {
                Some(elf) => {
                    let (map, prpsinfo, auxv) = elf.parse_notes();
                    let _ = self.prpsinfo.set(prpsinfo);
                    let _ = self.auxv_bytes.set(auxv);
                    map
                }
                None => {
                    let _ = self.prpsinfo.set(None);
                    let _ = self.auxv_bytes.set(None);
                    HashMap::new()
                }
            });
    }
}

/// Convert a timeval (sec, usec) to approximate clock ticks.
fn timeval_to_ticks(sec: u64, usec: u64) -> u64 {
    // sysconf(_SC_CLK_TCK) is typically 100 on Linux.
    let hz = unsafe { nix::libc::sysconf(nix::libc::_SC_CLK_TCK) };
    let hz = if hz > 0 { hz as u64 } else { 100 };
    sec.saturating_mul(hz)
        .saturating_add(usec.saturating_mul(hz) / 1_000_000)
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
        utime: prstatus.map(|p| timeval_to_ticks(p.pr_utime_sec, p.pr_utime_usec)),
        stime: prstatus.map(|p| timeval_to_ticks(p.pr_stime_sec, p.pr_stime_usec)),
        cutime: prstatus.map(|p| timeval_to_ticks(p.pr_cutime_sec, p.pr_cutime_usec)),
        cstime: prstatus.map(|p| timeval_to_ticks(p.pr_cstime_sec, p.pr_cstime_usec)),
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

    fn read_stat(&self) -> io::Result<model::stat::Stat> {
        let pid = self.pid();
        self.ensure_notes();
        let prpsinfo = self
            .prpsinfo
            .get()
            .expect("ensure_notes initialized")
            .as_ref();
        let prstatus_map = self.prstatus_map.get().expect("ensure_notes initialized");
        let prstatus = prstatus_map.get(&pid);
        if prstatus.is_some() || prpsinfo.is_some() {
            let mut stat = prstatus_to_stat(prpsinfo, prstatus);
            if !prstatus_map.is_empty() {
                stat.num_threads = Some(prstatus_map.len() as u64);
            }
            return Ok(stat);
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "stat not available from coredump",
        ))
    }

    fn read_status(&self) -> io::Result<model::status::Status> {
        // Prefer the journal's COREDUMP_PROC_STATUS (full /proc/pid/status snapshot).
        if let Ok(text) = self.get_field_str("COREDUMP_PROC_STATUS") {
            return model::status::Status::from_buf_read(text.as_bytes());
        }
        // Fall back to prstatus/prpsinfo notes for the main thread.
        let pid = self.pid();
        self.ensure_notes();
        let prpsinfo = self
            .prpsinfo
            .get()
            .expect("ensure_notes initialized")
            .as_ref();
        let prstatus_map = self.prstatus_map.get().expect("ensure_notes initialized");
        let prstatus = prstatus_map.get(&pid);
        if prstatus.is_some() || prpsinfo.is_some() {
            let mut status = prstatus_to_status(prpsinfo, prstatus);
            if !prstatus_map.is_empty() {
                status.threads = Some(prstatus_map.len());
            }
            return Ok(status);
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "status not available from coredump",
        ))
    }

    fn read_comm(&self) -> io::Result<String> {
        if let Ok(s) = self.get_field_str("COREDUMP_COMM") {
            return Ok(s.to_string());
        }
        self.ensure_notes();
        if let Some(prpsinfo) = self
            .prpsinfo
            .get()
            .expect("ensure_notes initialized")
            .as_ref()
        {
            return Ok(prpsinfo.pr_fname.clone());
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "comm not available from coredump",
        ))
    }

    fn read_cmdline(&self) -> io::Result<Vec<u8>> {
        if let Ok(b) = self.get_field("COREDUMP_CMDLINE") {
            return Ok(b.to_vec());
        }
        // Fall back to prpsinfo pr_psargs as a single opaque argument.
        // pr_psargs is a space-joined, truncated kernel rendering of the
        // command line -- we cannot recover original argv boundaries from it,
        // so return it whole rather than fabricating entries by splitting on
        // spaces.
        self.ensure_notes();
        if let Some(prpsinfo) = self
            .prpsinfo
            .get()
            .expect("ensure_notes initialized")
            .as_ref()
        {
            if !prpsinfo.pr_psargs.is_empty() {
                let mut bytes = prpsinfo.pr_psargs.as_bytes().to_vec();
                bytes.push(0);
                return Ok(bytes);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cmdline not available from coredump",
        ))
    }

    fn read_environ(&self) -> io::Result<Vec<u8>> {
        self.get_field("COREDUMP_ENVIRON").map(|b| b.to_vec())
    }

    fn read_auxv(&self) -> io::Result<model::auxv::Auxv> {
        // Try the journal field first, then fall back to the ELF NT_AUXV note.
        let bytes = match self.get_field("COREDUMP_PROC_AUXV") {
            Ok(b) => b,
            Err(_) => {
                // Trigger note parsing so auxv_bytes gets populated.
                self.ensure_notes();
                match self.auxv_bytes.get().and_then(|o| o.as_deref()) {
                    Some(b) => b,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "auxv data not found in coredump",
                        ))
                    }
                }
            }
        };

        model::auxv::Auxv::from_read(bytes, self.word_size(), self.byte_order())
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
        self.ensure_notes();
        let prpsinfo = self
            .prpsinfo
            .get()
            .expect("ensure_notes initialized")
            .as_ref();
        let prstatus = self
            .prstatus_map
            .get()
            .expect("ensure_notes initialized")
            .get(&tid);
        if prstatus.is_some() {
            Ok(prstatus_to_stat(prpsinfo, prstatus))
        } else if tid == self.pid() && prpsinfo.is_some() {
            Ok(prstatus_to_stat(prpsinfo, None))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("thread {tid} not available from coredump"),
            ))
        }
    }

    fn read_tid_status(&self, tid: u64) -> io::Result<model::status::Status> {
        // Main thread: prefer journal string, fall back to prstatus.
        if tid == self.pid() {
            if let Ok(text) = self.get_field_str("COREDUMP_PROC_STATUS") {
                return model::status::Status::from_buf_read(text.as_bytes());
            }
        }
        // Any thread: fall back to prstatus/prpsinfo notes.
        self.ensure_notes();
        let prpsinfo = self
            .prpsinfo
            .get()
            .expect("ensure_notes initialized")
            .as_ref();
        let prstatus = self
            .prstatus_map
            .get()
            .expect("ensure_notes initialized")
            .get(&tid);
        if prstatus.is_some() {
            Ok(prstatus_to_status(prpsinfo, prstatus))
        } else if tid == self.pid() && prpsinfo.is_some() {
            Ok(prstatus_to_status(prpsinfo, None))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("thread {tid} not available from coredump"),
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
