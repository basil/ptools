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

//! Core process-handle module: parsing and structured access to process data.
//!
//! This module consumes the [`crate::source`] abstraction to read raw procfs
//! (or coredump) data and parses it into typed Rust structures.  Its central
//! type, [`ProcHandle`], is the opaque handle through which all process
//! queries flow.
//!
//! **Consumed by:** the presentation layer ([`crate::display`]) and the
//! binary targets in `src/bin/`.  Those consumers should treat this module
//! as a data-provider and never format output themselves from raw source
//! data.
//!
//! **Contract:**
//! - This module must **never** write to stdout.
//! - Types defined here should **not** implement `Display`.
//! - This module provides structured data to the presentation layer for
//!   formatting; it should never make presentation decisions itself.

pub mod fd;
pub mod net;
pub mod numa;
pub mod pidfd;
pub mod signal;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;

use nix::unistd::{sysconf, SysconfVar};

use crate::model;
use crate::model::auxv::AuxvType;
use crate::source::ProcSource;

/// Opaque process handle
///
/// Callers obtain a handle via [`resolve_operand`] and interact with it
/// through typed accessor methods rather than reading /proc files directly.
pub struct ProcHandle {
    source: Box<dyn ProcSource>,
    is_core: bool,
}

impl ProcHandle {
    /// Whether the handle was opened from a coredump (as opposed to a live
    /// process).
    pub fn is_core(&self) -> bool {
        self.is_core
    }

    /// Walk and symbolize frames for one thread.  Delegates to the
    /// underlying data source which manages dwfl internally.
    pub fn trace_thread(
        &self,
        tid: u32,
        options: &crate::stack::TraceOptions,
    ) -> Vec<crate::stack::Frame> {
        self.source.trace_thread(tid, options)
    }

    /// Return the page size for the target process.
    ///
    /// Prefers `AT_PAGESZ` from the auxiliary vector, falls back to
    /// `sysconf(_SC_PAGE_SIZE)`.
    pub fn page_size(&self) -> io::Result<u64> {
        if let Some(page_sz) = self.auxv().ok().and_then(|auxv| {
            auxv.0
                .iter()
                .find(|(typ, _)| *typ == AuxvType::PageSz)
                .map(|(_, value)| *value)
        }) {
            return Ok(page_sz);
        }

        eprintln!("warning: AT_PAGESZ not available, falling back to sysconf");
        match sysconf(SysconfVar::PAGE_SIZE) {
            Ok(Some(v)) => Ok(v as u64),
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "sysconf(_SC_PAGE_SIZE) returned no value",
            )),
            Err(e) => Err(io::Error::other(format!(
                "sysconf(_SC_PAGE_SIZE) failed: {e}"
            ))),
        }
    }

    /// Read a NUL-terminated C string from the target process's memory.
    ///
    /// Best-effort: reads from `addr` to the end of its page. If no NUL
    /// terminator is found within that range, returns the partial content.
    pub fn read_cstring_at(&self, addr: u64) -> Option<String> {
        if addr == 0 {
            return None;
        }
        let page_size = match self.page_size() {
            Ok(v) => v.clamp(1, 64 * 1024),
            Err(_) => return None,
        };
        let bytes_to_page_end = (page_size - (addr % page_size)) as usize;
        let mut buf = vec![0u8; bytes_to_page_end];
        if !self.source.read_memory(addr, &mut buf) {
            return None;
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..len]).into_owned())
    }

    // -- Pure delegation ---------------------------------------------

    pub fn pid(&self) -> u64 {
        self.source.pid()
    }

    pub fn word_size(&self) -> usize {
        self.source.word_size()
    }

    pub fn auxv(&self) -> io::Result<model::auxv::Auxv> {
        self.source.read_auxv()
    }

    pub fn comm(&self) -> io::Result<String> {
        self.source.read_comm()
    }

    pub fn exe(&self) -> io::Result<PathBuf> {
        self.source.read_exe()
    }

    pub fn tids(&self) -> io::Result<Vec<u64>> {
        self.source.list_tids()
    }

    fn fds(&self) -> io::Result<Vec<u64>> {
        self.source.list_fds()
    }

    fn fd_path(&self, fd: u64) -> io::Result<PathBuf> {
        self.source.read_fd_link(fd)
    }

    fn fdinfo(&self, fd: u64) -> io::Result<model::fdinfo::FdInfo> {
        self.source.read_fdinfo(fd)
    }

    // -- Parsed from /proc/[pid]/stat --------------------------------

    /// Process state parsed from `/proc/[pid]/stat`.
    pub fn state(&self) -> io::Result<model::stat::ProcState> {
        self.source
            .read_stat()?
            .state
            .ok_or_else(|| unsupported("stat", "state"))
    }

    /// User CPU time in clock ticks (field 14 of /proc/[pid]/stat).
    pub fn utime(&self) -> io::Result<u64> {
        self.source
            .read_stat()?
            .utime
            .ok_or_else(|| unsupported("stat", "utime"))
    }

    /// System CPU time in clock ticks (field 15 of /proc/[pid]/stat).
    pub fn stime(&self) -> io::Result<u64> {
        self.source
            .read_stat()?
            .stime
            .ok_or_else(|| unsupported("stat", "stime"))
    }

    /// User CPU time in microseconds (from prstatus timeval, when available).
    pub fn utime_us(&self) -> io::Result<u64> {
        self.source.read_utime_us()
    }

    /// System CPU time in microseconds (from prstatus timeval, when available).
    pub fn stime_us(&self) -> io::Result<u64> {
        self.source.read_stime_us()
    }

    /// Children user CPU time in microseconds (from prstatus timeval, when available).
    pub fn cutime_us(&self) -> io::Result<u64> {
        self.source.read_cutime_us()
    }

    /// Children system CPU time in microseconds (from prstatus timeval, when available).
    pub fn cstime_us(&self) -> io::Result<u64> {
        self.source.read_cstime_us()
    }

    /// Process group ID (field 5 of /proc/[pid]/stat).
    pub fn pgrp(&self) -> io::Result<u64> {
        self.source
            .read_stat()?
            .pgrp
            .ok_or_else(|| unsupported("stat", "pgrp"))
    }

    /// Session ID (field 6 of /proc/[pid]/stat).
    pub fn sid(&self) -> io::Result<u64> {
        self.source
            .read_stat()?
            .sid
            .ok_or_else(|| unsupported("stat", "sid"))
    }

    /// Nice value (field 19 of /proc/[pid]/stat).
    pub fn nice(&self) -> io::Result<i32> {
        self.source
            .read_stat()?
            .nice
            .ok_or_else(|| unsupported("stat", "nice"))
    }

    /// Start time in clock ticks (field 22 of /proc/[pid]/stat).
    pub fn starttime(&self) -> io::Result<u64> {
        self.source
            .read_stat()?
            .starttime
            .ok_or_else(|| unsupported("stat", "starttime"))
    }

    // -- Parsed from /proc/[pid]/status ------------------------------

    pub fn ppid(&self) -> io::Result<u64> {
        self.source
            .read_status()?
            .ppid
            .ok_or_else(|| unsupported("status", "PPid"))
    }

    pub fn ruid(&self) -> io::Result<u32> {
        self.source
            .read_status()?
            .ruid
            .ok_or_else(|| unsupported("status", "Uid"))
    }

    pub fn euid(&self) -> io::Result<u32> {
        self.source
            .read_status()?
            .euid
            .ok_or_else(|| unsupported("status", "Uid"))
    }

    pub fn suid(&self) -> io::Result<u32> {
        self.source
            .read_status()?
            .suid
            .ok_or_else(|| unsupported("status", "Uid"))
    }

    pub fn fsuid(&self) -> io::Result<u32> {
        self.source
            .read_status()?
            .fsuid
            .ok_or_else(|| unsupported("status", "Uid"))
    }

    pub fn rgid(&self) -> io::Result<u32> {
        self.source
            .read_status()?
            .rgid
            .ok_or_else(|| unsupported("status", "Gid"))
    }

    pub fn egid(&self) -> io::Result<u32> {
        self.source
            .read_status()?
            .egid
            .ok_or_else(|| unsupported("status", "Gid"))
    }

    pub fn sgid(&self) -> io::Result<u32> {
        self.source
            .read_status()?
            .sgid
            .ok_or_else(|| unsupported("status", "Gid"))
    }

    pub fn fsgid(&self) -> io::Result<u32> {
        self.source
            .read_status()?
            .fsgid
            .ok_or_else(|| unsupported("status", "Gid"))
    }

    pub fn groups(&self) -> io::Result<Vec<u32>> {
        self.source
            .read_status()?
            .groups
            .ok_or_else(|| unsupported("status", "Groups"))
    }

    pub fn umask(&self) -> io::Result<u32> {
        self.source
            .read_status()?
            .umask
            .ok_or_else(|| unsupported("status", "Umask"))
    }

    pub fn thread_count(&self) -> io::Result<usize> {
        self.source
            .read_status()?
            .threads
            .ok_or_else(|| unsupported("status", "Threads"))
    }

    // -- Thread methods ----------------------------------------------

    /// CPU number a thread is currently running on (field 39 of tid/stat).
    pub fn thread_cpu(&self, tid: u64) -> io::Result<u32> {
        self.source
            .read_tid_stat(tid)?
            .processor
            .ok_or_else(|| unsupported("task/stat", "processor"))
    }

    /// Cpus_allowed_list from a thread's status, as a `BTreeSet<usize>`.
    pub fn thread_affinity(&self, tid: u64) -> io::Result<BTreeSet<usize>> {
        self.source
            .read_tid_status(tid)?
            .cpus_allowed
            .ok_or_else(|| unsupported("task/status", "Cpus_allowed_list"))
    }

    // -- Compound convenience ----------------------------------------

    /// Read cmdline and split on NUL into individual arguments.
    pub fn argv(&self) -> io::Result<Vec<OsString>> {
        let bytes = self.source.read_cmdline()?;
        let mut args: Vec<OsString> = bytes
            .split(|b| *b == b'\0')
            .map(|b| OsString::from(std::ffi::OsStr::from_bytes(b)))
            .collect();
        if args.last().is_some_and(|arg| arg.is_empty()) {
            args.pop();
        }
        Ok(args)
    }

    /// Read environment variables and parse into key-value pairs.
    ///
    /// Splits the raw NUL-delimited environ blob on `=` to produce
    /// `(key, value)` pairs.  Entries that lack an `=` or have an
    /// empty key are silently skipped (processes like sshd can overwrite
    /// their environ memory with status info, leaving garbage).
    pub fn environ(&self) -> io::Result<Vec<(OsString, OsString)>> {
        let bytes = self.source.read_environ()?;
        let mut vars = Vec::new();
        for chunk in bytes.split(|b| *b == b'\0') {
            if chunk.is_empty() {
                continue;
            }
            if let Some(pos) = chunk.iter().position(|b| *b == b'=') {
                if pos > 0 {
                    let key = OsString::from(std::ffi::OsStr::from_bytes(&chunk[..pos]));
                    let value = OsString::from(std::ffi::OsStr::from_bytes(&chunk[pos + 1..]));
                    vars.push((key, value));
                } else {
                    eprintln!(
                        "warning: skipping environ entry with empty key for pid {}",
                        self.pid()
                    );
                }
            }
        }
        Ok(vars)
    }

    pub fn run_time_ns(&self) -> io::Result<u64> {
        Ok(self.source.read_schedstat()?.run_time_ns)
    }

    pub fn wait_time_ns(&self) -> io::Result<u64> {
        Ok(self.source.read_schedstat()?.wait_time_ns)
    }

    /// Query the open-files resource limit from `/proc/[pid]/limits`.
    pub fn nofile_limit(&self) -> io::Result<model::limits::Limit> {
        self.source
            .read_limits()?
            .get(nix::sys::resource::Resource::RLIMIT_NOFILE)
            .cloned()
            .ok_or_else(|| unsupported("limits", "RLIMIT_NOFILE"))
    }

    /// Parse all resource limits from `/proc/[pid]/limits`.
    pub fn resource_limits(&self) -> io::Result<model::limits::Limits> {
        self.source.read_limits()
    }
}

impl ProcHandle {
    pub fn from_pid(pid: u64) -> Self {
        ProcHandle {
            source: crate::source::open_live(pid),
            is_core: false,
        }
    }
}

/// Extract a PID from a `/proc/<pid>` path.
pub fn parse_proc_path(s: &str) -> Option<u64> {
    let suffix = s.strip_prefix("/proc/")?;
    suffix.parse::<u64>().ok().filter(|&pid| pid >= 1)
}

/// Result of parsing a command-line argument as a PID.
pub enum PidArg {
    /// Successfully parsed PID.
    Pid(u64),
    /// Non-PID /proc path (e.g. /proc/cpuinfo from shell expansion); skip silently.
    Skip,
}

/// Parse a command-line argument as a PID.
///
/// Accepts plain numeric PIDs ("1234") and /proc paths ("/proc/1234").
/// Returns `Skip` for /proc paths with non-numeric suffixes, allowing
/// `tool /proc/*` to work on Linux where /proc contains non-PID entries.
pub fn parse_pid_arg(s: &str) -> Result<PidArg, String> {
    if let Ok(pid) = s.parse::<u64>() {
        if pid < 1 || pid > i32::MAX as u64 {
            return Err(format!("invalid PID '{s}'"));
        }
        return Ok(PidArg::Pid(pid));
    }
    if let Some(pid) = parse_proc_path(s) {
        if pid > i32::MAX as u64 {
            return Err(format!("invalid PID '{s}'"));
        }
        return Ok(PidArg::Pid(pid));
    }
    if s.starts_with("/proc/") {
        return Ok(PidArg::Skip);
    }
    Err(format!("invalid PID '{s}'"))
}

/// True if `s` is a /proc path that is not a PID directory.
pub fn is_non_pid_proc_path(s: &str) -> bool {
    s.strip_prefix("/proc/")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.parse::<u64>().is_err())
}

/// A parsed PID with an optional thread (LWP) filter.
struct PidSpec {
    pid: u64,
    tid: Option<u64>,
}

fn parse_pid_spec(s: &str) -> io::Result<PidSpec> {
    if let Some(pid) = parse_proc_path(s) {
        return Ok(PidSpec { pid, tid: None });
    }
    if let Some((pid_str, tid_str)) = s.split_once('/') {
        let pid = pid_str
            .parse::<u64>()
            .map_err(|e| io::Error::other(format!("Error parsing PID '{pid_str}': {e}")))?;
        let tid = tid_str
            .parse::<u64>()
            .map_err(|e| io::Error::other(format!("Error parsing thread ID '{tid_str}': {e}")))?;
        if pid == 0 {
            return Err(io::Error::other("PID must be >= 1".to_string()));
        }
        Ok(PidSpec {
            pid,
            tid: Some(tid),
        })
    } else {
        let pid = s
            .parse::<u64>()
            .map_err(|e| io::Error::other(format!("Error parsing PID '{s}': {e}")))?;
        if pid == 0 {
            return Err(io::Error::other("PID must be >= 1".to_string()));
        }
        Ok(PidSpec { pid, tid: None })
    }
}

/// Grab a process from a coredump
fn grab_core(path: &Path) -> io::Result<ProcHandle> {
    let source = crate::source::open_coredump(path)?;
    Ok(ProcHandle {
        source,
        is_core: true,
    })
}

fn unsupported(file: &str, field: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{field} not available from /proc/[pid]/{file}"),
    )
}

/// Resolve a positional operand to a `ProcHandle`.
///
/// Resolution order:
/// 1. Try parsing as a plain PID (digits only)
/// 2. Otherwise treat as a coredump file path
///
/// This variant does **not** accept `pid/tid` syntax; use
/// [`resolve_operand_with_tid`] for tools that support thread selection.
pub fn resolve_operand(arg: &str) -> io::Result<ProcHandle> {
    match arg.parse::<u64>() {
        Ok(pid) => {
            if pid == 0 {
                return Err(io::Error::other("PID must be >= 1".to_string()));
            }
            Ok(ProcHandle::from_pid(pid))
        }
        Err(_) => {
            if let Some(pid) = parse_proc_path(arg) {
                return Ok(ProcHandle::from_pid(pid));
            }
            let path = PathBuf::from(arg);
            grab_core(&path)
        }
    }
}

/// Resolve a positional operand to a `ProcHandle` and optional thread ID.
///
/// Resolution order:
/// 1. Try parsing as a PID spec (`1234` or `1234/5`)
/// 2. If that fails and the arg is purely digits, surface the PID error
/// 3. Otherwise treat as a coredump file path
pub fn resolve_operand_with_tid(arg: &str) -> io::Result<(ProcHandle, Option<u64>)> {
    match parse_pid_spec(arg) {
        Ok(spec) => Ok((ProcHandle::from_pid(spec.pid), spec.tid)),
        Err(e) => {
            if arg.bytes().all(|b| b.is_ascii_digit()) {
                return Err(e);
            }
            let path = PathBuf::from(arg);
            grab_core(&path).map(|h| (h, None))
        }
    }
}
