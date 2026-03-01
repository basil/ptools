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

pub mod cred;
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

use cred::parse_cred;
use cred::ProcCred;
use signal::intersect_blocked_masks;
use signal::parse_signal_set;

use crate::model;
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
    pub(crate) fn trace_thread(
        &self,
        tid: u32,
        options: &crate::stack::TraceOptions,
    ) -> Vec<crate::stack::Frame> {
        self.source.trace_thread(tid, options)
    }

    /// Read memory from the process -- core dump PT_LOAD segments or live
    /// `process_vm_readv(2)`.
    pub(crate) fn read_memory(&self, addr: u64, buf: &mut [u8]) -> bool {
        self.source.read_memory(addr, buf)
    }

    /// Read a NUL-terminated C string from the target process's memory.
    ///
    /// Best-effort: reads from `addr` to the end of its page. If no NUL
    /// terminator is found within that range, returns the partial content.
    pub(crate) fn read_cstring_at(&self, addr: u64, page_size: u64) -> Option<String> {
        if addr == 0 {
            return None;
        }
        let page_size = page_size.clamp(1, 64 * 1024);
        let bytes_to_page_end = (page_size - (addr % page_size)) as usize;
        let mut buf = vec![0u8; bytes_to_page_end];
        if !self.read_memory(addr, &mut buf) {
            return None;
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..len]).into_owned())
    }

    // -- Pure delegation ---------------------------------------------

    pub fn pid(&self) -> u64 {
        self.source.pid()
    }

    pub(crate) fn word_size(&self) -> usize {
        self.source.word_size()
    }

    pub(crate) fn auxv(&self) -> io::Result<model::auxv::Auxv> {
        self.source.read_auxv()
    }

    pub(crate) fn comm(&self) -> io::Result<String> {
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
    pub fn state(&self) -> io::Result<ProcState> {
        let stat = self.source.read_stat()?;
        // Use rfind to handle comm fields containing parentheses.
        let after_comm = stat
            .rfind(')')
            .ok_or_else(|| file_parse_error("stat", "missing ')' in comm field"))?
            + 1;
        let rest = stat[after_comm..].trim_start();
        rest.chars()
            .next()
            .map(ProcState::from_char)
            .ok_or_else(|| file_parse_error("stat", "empty state field"))
    }

    /// User CPU time in clock ticks (field 14 of /proc/[pid]/stat).
    pub fn utime(&self) -> io::Result<u64> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| file_parse_error("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
        //   tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10)
        //   utime(11) stime(12) ...
        let field = after_comm
            .split_whitespace()
            .nth(11)
            .ok_or_else(|| file_parse_error("stat", "missing utime field"))?;
        field
            .parse::<u64>()
            .map_err(|e| file_parse_error("stat", &format!("invalid utime: {e}")))
    }

    /// System CPU time in clock ticks (field 15 of /proc/[pid]/stat).
    pub fn stime(&self) -> io::Result<u64> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| file_parse_error("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ... utime(11) stime(12) ...
        let field = after_comm
            .split_whitespace()
            .nth(12)
            .ok_or_else(|| file_parse_error("stat", "missing stime field"))?;
        field
            .parse::<u64>()
            .map_err(|e| file_parse_error("stat", &format!("invalid stime: {e}")))
    }

    /// Process group ID (field 5 of /proc/[pid]/stat).
    pub fn pgrp(&self) -> io::Result<u64> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| file_parse_error("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ppid(1) pgrp(2) ...
        let field = after_comm
            .split_whitespace()
            .nth(2)
            .ok_or_else(|| file_parse_error("stat", "missing pgrp field"))?;
        field
            .parse::<u64>()
            .map_err(|e| file_parse_error("stat", &format!("invalid pgrp: {e}")))
    }

    /// Session ID (field 6 of /proc/[pid]/stat).
    pub fn sid(&self) -> io::Result<u64> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| file_parse_error("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ppid(1) pgrp(2) session(3) ...
        let field = after_comm
            .split_whitespace()
            .nth(3)
            .ok_or_else(|| file_parse_error("stat", "missing session field"))?;
        field
            .parse::<u64>()
            .map_err(|e| file_parse_error("stat", &format!("invalid session: {e}")))
    }

    /// Nice value (field 19 of /proc/[pid]/stat).
    pub fn nice(&self) -> io::Result<i32> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| file_parse_error("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
        //   tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10)
        //   utime(11) stime(12) cutime(13) cstime(14) priority(15) nice(16) ...
        let field = after_comm
            .split_whitespace()
            .nth(16)
            .ok_or_else(|| file_parse_error("stat", "missing nice field"))?;
        field
            .parse::<i32>()
            .map_err(|e| file_parse_error("stat", &format!("invalid nice: {e}")))
    }

    /// Start time in clock ticks (field 22 of /proc/[pid]/stat).
    pub fn starttime(&self) -> io::Result<u64> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| file_parse_error("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ppid(1) ... starttime(19)
        let field = after_comm
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| file_parse_error("stat", "missing starttime field"))?;
        field
            .parse::<u64>()
            .map_err(|e| file_parse_error("stat", &format!("invalid starttime: {e}")))
    }

    // -- Parsed from /proc/[pid]/status ------------------------------

    pub fn ppid(&self) -> io::Result<u64> {
        let status = self.source.read_status()?;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("PPid:") {
                return val
                    .trim()
                    .parse::<u64>()
                    .map_err(|e| file_parse_error("status", &format!("invalid PPid: {e}")));
            }
        }
        Err(file_parse_error("status", "missing PPid"))
    }

    pub fn euid(&self) -> io::Result<u32> {
        let status = self.source.read_status()?;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Uid:") {
                let fields: Vec<&str> = val.split_whitespace().collect();
                if fields.len() < 2 {
                    return Err(file_parse_error("status", "Uid field has too few values"));
                }
                return fields[1]
                    .parse::<u32>()
                    .map_err(|e| file_parse_error("status", &format!("invalid euid: {e}")));
            }
        }
        Err(file_parse_error("status", "missing Uid"))
    }

    pub fn umask(&self) -> io::Result<u32> {
        let status = self.source.read_status()?;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Umask:") {
                return u32::from_str_radix(val.trim(), 8)
                    .map_err(|e| file_parse_error("status", &format!("invalid Umask: {e}")));
            }
        }
        Err(file_parse_error("status", "missing Umask"))
    }

    pub fn thread_count(&self) -> io::Result<usize> {
        let status = self.source.read_status()?;
        let val = status
            .lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .ok_or_else(|| file_parse_error("status", "missing Threads"))?;
        val.trim()
            .parse::<usize>()
            .map_err(|e| file_parse_error("status", &format!("invalid Threads: {e}")))
    }

    pub fn cred(&self) -> io::Result<ProcCred> {
        let status = self.source.read_status()?;
        parse_cred(&status)
    }

    // -- Signal masks ------------------------------------------------

    /// Parse signal masks (SigIgn/SigCgt/SigBlk/SigPnd/ShdPnd) from status.
    /// The blocked mask is the intersection across all threads.
    pub fn signal_masks(&self) -> io::Result<SignalMasks> {
        let status = self.source.read_status()?;

        let mut sig_ign = None;
        let mut sig_cgt = None;
        let mut sig_blk = None;
        let mut sig_pnd = None;
        let mut shd_pnd = None;

        for line in status.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let value = value.trim();
                match key {
                    "SigIgn" => sig_ign = Some(value.to_string()),
                    "SigCgt" => sig_cgt = Some(value.to_string()),
                    "SigBlk" => sig_blk = Some(value.to_string()),
                    "SigPnd" => sig_pnd = Some(value.to_string()),
                    "ShdPnd" => shd_pnd = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        let sig_ign_hex = sig_ign.ok_or_else(|| file_parse_error("status", "missing SigIgn"))?;
        let sig_cgt_hex = sig_cgt.ok_or_else(|| file_parse_error("status", "missing SigCgt"))?;

        let parse = |name: &str, hex: &str| -> io::Result<BTreeSet<usize>> {
            parse_signal_set(hex)
                .map_err(|e| file_parse_error("status", &format!("invalid {name}: {e}")))
        };

        let ignored = parse("SigIgn", &sig_ign_hex)?;
        let caught = parse("SigCgt", &sig_cgt_hex)?;

        // Compute blocked mask as intersection across all threads.
        // Falls back to main thread's SigBlk if /proc/[pid]/task/ is unreadable.
        let blocked = self
            .thread_blocked_masks()
            .map(|masks| intersect_blocked_masks(&masks))
            .or_else(|| sig_blk.and_then(|s| parse_signal_set(&s).ok()))
            .unwrap_or_default();

        let pending = sig_pnd
            .and_then(|s| parse_signal_set(&s).ok())
            .unwrap_or_default();
        let shared_pending = shd_pnd
            .and_then(|s| parse_signal_set(&s).ok())
            .unwrap_or_default();

        Ok(SignalMasks {
            ignored,
            caught,
            blocked,
            pending,
            shared_pending,
        })
    }

    /// Per-thread blocked masks (SigBlk from each thread's status).
    fn thread_blocked_masks(&self) -> Option<Vec<BTreeSet<usize>>> {
        let tids = self.source.list_tids().ok()?;

        // Warn if the source reports fewer threads than actually existed.
        if let Ok(status) = self.source.read_status() {
            if let Some(n) = status
                .lines()
                .find_map(|l| l.strip_prefix("Threads:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
            {
                if n > tids.len() {
                    eprintln!(
                        "warning: process had {} threads but only {} available; \
                         blocked masks may be incomplete",
                        n,
                        tids.len()
                    );
                }
            }
        }

        let tid_count = tids.len();
        let mut masks = Vec::new();
        for tid in tids {
            let Ok(status) = self.source.read_tid_status(tid) else {
                continue;
            };
            for line in status.lines() {
                if let Some(hex) = line.strip_prefix("SigBlk:") {
                    if let Ok(mask) = parse_signal_set(hex) {
                        masks.push(mask);
                    }
                    break;
                }
            }
        }

        if !masks.is_empty() && masks.len() < tid_count {
            eprintln!(
                "warning: read blocked mask for {} of {} threads; \
                 blocked-signal intersection may be incomplete",
                masks.len(),
                tid_count
            );
        }

        if masks.is_empty() {
            None
        } else {
            Some(masks)
        }
    }

    // -- Thread methods ----------------------------------------------

    /// CPU number a thread is currently running on (field 39 of tid/stat).
    pub fn thread_cpu(&self, tid: u64) -> io::Result<u32> {
        let stat = self.source.read_tid_stat(tid)?;
        let after_comm = stat
            .rfind(')')
            .ok_or_else(|| file_parse_error("task/stat", "missing ')' in comm field"))?
            + 1;
        let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
        // processor is at index 36 after the comm field
        let val = fields
            .get(36)
            .ok_or_else(|| file_parse_error("task/stat", "missing processor field"))?;
        val.parse::<u32>()
            .map_err(|e| file_parse_error("task/stat", &format!("invalid processor: {e}")))
    }

    /// Cpus_allowed_list from a thread's status, as a `BTreeSet<u32>`.
    pub fn thread_affinity(&self, tid: u64) -> io::Result<std::collections::BTreeSet<u32>> {
        let status = self.source.read_tid_status(tid)?;
        let line = status
            .lines()
            .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
            .ok_or_else(|| file_parse_error("task/status", "missing Cpus_allowed_list"))?;
        numa::parse_list_format(line.trim())
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
    pub(crate) fn environ(&self) -> io::Result<Vec<(OsString, OsString)>> {
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

    pub fn schedstat(&self) -> io::Result<model::schedstat::SchedStat> {
        self.source.read_schedstat()
    }

    /// Query the open-files resource limit from `/proc/[pid]/limits`.
    pub fn nofile_limit(&self) -> io::Result<model::limits::Limit> {
        let limits = self.source.read_limits()?;
        limits
            .get(nix::sys::resource::Resource::RLIMIT_NOFILE)
            .cloned()
            .ok_or_else(|| file_parse_error("limits", "RLIMIT_NOFILE not found"))
    }

    /// Parse all resource limits from `/proc/[pid]/limits`.
    pub fn resource_limits(&self) -> io::Result<model::limits::Limits> {
        self.source.read_limits()
    }

    /// Gather fully-populated [`fd::FileDescriptor`] structs for every open
    /// file descriptor in the process.
    ///
    /// This is the primary entry point for tools that need to enumerate a
    /// process's open files.  It combines fd path/stat/fdinfo, socket info
    /// from `/proc/net/*`, socket details via `getsockopt`, and peer process
    /// resolution into a single call.
    pub fn file_descriptors(&self) -> io::Result<Vec<fd::FileDescriptor>> {
        let fds = self.fds()?;
        let sockets = net::parse_socket_info(&*self.source);

        // Compute TCP peer processes in bulk (system-wide /proc scan).
        // Skip for coredumps or when no loopback TCP sockets exist.
        let tcp_peers = if !self.is_core && net::has_loopback_tcp_peers(&sockets) {
            net::derive_peer_processes(self.pid(), &sockets)
        } else {
            std::collections::HashMap::new()
        };

        let mut result = Vec::with_capacity(fds.len());
        for fd_num in fds {
            match self.gather_fd(fd_num, &sockets, &tcp_peers) {
                Ok(fd_desc) => result.push(fd_desc),
                Err(e) => {
                    eprintln!(
                        "failed to gather info for /proc/{}/fd/{}: {}",
                        self.pid(),
                        fd_num,
                        e
                    );
                }
            }
        }

        Ok(result)
    }

    /// Gather all available information for a single file descriptor.
    #[allow(clippy::unnecessary_cast)]
    fn gather_fd(
        &self,
        fd_num: u64,
        sockets: &std::collections::HashMap<u64, net::SocketInfo>,
        tcp_peers: &std::collections::HashMap<u64, (u64, String)>,
    ) -> io::Result<fd::FileDescriptor> {
        let path = self.fd_path(fd_num)?;
        let link_text = path.to_string_lossy();
        let info = self.fdinfo(fd_num)?;

        // stat() -- live only
        let stat_result = if !self.is_core {
            fd::stat_fd(self.pid(), fd_num).ok()
        } else {
            None
        };

        // Classify file type
        let file_type = if let Some(ref st) = stat_result {
            fd::file_type_from_stat(st.st_mode, &link_text)
        } else {
            fd::file_type_from_link(&link_text)
        };

        // Socket resolution
        let is_socket = matches!(file_type, fd::FileType::Posix(fd::PosixFileType::Socket))
            || link_text.starts_with("socket:[");

        let mut socket = None;
        let mut sockprotoname = None;

        if is_socket {
            // Try to find inode -- from stat if available, else from link text
            let inode = stat_result
                .as_ref()
                .map(|st| st.st_ino as u64)
                .or_else(|| fd::parse_socket_inode(&link_text));

            if let Some(inode) = inode {
                if let Some(sock_info) = sockets.get(&inode) {
                    let details = net::query_socket_details(self.pid(), fd_num);

                    // Resolve peer process: TCP peers from bulk map, Unix via SO_PEERCRED
                    let peer = tcp_peers.get(&inode).cloned().or_else(|| {
                        if matches!(sock_info.family, nix::sys::socket::AddressFamily::Unix)
                            && !self.is_core
                        {
                            net::unix_peer_process(self.pid(), fd_num)
                        } else {
                            None
                        }
                    });

                    socket = Some(net::Socket::from_parts(sock_info.clone(), details, peer));
                }
            }

            // Fallback: sockprotoname xattr when not found in /proc/net/*
            if socket.is_none() && !self.is_core {
                sockprotoname = fd::get_sockprotoname(self.pid(), fd_num);
            }
        }

        Ok(fd::FileDescriptor {
            fd: fd_num,
            path: path.clone(),
            file_type,
            stat: stat_result,
            fdinfo: info,
            socket,
            sockprotoname,
        })
    }
}

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

impl ProcState {
    fn from_char(c: char) -> Self {
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

/// Signal disposition masks parsed from /proc/[pid]/status.
pub struct SignalMasks {
    pub ignored: BTreeSet<usize>,
    pub caught: BTreeSet<usize>,
    /// Intersection of SigBlk across all threads.
    pub blocked: BTreeSet<usize>,
    pub pending: BTreeSet<usize>,
    pub shared_pending: BTreeSet<usize>,
}

impl ProcHandle {
    pub fn from_pid(pid: u64) -> Self {
        ProcHandle {
            source: crate::source::open_live(pid),
            is_core: false,
        }
    }
}

/// A parsed PID with an optional thread (LWP) filter.
struct PidSpec {
    pid: u64,
    tid: Option<u64>,
}

fn parse_pid_spec(s: &str) -> io::Result<PidSpec> {
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

fn parse_error(item: &str, reason: &str) -> io::Error {
    io::Error::other(format!("Error parsing {item}: {reason}"))
}

fn file_parse_error(file: &str, reason: &str) -> io::Error {
    io::Error::other(format!("Error parsing /proc/[pid]/{file}: {reason}"))
}
