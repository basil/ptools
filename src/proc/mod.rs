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
//! - This module must **never** write to stdout or stderr.  All warnings
//!   and non-fatal diagnostics must be returned via the `warnings` vector
//!   on [`ProcHandle`].
//! - Types defined here should **not** implement `Display` except for
//!   [`Error`], which needs `Display` for the `std::error::Error` blanket.
//! - This module provides structured data to the presentation layer for
//!   formatting; it should never make presentation decisions itself.

pub(crate) mod auxv;
pub(crate) mod cred;
pub(crate) mod fd;
pub(crate) mod net;
pub(crate) mod numa;
pub(crate) mod pidfd;
pub(crate) mod signal;

use nix::fcntl::OFlag;
use std::cell::RefCell;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::source::ProcSource;
use cred::{parse_cred, ProcCred};
use signal::{intersect_blocked_masks, parse_signal_set, SignalSet};

/// A resource limit value (soft or hard).
///
/// `None` represents "unlimited" (i.e. `RLIM_INFINITY`).
pub type RlimitVal = Option<u64>;

/// Parsed resource limit with soft and hard values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimit {
    pub soft: RlimitVal,
    pub hard: RlimitVal,
}

/// A named resource limit parsed from `/proc/[pid]/limits`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLimit {
    /// Kernel-assigned name (e.g. "Max open files").
    pub name: String,
    /// Soft (current) limit value.
    pub soft: RlimitVal,
    /// Hard (maximum) limit value.
    pub hard: RlimitVal,
    /// Unit string from the kernel (e.g. "bytes", "files", "seconds").
    pub unit: String,
}

/// Parsed fdinfo with structured fields from `/proc/[pid]/fdinfo/<fd>`.
struct FdInfo {
    offset: u64,
    flags: OFlag,
    mnt_id: Option<u64>,
    extra_lines: Vec<String>,
}

fn parse_rlimit_val(s: &str) -> Result<RlimitVal, Error> {
    if s.eq_ignore_ascii_case("unlimited") {
        Ok(None)
    } else {
        s.parse::<u64>()
            .map(Some)
            .map_err(|e| Error::parse("rlimit value", &e.to_string()))
    }
}

/// Try to parse a single resource limit from the raw limits text.
///
/// Returns `Ok(None)` if the line for this resource is not present.
fn parse_rlimit_line(limits: &str, prefix: &str) -> Result<Option<Rlimit>, Error> {
    for line in limits.lines() {
        if let Some(rest) = line.strip_prefix(prefix) {
            let rest = rest.trim();
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if fields.len() < 2 {
                return Err(Error::parse(prefix, "line has fewer fields than expected"));
            }
            return Ok(Some(Rlimit {
                soft: parse_rlimit_val(fields[0])?,
                hard: parse_rlimit_val(fields[1])?,
            }));
        }
    }
    Ok(None)
}

/// Parse all resource limits from the raw `/proc/[pid]/limits` text.
///
/// The kernel formats limits with fixed-width columns:
/// `%-25s %-20s %-20s %-10s\n`
/// The header line is skipped.
fn parse_resource_limits(text: &str) -> Result<Vec<ResourceLimit>, Error> {
    let mut limits = Vec::new();
    for line in text.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        // The kernel format is: %-25s %-20s %-20s %-10s
        // Name occupies columns 0..25, soft 25..45, hard 45..65, unit 65..
        if line.len() < 45 {
            return Err(Error::parse("limits", "line too short"));
        }
        let name = line[..25].trim_end().to_string();
        let soft_str = if line.len() >= 45 {
            line[25..45].trim()
        } else {
            line[25..].trim()
        };
        let hard_str = if line.len() >= 65 {
            line[45..65].trim()
        } else if line.len() > 45 {
            line[45..].trim()
        } else {
            ""
        };
        let unit = if line.len() > 65 {
            line[65..].trim().to_string()
        } else {
            String::new()
        };

        let soft = parse_rlimit_val(soft_str)?;
        let hard = parse_rlimit_val(hard_str)?;

        limits.push(ResourceLimit {
            name,
            soft,
            hard,
            unit,
        });
    }
    Ok(limits)
}

/// Scheduler statistics from `/proc/[pid]/schedstat`.
pub struct SchedStat {
    pub run_time_ns: u64,
    pub wait_time_ns: u64,
    pub timeslices: u64,
}

/// Opaque process handle
///
/// Callers obtain a handle via [`resolve_operand`] and interact with it
/// through typed accessor methods rather than reading /proc files directly.
pub struct ProcHandle {
    source: Box<dyn ProcSource>,
    warnings: RefCell<Vec<String>>,
    is_core: bool,
}

impl ProcHandle {
    /// Drain and return all accumulated warnings.
    pub fn drain_warnings(&self) -> Vec<String> {
        let mut w = std::mem::take(&mut *self.warnings.borrow_mut());
        w.extend(self.source.drain_warnings());
        w
    }

    /// Append a warning to the handle's warning list.
    pub(crate) fn push_warning(&self, msg: String) {
        self.warnings.borrow_mut().push(msg);
    }

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

    fn auxv_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.source.read_auxv()?)
    }

    /// Parse and return all auxiliary vector entries with metadata.
    pub(crate) fn auxv(&self) -> Result<auxv::AuxvData, Error> {
        auxv::read_auxv(self)
    }

    pub(crate) fn comm(&self) -> Result<String, Error> {
        Ok(self.source.read_comm()?)
    }

    pub fn exe(&self) -> Result<PathBuf, Error> {
        Ok(self.source.read_exe()?)
    }

    pub fn tids(&self) -> Result<Vec<u64>, Error> {
        Ok(self.source.list_tids()?)
    }

    fn fds(&self) -> Result<Vec<u64>, Error> {
        Ok(self.source.list_fds()?)
    }

    fn fd_path(&self, fd: u64) -> Result<PathBuf, Error> {
        Ok(self.source.read_fd_link(fd)?)
    }

    fn fdinfo(&self, fd: u64) -> Result<FdInfo, Error> {
        let contents = self.source.read_fdinfo(fd)?;
        let mut offset = None;
        let mut flags = None;
        let mut mnt_id = None;
        let mut extra_lines = Vec::new();

        for line in contents.lines() {
            if let Some(val) = line.strip_prefix("pos:") {
                offset = Some(
                    val.trim()
                        .parse::<u64>()
                        .map_err(|e| Error::in_file("fdinfo", &format!("invalid pos: {}", e)))?,
                );
            } else if let Some(val) = line.strip_prefix("flags:") {
                let raw = i32::from_str_radix(val.trim(), 8)
                    .map_err(|e| Error::in_file("fdinfo", &format!("invalid flags: {}", e)))?;
                flags = Some(OFlag::from_bits_truncate(raw));
            } else if let Some(val) = line.strip_prefix("mnt_id:") {
                mnt_id = val.trim().parse::<u64>().ok();
            } else if !line.is_empty() {
                extra_lines.push(line.to_string());
            }
        }

        Ok(FdInfo {
            offset: offset.ok_or_else(|| Error::in_file("fdinfo", "missing 'pos' field"))?,
            flags: flags.ok_or_else(|| Error::in_file("fdinfo", "missing 'flags' field"))?,
            mnt_id,
            extra_lines,
        })
    }

    // -- Parsed from /proc/[pid]/stat --------------------------------

    /// Process state parsed from `/proc/[pid]/stat`.
    pub fn state(&self) -> Result<ProcState, Error> {
        let stat = self.source.read_stat()?;
        // Use rfind to handle comm fields containing parentheses.
        let after_comm = stat
            .rfind(')')
            .ok_or_else(|| Error::in_file("stat", "missing ')' in comm field"))?
            + 1;
        let rest = stat[after_comm..].trim_start();
        rest.chars()
            .next()
            .map(ProcState::from_char)
            .ok_or_else(|| Error::in_file("stat", "empty state field"))
    }

    /// User CPU time in clock ticks (field 14 of /proc/[pid]/stat).
    pub fn utime(&self) -> Result<u64, Error> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| Error::in_file("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
        //   tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10)
        //   utime(11) stime(12) ...
        let field = after_comm
            .split_whitespace()
            .nth(11)
            .ok_or_else(|| Error::in_file("stat", "missing utime field"))?;
        field
            .parse::<u64>()
            .map_err(|e| Error::in_file("stat", &format!("invalid utime: {}", e)))
    }

    /// System CPU time in clock ticks (field 15 of /proc/[pid]/stat).
    pub fn stime(&self) -> Result<u64, Error> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| Error::in_file("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ... utime(11) stime(12) ...
        let field = after_comm
            .split_whitespace()
            .nth(12)
            .ok_or_else(|| Error::in_file("stat", "missing stime field"))?;
        field
            .parse::<u64>()
            .map_err(|e| Error::in_file("stat", &format!("invalid stime: {}", e)))
    }

    /// Process group ID (field 5 of /proc/[pid]/stat).
    pub fn pgrp(&self) -> Result<u64, Error> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| Error::in_file("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ppid(1) pgrp(2) ...
        let field = after_comm
            .split_whitespace()
            .nth(2)
            .ok_or_else(|| Error::in_file("stat", "missing pgrp field"))?;
        field
            .parse::<u64>()
            .map_err(|e| Error::in_file("stat", &format!("invalid pgrp: {}", e)))
    }

    /// Session ID (field 6 of /proc/[pid]/stat).
    pub fn sid(&self) -> Result<u64, Error> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| Error::in_file("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ppid(1) pgrp(2) session(3) ...
        let field = after_comm
            .split_whitespace()
            .nth(3)
            .ok_or_else(|| Error::in_file("stat", "missing session field"))?;
        field
            .parse::<u64>()
            .map_err(|e| Error::in_file("stat", &format!("invalid session: {}", e)))
    }

    /// Nice value (field 19 of /proc/[pid]/stat).
    pub fn nice(&self) -> Result<i32, Error> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| Error::in_file("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
        //   tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10)
        //   utime(11) stime(12) cutime(13) cstime(14) priority(15) nice(16) ...
        let field = after_comm
            .split_whitespace()
            .nth(16)
            .ok_or_else(|| Error::in_file("stat", "missing nice field"))?;
        field
            .parse::<i32>()
            .map_err(|e| Error::in_file("stat", &format!("invalid nice: {}", e)))
    }

    /// Start time in clock ticks (field 22 of /proc/[pid]/stat).
    pub fn starttime(&self) -> Result<u64, Error> {
        let data = self.source.read_stat()?;
        let close_paren = data
            .rfind(')')
            .ok_or_else(|| Error::in_file("stat", "missing ')' in comm field"))?;
        let after_comm = &data[close_paren + 2..];
        // Fields after comm: state(0) ppid(1) ... starttime(19)
        let field = after_comm
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| Error::in_file("stat", "missing starttime field"))?;
        field
            .parse::<u64>()
            .map_err(|e| Error::in_file("stat", &format!("invalid starttime: {}", e)))
    }

    // -- Parsed from /proc/[pid]/status ------------------------------

    pub fn ppid(&self) -> Result<u64, Error> {
        let status = self.source.read_status()?;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("PPid:") {
                return val
                    .trim()
                    .parse::<u64>()
                    .map_err(|e| Error::in_file("status", &format!("invalid PPid: {}", e)));
            }
        }
        Err(Error::in_file("status", "missing PPid"))
    }

    pub fn euid(&self) -> Result<u32, Error> {
        let status = self.source.read_status()?;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Uid:") {
                let fields: Vec<&str> = val.split_whitespace().collect();
                if fields.len() < 2 {
                    return Err(Error::in_file("status", "Uid field has too few values"));
                }
                return fields[1]
                    .parse::<u32>()
                    .map_err(|e| Error::in_file("status", &format!("invalid euid: {}", e)));
            }
        }
        Err(Error::in_file("status", "missing Uid"))
    }

    pub fn umask(&self) -> Result<u32, Error> {
        let status = self.source.read_status()?;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Umask:") {
                return u32::from_str_radix(val.trim(), 8)
                    .map_err(|e| Error::in_file("status", &format!("invalid Umask: {}", e)));
            }
        }
        Err(Error::in_file("status", "missing Umask"))
    }

    pub fn thread_count(&self) -> Result<usize, Error> {
        let status = self.source.read_status()?;
        let val = status
            .lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .ok_or_else(|| Error::in_file("status", "missing Threads"))?;
        val.trim()
            .parse::<usize>()
            .map_err(|e| Error::in_file("status", &format!("invalid Threads: {}", e)))
    }

    pub fn cred(&self) -> Result<ProcCred, Error> {
        let status = self.source.read_status()?;
        parse_cred(&status)
    }

    // -- Signal masks ------------------------------------------------

    /// Parse signal masks (SigIgn/SigCgt/SigBlk/SigPnd/ShdPnd) from status.
    /// The blocked mask is the intersection across all threads.
    pub fn signal_masks(&self) -> Result<SignalMasks, Error> {
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

        let sig_ign_hex = sig_ign.ok_or_else(|| Error::in_file("status", "missing SigIgn"))?;
        let sig_cgt_hex = sig_cgt.ok_or_else(|| Error::in_file("status", "missing SigCgt"))?;

        let parse = |name: &str, hex: &str| -> Result<SignalSet, Error> {
            parse_signal_set(hex)
                .map_err(|e| Error::in_file("status", &format!("invalid {}: {}", name, e)))
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
    fn thread_blocked_masks(&self) -> Option<Vec<SignalSet>> {
        let tids = self.source.list_tids().ok()?;

        // Warn if the source reports fewer threads than actually existed.
        if let Ok(status) = self.source.read_status() {
            if let Some(n) = status
                .lines()
                .find_map(|l| l.strip_prefix("Threads:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
            {
                if n > tids.len() {
                    self.warnings.borrow_mut().push(format!(
                        "warning: process had {} threads but only {} available; \
                         blocked masks may be incomplete",
                        n,
                        tids.len()
                    ));
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
            self.warnings.borrow_mut().push(format!(
                "warning: read blocked mask for {} of {} threads; \
                 blocked-signal intersection may be incomplete",
                masks.len(),
                tid_count
            ));
        }

        if masks.is_empty() {
            None
        } else {
            Some(masks)
        }
    }

    // -- Thread methods ----------------------------------------------

    /// CPU number a thread is currently running on (field 39 of tid/stat).
    pub fn thread_cpu(&self, tid: u64) -> Result<u32, Error> {
        let stat = self.source.read_tid_stat(tid)?;
        let after_comm = stat
            .rfind(')')
            .ok_or_else(|| Error::in_file("task/stat", "missing ')' in comm field"))?
            + 1;
        let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
        // processor is at index 36 after the comm field
        let val = fields
            .get(36)
            .ok_or_else(|| Error::in_file("task/stat", "missing processor field"))?;
        val.parse::<u32>()
            .map_err(|e| Error::in_file("task/stat", &format!("invalid processor: {}", e)))
    }

    /// Cpus_allowed_list from a thread's status, as a `CpuSet`.
    pub fn thread_affinity(&self, tid: u64) -> Result<numa::CpuSet, Error> {
        let status = self.source.read_tid_status(tid)?;
        let line = status
            .lines()
            .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
            .ok_or_else(|| Error::in_file("task/status", "missing Cpus_allowed_list"))?;
        numa::parse_list_format(line.trim())
    }

    // -- Compound convenience ----------------------------------------

    /// Read cmdline and split on NUL into individual arguments.
    pub fn argv(&self) -> Result<Vec<OsString>, Error> {
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
    pub(crate) fn environ(&self) -> Result<Vec<(OsString, OsString)>, Error> {
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
                    self.warnings.borrow_mut().push(format!(
                        "warning: skipping environ entry with empty key for pid {}",
                        self.pid()
                    ));
                }
            }
        }
        Ok(vars)
    }

    /// Parse scheduler statistics from `/proc/[pid]/schedstat`.
    pub fn schedstat(&self) -> Result<SchedStat, Error> {
        let data = self.source.read_schedstat()?;
        let mut fields = data.split_whitespace();
        let run_time_ns = fields
            .next()
            .ok_or_else(|| Error::in_file("schedstat", "missing run_time field"))?
            .parse::<u64>()
            .map_err(|e| Error::in_file("schedstat", &format!("invalid run_time: {}", e)))?;
        let wait_time_ns = fields
            .next()
            .ok_or_else(|| Error::in_file("schedstat", "missing wait_time field"))?
            .parse::<u64>()
            .map_err(|e| Error::in_file("schedstat", &format!("invalid wait_time: {}", e)))?;
        let timeslices = fields
            .next()
            .ok_or_else(|| Error::in_file("schedstat", "missing timeslices field"))?
            .parse::<u64>()
            .map_err(|e| Error::in_file("schedstat", &format!("invalid timeslices: {}", e)))?;
        Ok(SchedStat {
            run_time_ns,
            wait_time_ns,
            timeslices,
        })
    }

    /// Query the open-files resource limit from `/proc/[pid]/limits`.
    pub fn nofile_limit(&self) -> Result<Rlimit, Error> {
        let limits = self.source.read_limits()?;
        parse_rlimit_line(&limits, "Max open files")?
            .ok_or_else(|| Error::parse("/proc/[pid]/limits", "Max open files line not found"))
    }

    /// Parse all resource limits from `/proc/[pid]/limits`.
    pub fn resource_limits(&self) -> Result<Vec<ResourceLimit>, Error> {
        let limits = self.source.read_limits()?;
        parse_resource_limits(&limits)
    }

    /// Gather fully-populated [`fd::FileDescriptor`] structs for every open
    /// file descriptor in the process.
    ///
    /// This is the primary entry point for tools that need to enumerate a
    /// process's open files.  It combines fd path/stat/fdinfo, socket info
    /// from `/proc/net/*`, socket details via `getsockopt`, and peer process
    /// resolution into a single call.
    pub fn file_descriptors(&self) -> Result<Vec<fd::FileDescriptor>, Error> {
        let fds = self.fds()?;
        let sockets = net::parse_socket_info(&*self.source);

        let mut warnings = Vec::new();

        // Compute TCP peer processes in bulk (system-wide /proc scan).
        // Skip for coredumps or when no loopback TCP sockets exist.
        let tcp_peers = if !self.is_core && net::has_loopback_tcp_peers(&sockets) {
            net::derive_peer_processes(self.pid(), &sockets, &mut warnings)
        } else {
            std::collections::HashMap::new()
        };

        let mut result = Vec::with_capacity(fds.len());
        for fd_num in fds {
            match self.gather_fd(fd_num, &sockets, &tcp_peers, &mut warnings) {
                Ok(fd_desc) => result.push(fd_desc),
                Err(e) => {
                    warnings.push(format!(
                        "failed to gather info for /proc/{}/fd/{}: {}",
                        self.pid(),
                        fd_num,
                        e
                    ));
                }
            }
        }

        self.warnings.borrow_mut().extend(warnings);
        Ok(result)
    }

    /// Gather all available information for a single file descriptor.
    #[allow(clippy::unnecessary_cast)]
    fn gather_fd(
        &self,
        fd_num: u64,
        sockets: &std::collections::HashMap<u64, net::SocketInfo>,
        tcp_peers: &std::collections::HashMap<u64, net::PeerProcess>,
        warnings: &mut Vec<String>,
    ) -> Result<fd::FileDescriptor, Error> {
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
            fd::file_type_from_stat(st.mode, &link_text)
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
                .map(|st| st.inode)
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
                sockprotoname = fd::get_sockprotoname(self.pid(), fd_num, warnings);
            }
        }

        Ok(fd::FileDescriptor {
            fd: fd_num,
            path: path.clone(),
            file_type,
            stat: stat_result,
            offset: info.offset,
            open_flags: info.flags,
            mnt_id: info.mnt_id,
            extra_lines: info.extra_lines,
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
    DiskSleep,
    Zombie,
    Stopped,
    TracingStop,
    Dead,
    Idle,
    /// A state character not covered by the known variants.
    Other(char),
}

impl ProcState {
    fn from_char(c: char) -> Self {
        match c {
            'R' => Self::Running,
            'S' => Self::Sleeping,
            'D' => Self::DiskSleep,
            'Z' => Self::Zombie,
            'T' => Self::Stopped,
            't' => Self::TracingStop,
            'X' | 'x' => Self::Dead,
            'I' => Self::Idle,
            other => Self::Other(other),
        }
    }
}

/// Signal disposition masks parsed from /proc/[pid]/status.
pub struct SignalMasks {
    pub ignored: SignalSet,
    pub caught: SignalSet,
    /// Intersection of SigBlk across all threads.
    pub blocked: SignalSet,
    pub pending: SignalSet,
    pub shared_pending: SignalSet,
}

impl ProcHandle {
    pub fn from_pid(pid: u64) -> Self {
        ProcHandle {
            source: crate::source::open_live(pid),
            warnings: RefCell::new(Vec::new()),
            is_core: false,
        }
    }
}

/// A parsed PID with an optional thread (LWP) filter.
struct PidSpec {
    pid: u64,
    tid: Option<u64>,
}

fn parse_pid_spec(s: &str) -> Result<PidSpec, Error> {
    if let Some((pid_str, tid_str)) = s.split_once('/') {
        let pid = pid_str
            .parse::<u64>()
            .map_err(|e| Error::parse(&format!("PID '{}'", pid_str), &format!("{}", e)))?;
        let tid = tid_str
            .parse::<u64>()
            .map_err(|e| Error::parse(&format!("thread ID '{}'", tid_str), &format!("{}", e)))?;
        if pid == 0 {
            return Err(Error::Parse("PID must be >= 1".to_string()));
        }
        Ok(PidSpec {
            pid,
            tid: Some(tid),
        })
    } else {
        let pid = s
            .parse::<u64>()
            .map_err(|e| Error::parse(&format!("PID '{}'", s), &format!("{}", e)))?;
        if pid == 0 {
            return Err(Error::Parse("PID must be >= 1".to_string()));
        }
        Ok(PidSpec { pid, tid: None })
    }
}

/// Grab a process from a coredump
fn grab_core(path: &Path) -> Result<ProcHandle, Error> {
    let (source, warnings) = crate::source::open_coredump(path)?;
    Ok(ProcHandle {
        source,
        warnings: RefCell::new(warnings),
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
pub fn resolve_operand(arg: &str) -> Result<ProcHandle, Error> {
    match arg.parse::<u64>() {
        Ok(pid) => {
            if pid == 0 {
                return Err(Error::Parse("PID must be >= 1".to_string()));
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
pub fn resolve_operand_with_tid(arg: &str) -> Result<(ProcHandle, Option<u64>), Error> {
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

/// Unified error type for ptools operations.
#[derive(Debug)]
pub enum Error {
    /// I/O error from the underlying data source.
    Io(io::Error),
    /// Error parsing procfs data.
    Parse(String),
}

impl Error {
    pub fn parse(item: &str, reason: &str) -> Self {
        Error::Parse(format!("Error parsing {}: {}", item, reason))
    }
    pub fn in_file(file: &str, reason: &str) -> Self {
        Error::Parse(format!("Error parsing /proc/[pid]/{}: {}", file, reason))
    }

    /// Whether the underlying error is an I/O "not found" error.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::Io(e) if e.kind() == io::ErrorKind::NotFound)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Parse(_) => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::Parse(reason) => write!(f, "{}", reason),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::Parse(e.to_string())
    }
}
