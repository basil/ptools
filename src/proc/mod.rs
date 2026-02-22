pub mod auxv;
pub(crate) mod coredump;
pub mod cred;
pub mod fd;
pub(crate) mod live;
pub(crate) mod net;
pub mod numa;
pub mod signal;

use nix::fcntl::OFlag;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use coredump::CoredumpSource;
use cred::{parse_cred, ProcCred};
use live::LiveProcess;
use signal::{intersect_blocked_masks, parse_signal_set, SignalSet};

use auxv::{AuxvEntry, AuxvType};

/// Abstraction over process data sources.
///
/// A live process reads from `/proc/[pid]/...`; a coredump backend
/// supplies the same data from journal fields or ELF notes.
pub(crate) trait ProcSource {
    fn pid(&self) -> u64;

    // Per-process files
    fn read_stat(&self) -> io::Result<String>;
    fn read_status(&self) -> io::Result<String>;
    fn read_comm(&self) -> io::Result<String>;
    fn read_cmdline(&self) -> io::Result<Vec<u8>>;
    fn read_environ(&self) -> io::Result<Vec<u8>>;
    fn read_auxv(&self) -> io::Result<Vec<u8>>;
    fn read_exe(&self) -> io::Result<PathBuf>;
    fn read_limits(&self) -> io::Result<String>;

    // Per-thread
    fn list_tids(&self) -> io::Result<Vec<u64>>;
    fn read_tid_stat(&self, tid: u64) -> io::Result<String>;
    fn read_tid_status(&self, tid: u64) -> io::Result<String>;

    // Per-fd
    fn list_fds(&self) -> io::Result<Vec<u64>>;
    fn read_fd_link(&self, fd: u64) -> io::Result<PathBuf>;
    fn read_fdinfo(&self, fd: u64) -> io::Result<String>;

    // Network namespace
    fn read_net_file(&self, name: &str) -> io::Result<String>;
}

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

/// Resource types that can be queried via `/proc/[pid]/limits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    CpuTime,
    FileSize,
    DataSize,
    StackSize,
    CoreSize,
    ResidentSet,
    Processes,
    OpenFiles,
    LockedMemory,
    AddressSpace,
    FileLocks,
    PendingSignals,
    MsgqueueSize,
    NicePriority,
    RealtimePriority,
    RealtimeTimeout,
}

impl Resource {
    /// All known resource types, in the order they appear in
    /// `/proc/[pid]/limits`.
    pub const ALL: &[Resource] = &[
        Resource::CpuTime,
        Resource::FileSize,
        Resource::DataSize,
        Resource::StackSize,
        Resource::CoreSize,
        Resource::ResidentSet,
        Resource::Processes,
        Resource::OpenFiles,
        Resource::LockedMemory,
        Resource::AddressSpace,
        Resource::FileLocks,
        Resource::PendingSignals,
        Resource::MsgqueueSize,
        Resource::NicePriority,
        Resource::RealtimePriority,
        Resource::RealtimeTimeout,
    ];

    /// The line prefix used in `/proc/[pid]/limits` for this resource.
    fn line_prefix(self) -> &'static str {
        match self {
            Resource::CpuTime => "Max cpu time",
            Resource::FileSize => "Max file size",
            Resource::DataSize => "Max data size",
            Resource::StackSize => "Max stack size",
            Resource::CoreSize => "Max core file size",
            Resource::ResidentSet => "Max resident set",
            Resource::Processes => "Max processes",
            Resource::OpenFiles => "Max open files",
            Resource::LockedMemory => "Max locked memory",
            Resource::AddressSpace => "Max address space",
            Resource::FileLocks => "Max file locks",
            Resource::PendingSignals => "Max pending signals",
            Resource::MsgqueueSize => "Max msgqueue size",
            Resource::NicePriority => "Max nice priority",
            Resource::RealtimePriority => "Max realtime priority",
            Resource::RealtimeTimeout => "Max realtime timeout",
        }
    }
}

/// Parsed fdinfo with structured fields from `/proc/[pid]/fdinfo/<fd>`.
pub struct FdInfo {
    pub offset: u64,
    pub flags: OFlag,
    pub mnt_id: Option<u64>,
    pub extra_lines: Vec<String>,
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

/// Opaque process handle
///
/// Callers obtain a handle via [`resolve_operand`] and interact with it
/// through typed accessor methods rather than reading /proc files directly.
pub struct ProcHandle {
    source: Box<dyn ProcSource>,
    warnings: Vec<String>,
    is_core: bool,
}

impl ProcHandle {
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Whether the handle was opened from a coredump (as opposed to a live
    /// process).
    pub fn is_core(&self) -> bool {
        self.is_core
    }

    // -- Pure delegation ---------------------------------------------

    pub fn pid(&self) -> u64 {
        self.source.pid()
    }

    fn auxv_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.source.read_auxv()?)
    }

    /// Parse and return all auxiliary vector entries.
    pub fn auxv(&self) -> Result<Vec<AuxvEntry>, Error> {
        auxv::read_auxv(self)
    }

    /// Look up a specific auxv value by type.
    pub fn auxv_val(&self, key: AuxvType) -> Result<Option<u64>, Error> {
        let entries = self.auxv()?;
        Ok(entries.iter().find(|e| e.key == key).map(|e| e.value))
    }

    pub fn comm(&self) -> Result<String, Error> {
        Ok(self.source.read_comm()?)
    }

    pub fn exe(&self) -> Result<PathBuf, Error> {
        Ok(self.source.read_exe()?)
    }

    pub fn tids(&self) -> Result<Vec<u64>, Error> {
        Ok(self.source.list_tids()?)
    }

    pub fn fds(&self) -> Result<Vec<u64>, Error> {
        Ok(self.source.list_fds()?)
    }

    pub fn fd_path(&self, fd: u64) -> Result<PathBuf, Error> {
        Ok(self.source.read_fd_link(fd)?)
    }

    pub fn fdinfo(&self, fd: u64) -> Result<FdInfo, Error> {
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

    pub fn limits_raw(&self) -> Result<String, Error> {
        Ok(self.source.read_limits()?)
    }

    pub fn net_file(&self, name: &str) -> Result<String, Error> {
        Ok(self.source.read_net_file(name)?)
    }

    /// Parse socket metadata from `/proc/[pid]/net/*` files, returning a map
    /// keyed by inode number.
    pub fn socket_info(&self) -> std::collections::HashMap<u64, net::SocketInfo> {
        net::parse_socket_info(&*self.source)
    }

    /// Query socket details (options, TCP info, congestion control) for a
    /// file descriptor by duplicating it via `pidfd_getfd` and calling
    /// `getsockopt`.
    ///
    /// Returns `None` for coredumps, non-Linux platforms, or when the fd
    /// cannot be duplicated.
    pub fn socket_details(&self, fd: u64) -> Option<net::SocketDetails> {
        net::query_socket_details(self.pid(), fd)
    }

    // -- Parsed from /proc/[pid]/stat --------------------------------

    /// Process state parsed from `/proc/[pid]/stat`.
    pub fn state(&self) -> Result<ProcessState, Error> {
        let stat = self.source.read_stat()?;
        // Use rfind to handle comm fields containing parentheses.
        let after_comm = stat
            .rfind(')')
            .ok_or_else(|| Error::in_file("stat", "missing ')' in comm field"))?
            + 1;
        let rest = stat[after_comm..].trim_start();
        rest.chars()
            .next()
            .map(ProcessState::from_char)
            .ok_or_else(|| Error::in_file("stat", "empty state field"))
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
                    eprintln!(
                        "warning: process had {} threads but only {} available; \
                         blocked masks may be incomplete",
                        n,
                        tids.len()
                    );
                }
            }
        }

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
    pub fn environ(&mut self) -> Result<Vec<(OsString, OsString)>, Error> {
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
                    self.warnings.push(format!(
                        "warning: skipping environ entry with empty key for pid {}",
                        self.pid()
                    ));
                }
            }
        }
        Ok(vars)
    }

    /// Query a single resource limit from `/proc/[pid]/limits`.
    pub fn rlimit(&self, resource: Resource) -> Result<Rlimit, Error> {
        let limits = self.source.read_limits()?;
        let prefix = resource.line_prefix();
        parse_rlimit_line(&limits, prefix)?.ok_or_else(|| {
            Error::parse("/proc/[pid]/limits", &format!("{} line not found", prefix))
        })
    }

    /// Query all resource limits from `/proc/[pid]/limits`.
    ///
    /// Returns a vec of `(Resource, Rlimit)` pairs for each resource
    /// present in the limits file.
    pub fn rlimits(&self) -> Result<Vec<(Resource, Rlimit)>, Error> {
        let limits = self.source.read_limits()?;
        let mut result = Vec::new();
        for &resource in Resource::ALL {
            if let Some(rlimit) = parse_rlimit_line(&limits, resource.line_prefix())? {
                result.push((resource, rlimit));
            }
        }
        Ok(result)
    }

    /// Query the open-files resource limit.
    ///
    /// Convenience wrapper around [`rlimit(Resource::OpenFiles)`](Self::rlimit).
    pub fn nofile_limit(&self) -> Result<Rlimit, Error> {
        self.rlimit(Resource::OpenFiles)
    }

    /// Gather fully-populated [`fd::FileDescriptor`] structs for every open
    /// file descriptor in the process.
    ///
    /// This is the primary entry point for tools that need to enumerate a
    /// process's open files.  It combines `fds()`, `fd_path()`, `fdinfo()`,
    /// `stat()`, `socket_info()`, and `socket_details()` into a single call.
    pub fn file_descriptors(&self) -> Result<Vec<fd::FileDescriptor>, Error> {
        let fds = self.fds()?;
        let sockets = self.socket_info();
        let mut result = Vec::with_capacity(fds.len());
        for fd_num in fds {
            match self.gather_fd(fd_num, &sockets) {
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
                    let details = self.socket_details(fd_num);
                    socket = Some(fd::FdSocket {
                        info: sock_info.clone(),
                        details,
                    });
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
            offset: info.offset,
            open_flags: fd::OpenFlags(info.flags),
            mnt_id: info.mnt_id,
            extra_lines: info.extra_lines,
            socket,
            sockprotoname,
        })
    }
}

/// Process state from `/proc/[pid]/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
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

impl ProcessState {
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

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Sleeping => write!(f, "sleeping"),
            Self::DiskSleep => write!(f, "uninterruptible sleep"),
            Self::Zombie => write!(f, "zombie"),
            Self::Stopped => write!(f, "stopped"),
            Self::TracingStop => write!(f, "tracing stop"),
            Self::Dead => write!(f, "dead"),
            Self::Idle => write!(f, "idle"),
            Self::Other(c) => write!(f, "unknown state '{}'", c),
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
            source: Box::new(LiveProcess::new(pid)),
            warnings: Vec::new(),
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
            .map_err(|e| Error::Parse(format!("invalid PID '{}': {}", pid_str, e)))?;
        let tid = tid_str
            .parse::<u64>()
            .map_err(|e| Error::Parse(format!("invalid thread ID '{}': {}", tid_str, e)))?;
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
            .map_err(|e| Error::Parse(format!("invalid PID '{}': {}", s, e)))?;
        if pid == 0 {
            return Err(Error::Parse("PID must be >= 1".to_string()));
        }
        Ok(PidSpec { pid, tid: None })
    }
}

/// Grab a process from a coredump
fn grab_core(path: &Path) -> Result<ProcHandle, Error> {
    let source = CoredumpSource::from_corefile(path)?;
    let warnings = source.warnings().to_vec();
    Ok(ProcHandle {
        source: Box::new(source),
        warnings,
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

/// Read the process state from /proc/[pid]/stat.
pub fn proc_state(pid: u64) -> Result<ProcessState, Error> {
    ProcHandle::from_pid(pid).state()
}

/// List all thread IDs for a given PID by reading `/proc/PID/task/`.
pub fn enumerate_tids(pid: u64) -> Result<Vec<u64>, Error> {
    ProcHandle::from_pid(pid).tids()
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
