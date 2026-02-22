pub mod auxv;
pub(crate) mod coredump;
pub mod cred;
pub(crate) mod live;
pub mod numa;

use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};

use coredump::CoredumpSource;
use cred::{parse_cred, ProcCred};
use live::LiveProcess;

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

    pub fn cmdline_bytes(&self) -> io::Result<Vec<u8>> {
        self.source.read_cmdline()
    }

    pub fn environ_bytes(&self) -> io::Result<Vec<u8>> {
        self.source.read_environ()
    }

    pub fn auxv_bytes(&self) -> io::Result<Vec<u8>> {
        self.source.read_auxv()
    }

    pub fn comm(&self) -> io::Result<String> {
        self.source.read_comm()
    }

    pub fn exe(&self) -> io::Result<PathBuf> {
        self.source.read_exe()
    }

    pub fn tids(&self) -> Vec<u64> {
        self.source.list_tids().unwrap_or_default()
    }

    pub fn fds(&self) -> io::Result<Vec<u64>> {
        self.source.list_fds()
    }

    pub fn fd_path(&self, fd: u64) -> io::Result<PathBuf> {
        self.source.read_fd_link(fd)
    }

    pub fn fdinfo_raw(&self, fd: u64) -> io::Result<String> {
        self.source.read_fdinfo(fd)
    }

    pub fn limits_raw(&self) -> io::Result<String> {
        self.source.read_limits()
    }

    pub fn net_file(&self, name: &str) -> io::Result<String> {
        self.source.read_net_file(name)
    }

    // -- Parsed from /proc/[pid]/stat --------------------------------

    /// Process state character (R, S, D, Z, T, t, ...).
    pub fn state(&self) -> Option<char> {
        let stat = self.source.read_stat().ok()?;
        // Use rfind to handle comm fields containing parentheses.
        let after_comm = stat.rfind(')')? + 1;
        let rest = stat[after_comm..].trim_start();
        rest.chars().next()
    }

    /// Start time in clock ticks (field 22 of /proc/[pid]/stat).
    pub fn starttime(&self) -> Option<u64> {
        let data = self.source.read_stat().ok()?;
        let after_comm = &data[data.rfind(')')? + 2..];
        // Fields after comm: state(0) ppid(1) ... starttime(19)
        after_comm.split_whitespace().nth(19)?.parse().ok()
    }

    // -- Parsed from /proc/[pid]/status ------------------------------

    pub fn ppid(&self) -> Result<u64, ParseError> {
        let status = self
            .source
            .read_status()
            .map_err(|e| ParseError::in_file("status", &e.to_string()))?;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("PPid:") {
                return val
                    .trim()
                    .parse::<u64>()
                    .map_err(|e| ParseError::in_file("status", &format!("invalid PPid: {}", e)));
            }
        }
        Err(ParseError::in_file("status", "missing PPid"))
    }

    pub fn euid(&self) -> Result<u32, ParseError> {
        let status = self
            .source
            .read_status()
            .map_err(|e| ParseError::in_file("status", &e.to_string()))?;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Uid:") {
                let fields: Vec<&str> = val.split_whitespace().collect();
                if fields.len() < 2 {
                    return Err(ParseError::in_file(
                        "status",
                        "Uid field has too few values",
                    ));
                }
                return fields[1]
                    .parse::<u32>()
                    .map_err(|e| ParseError::in_file("status", &format!("invalid euid: {}", e)));
            }
        }
        Err(ParseError::in_file("status", "missing Uid"))
    }

    pub fn umask(&self) -> Result<u32, ParseError> {
        let status = self
            .source
            .read_status()
            .map_err(|e| ParseError::in_file("status", &e.to_string()))?;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Umask:") {
                return u32::from_str_radix(val.trim(), 8)
                    .map_err(|e| ParseError::in_file("status", &format!("invalid Umask: {}", e)));
            }
        }
        Err(ParseError::in_file("status", "missing Umask"))
    }

    pub fn thread_count(&self) -> Option<usize> {
        let status = self.source.read_status().ok()?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
    }

    pub fn cred(&self) -> Result<ProcCred, ParseError> {
        let status = self
            .source
            .read_status()
            .map_err(|e| ParseError::in_file("status", &e.to_string()))?;
        parse_cred(&status)
    }

    // -- Signal masks ------------------------------------------------

    /// Parse signal masks (SigIgn/SigCgt/SigBlk/SigPnd/ShdPnd) from status.
    /// The blocked mask is the intersection across all threads.
    pub fn signal_masks(&self) -> Option<SignalMasks> {
        let pid = self.pid();
        let status = self
            .source
            .read_status()
            .map_err(|e| {
                eprintln!("Error reading /proc/{}/status: {}", pid, e);
                e
            })
            .ok()?;

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

        let sig_ign_hex = match sig_ign {
            Some(x) => x,
            None => {
                eprintln!("Error parsing /proc/{}/status: missing SigIgn", pid);
                return None;
            }
        };
        let sig_cgt_hex = match sig_cgt {
            Some(x) => x,
            None => {
                eprintln!("Error parsing /proc/{}/status: missing SigCgt", pid);
                return None;
            }
        };

        let parse = |name: &str, hex: &str| -> Option<Vec<bool>> {
            parse_signal_set(hex)
                .map_err(|e| {
                    eprintln!("Error parsing /proc/{}/status {}: {}", pid, name, e);
                    e
                })
                .ok()
        };

        let ignored = parse("SigIgn", &sig_ign_hex)?;
        let caught = parse("SigCgt", &sig_cgt_hex)?;

        // Compute blocked mask as intersection across all threads.
        // Falls back to main thread's SigBlk if /proc/[pid]/task/ is unreadable.
        let blocked = self
            .thread_blocked_masks()
            .map(|masks| intersect_blocked_masks(&masks))
            .or_else(|| sig_blk.and_then(|s| parse("SigBlk", &s)))
            .unwrap_or_default();

        let pending = sig_pnd
            .and_then(|s| parse("SigPnd", &s))
            .unwrap_or_default();
        let shared_pending = shd_pnd
            .and_then(|s| parse("ShdPnd", &s))
            .unwrap_or_default();

        Some(SignalMasks {
            ignored,
            caught,
            blocked,
            pending,
            shared_pending,
        })
    }

    /// Per-thread blocked masks (SigBlk from each thread's status).
    pub fn thread_blocked_masks(&self) -> Option<Vec<Vec<bool>>> {
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
    pub fn thread_cpu(&self, tid: u64) -> Option<u32> {
        let stat = self.source.read_tid_stat(tid).ok()?;
        let after_comm = stat.rfind(')')? + 1;
        let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
        // processor is at index 36 after the comm field
        fields.get(36)?.parse::<u32>().ok()
    }

    /// Cpus_allowed_list from a thread's status, as a sorted list of CPU IDs.
    pub fn thread_affinity(&self, tid: u64) -> Option<Vec<u32>> {
        let status = self.source.read_tid_status(tid).ok()?;
        let line = status
            .lines()
            .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))?;
        crate::proc::numa::parse_list_format(line.trim()).ok()
    }

    // -- Compound convenience ----------------------------------------

    /// Read cmdline and split on NUL into individual argument vectors.
    pub fn argv(&self) -> io::Result<Vec<Vec<u8>>> {
        let bytes = self.source.read_cmdline()?;
        let mut args: Vec<Vec<u8>> = bytes.split(|b| *b == b'\0').map(<[u8]>::to_vec).collect();
        if args.last().is_some_and(|arg| arg.is_empty()) {
            args.pop();
        }
        Ok(args)
    }

    /// Parse the "flags:" field from fdinfo as an octal file-flags value.
    pub fn fd_flags(&self, fd: u64) -> Result<u64, Box<dyn Error>> {
        let contents = self.source.read_fdinfo(fd)?;
        let line = contents
            .lines()
            .rfind(|line| line.starts_with("flags:"))
            .ok_or(ParseError::in_file("fdinfo", "no value 'flags'"))?;
        let (_, value) = line.split_once(':').ok_or(ParseError::in_file(
            "fdinfo",
            &format!("unexpected format for 'flags': {}", line),
        ))?;
        Ok(u64::from_str_radix(value.trim(), 8)?)
    }

    /// Parse the "pos:" field from fdinfo as the file offset.
    pub fn fd_offset(&self, fd: u64) -> Result<u64, Box<dyn Error>> {
        let contents = self.source.read_fdinfo(fd)?;
        let line = contents
            .lines()
            .rfind(|line| line.starts_with("pos:"))
            .ok_or(ParseError::in_file("fdinfo", "no value 'pos'"))?;
        let (_, value) = line.split_once(':').ok_or(ParseError::in_file(
            "fdinfo",
            &format!("unexpected format for 'pos': {}", line),
        ))?;
        Ok(value.trim().parse::<u64>()?)
    }

    /// Parse the "Max open files" line from /proc/[pid]/limits.
    pub fn nofile_limit(&self) -> Result<(String, String), Box<dyn Error>> {
        let limits = self.source.read_limits()?;
        for line in limits.lines() {
            if line.starts_with("Max open files") {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 6 {
                    return Err(Box::new(ParseError::new(
                        "Max open files",
                        "line has fewer fields than expected",
                    )));
                }
                return Ok((fields[3].to_string(), fields[4].to_string()));
            }
        }
        Err(Box::new(ParseError::new(
            "/proc/[pid]/limits",
            "Max open files line not found",
        )))
    }
}

/// Signal disposition masks parsed from /proc/[pid]/status.
pub struct SignalMasks {
    pub ignored: Vec<bool>,
    pub caught: Vec<bool>,
    /// Intersection of SigBlk across all threads.
    pub blocked: Vec<bool>,
    pub pending: Vec<bool>,
    pub shared_pending: Vec<bool>,
}

/// Parse a hex signal mask (e.g. from SigIgn) into a boolean vector indexed by signal number.
pub fn parse_signal_set(hex: &str) -> Result<Vec<bool>, String> {
    let trimmed = hex.trim();
    if trimmed.is_empty() {
        return Err("empty signal mask".to_string());
    }

    let mut bits = vec![false; 1];
    for (nibble_idx, ch) in trimmed.bytes().rev().enumerate() {
        let nibble = match ch {
            b'0'..=b'9' => ch - b'0',
            b'a'..=b'f' => 10 + (ch - b'a'),
            b'A'..=b'F' => 10 + (ch - b'A'),
            _ => {
                return Err(format!("invalid hex digit '{}'", ch as char));
            }
        };

        for bit in 0..4 {
            if (nibble & (1 << bit)) == 0 {
                continue;
            }
            let sig = nibble_idx * 4 + bit as usize + 1;
            if sig >= bits.len() {
                bits.resize(sig + 1, false);
            }
            bits[sig] = true;
        }
    }

    Ok(bits)
}

/// Compute the intersection of per-thread blocked masks.
pub fn intersect_blocked_masks(masks: &[Vec<bool>]) -> Vec<bool> {
    let Some(first) = masks.first() else {
        return Vec::new();
    };
    let max_len = masks.iter().map(|m| m.len()).max().unwrap_or(0);
    let mut result = vec![false; max_len];
    for i in 0..max_len {
        result[i] = masks.iter().all(|m| i < m.len() && m[i]);
    }
    // If there's only one thread, just return its mask directly.
    if masks.len() == 1 {
        return first.clone();
    }
    result
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

fn parse_pid_spec(s: &str) -> Result<PidSpec, String> {
    if let Some((pid_str, tid_str)) = s.split_once('/') {
        let pid = pid_str
            .parse::<u64>()
            .map_err(|e| format!("invalid PID '{}': {}", pid_str, e))?;
        let tid = tid_str
            .parse::<u64>()
            .map_err(|e| format!("invalid thread ID '{}': {}", tid_str, e))?;
        if pid == 0 {
            return Err("PID must be >= 1".to_string());
        }
        Ok(PidSpec {
            pid,
            tid: Some(tid),
        })
    } else {
        let pid = s
            .parse::<u64>()
            .map_err(|e| format!("invalid PID '{}': {}", s, e))?;
        if pid == 0 {
            return Err("PID must be >= 1".to_string());
        }
        Ok(PidSpec { pid, tid: None })
    }
}

/// Grab a process from a coredump
fn grab_core(path: &Path) -> Result<ProcHandle, io::Error> {
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
pub fn resolve_operand(arg: &str) -> Result<ProcHandle, String> {
    match arg.parse::<u64>() {
        Ok(pid) => {
            if pid == 0 {
                return Err("PID must be >= 1".to_string());
            }
            Ok(ProcHandle::from_pid(pid))
        }
        Err(_) => {
            let path = PathBuf::from(arg);
            grab_core(&path).map_err(|e| e.to_string())
        }
    }
}

/// Resolve a positional operand to a `ProcHandle` and optional thread ID.
///
/// Resolution order:
/// 1. Try parsing as a PID spec (`1234` or `1234/5`)
/// 2. If that fails and the arg is purely digits, surface the PID error
/// 3. Otherwise treat as a coredump file path
pub fn resolve_operand_with_tid(arg: &str) -> Result<(ProcHandle, Option<u64>), String> {
    match parse_pid_spec(arg) {
        Ok(spec) => Ok((ProcHandle::from_pid(spec.pid), spec.tid)),
        Err(e) => {
            if arg.bytes().all(|b| b.is_ascii_digit()) {
                return Err(e);
            }
            let path = PathBuf::from(arg);
            grab_core(&path)
                .map(|h| (h, None))
                .map_err(|e| e.to_string())
        }
    }
}

/// Read the state character from /proc/[pid]/stat.
pub fn proc_state(pid: u64) -> Option<char> {
    ProcHandle::from_pid(pid).state()
}

/// List all thread IDs for a given PID by reading `/proc/PID/task/`.
pub fn enumerate_tids(pid: u64) -> Vec<u64> {
    ProcHandle::from_pid(pid).tids()
}

#[derive(Debug)]
pub struct ParseError {
    reason: String,
}

impl ParseError {
    pub fn new(item: &str, reason: &str) -> Self {
        ParseError {
            reason: format!("Error parsing {}: {}", item, reason),
        }
    }
    pub fn in_file(file: &str, reason: &str) -> Self {
        ParseError {
            reason: format!("Error parsing /proc/[pid]/{}: {}", file, reason),
        }
    }
}

impl Error for ParseError {}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}
