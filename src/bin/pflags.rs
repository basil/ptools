//
//   Copyright 2026 Basil Crow
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

use std::fs::{self, File};
use std::io::Read;

use nix::libc;
use ptools::PidSpec;

fn data_model(pid: u64) -> Option<&'static str> {
    let exe_path = fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
    let mut exe_file = File::open(exe_path).ok()?;
    let mut header = [0u8; 5];
    exe_file.read_exact(&mut header).ok()?;

    if header[..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }

    match header[4] {
        1 => Some("_ILP32"),
        2 => Some("_LP64"),
        _ => None,
    }
}

// Linux process flags from <linux/sched.h>
const PF_IDLE: u64 = 0x0000_0002;
const PF_EXITING: u64 = 0x0000_0004;
const PF_POSTCOREDUMP: u64 = 0x0000_0008;
const PF_IO_WORKER: u64 = 0x0000_0010;
const PF_WQ_WORKER: u64 = 0x0000_0020;
const PF_FORKNOEXEC: u64 = 0x0000_0040;
const PF_MCE_PROCESS: u64 = 0x0000_0080;
const PF_SUPERPRIV: u64 = 0x0000_0100;
const PF_DUMPCORE: u64 = 0x0000_0200;
const PF_SIGNALED: u64 = 0x0000_0400;
const PF_MEMALLOC: u64 = 0x0000_0800;
const PF_NPROC_EXCEEDED: u64 = 0x0000_1000;
const PF_USED_MATH: u64 = 0x0000_2000;
const PF_USER_WORKER: u64 = 0x0000_4000;
const PF_NOFREEZE: u64 = 0x0000_8000;
const PF_KSWAPD: u64 = 0x0002_0000;
const PF_MEMALLOC_NOFS: u64 = 0x0004_0000;
const PF_MEMALLOC_NOIO: u64 = 0x0008_0000;
const PF_LOCAL_THROTTLE: u64 = 0x0010_0000;
const PF_KTHREAD: u64 = 0x0020_0000;
const PF_RANDOMIZE: u64 = 0x0040_0000;
const PF_NO_SETAFFINITY: u64 = 0x0400_0000;
const PF_MCE_EARLY: u64 = 0x0800_0000;
const PF_MEMALLOC_PIN: u64 = 0x1000_0000;

const PROC_FLAGS: &[(u64, &str)] = &[
    (PF_IDLE, "IDLE"),
    (PF_EXITING, "EXITING"),
    (PF_POSTCOREDUMP, "POSTCOREDUMP"),
    (PF_IO_WORKER, "IO_WORKER"),
    (PF_WQ_WORKER, "WQ_WORKER"),
    (PF_FORKNOEXEC, "FORKNOEXEC"),
    (PF_MCE_PROCESS, "MCE_PROCESS"),
    (PF_SUPERPRIV, "SUPERPRIV"),
    (PF_DUMPCORE, "DUMPCORE"),
    (PF_SIGNALED, "SIGNALED"),
    (PF_MEMALLOC, "MEMALLOC"),
    (PF_NPROC_EXCEEDED, "NPROC_EXCEEDED"),
    (PF_USED_MATH, "USED_MATH"),
    (PF_USER_WORKER, "USER_WORKER"),
    (PF_NOFREEZE, "NOFREEZE"),
    (PF_KSWAPD, "KSWAPD"),
    (PF_MEMALLOC_NOFS, "MEMALLOC_NOFS"),
    (PF_MEMALLOC_NOIO, "MEMALLOC_NOIO"),
    (PF_LOCAL_THROTTLE, "LOCAL_THROTTLE"),
    (PF_KTHREAD, "KTHREAD"),
    (PF_RANDOMIZE, "RANDOMIZE"),
    (PF_NO_SETAFFINITY, "NO_SETAFFINITY"),
    (PF_MCE_EARLY, "MCE_EARLY"),
    (PF_MEMALLOC_PIN, "MEMALLOC_PIN"),
];

fn format_proc_flags(flags: u64) -> String {
    let names: Vec<&str> = PROC_FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        "0".to_string()
    } else {
        names.join("|")
    }
}

fn thread_state_name(state: char) -> &'static str {
    match state {
        'R' => "RUNNING",
        'S' => "ASLEEP",
        'D' => "SLEEPING",
        'T' => "STOPPED",
        't' => "TRACED",
        'Z' => "ZOMBIE",
        'X' => "DEAD",
        'I' => "IDLE",
        _ => "UNKNOWN",
    }
}

/// Parse the flags field (field 9) from /proc/[pid]/stat.
fn parse_stat_flags(stat_line: &str) -> Option<u64> {
    // Fields in /proc/[pid]/stat are space-separated, but field 2 (comm) is in
    // parentheses and may contain spaces. Find the last ')' to skip past comm.
    let after_comm = stat_line.rfind(')')? + 1;
    let rest = stat_line[after_comm..].trim_start();
    // rest starts at field 3 (state). Fields: 3=state 4=ppid 5=pgrp 6=session
    // 7=tty_nr 8=tpgid 9=flags
    let fields: Vec<&str> = rest.splitn(8, ' ').collect();
    if fields.len() < 7 {
        return None;
    }
    // fields[0]=state, fields[1]=ppid, ..., fields[6]=flags (index 6 = field 9)
    fields[6].parse::<u64>().ok()
}

/// Parse the state field (field 3) from /proc/[pid]/stat.
fn parse_stat_state(stat_line: &str) -> Option<char> {
    let after_comm = stat_line.rfind(')')? + 1;
    let rest = stat_line[after_comm..].trim_start();
    rest.chars().next()
}

#[cfg(target_arch = "x86_64")]
fn syscall_name(nr: i64) -> Option<&'static str> {
    // x86_64 syscall numbers from <asm/unistd_64.h>
    match nr {
        0 => Some("read"),
        1 => Some("write"),
        2 => Some("open"),
        3 => Some("close"),
        4 => Some("stat"),
        5 => Some("fstat"),
        6 => Some("lstat"),
        7 => Some("poll"),
        8 => Some("lseek"),
        9 => Some("mmap"),
        10 => Some("mprotect"),
        11 => Some("munmap"),
        16 => Some("ioctl"),
        17 => Some("pread64"),
        18 => Some("pwrite64"),
        19 => Some("readv"),
        20 => Some("writev"),
        21 => Some("access"),
        22 => Some("pipe"),
        14 => Some("rt_sigprocmask"),
        15 => Some("rt_sigreturn"),
        23 => Some("select"),
        24 => Some("sched_yield"),
        32 => Some("dup"),
        33 => Some("dup2"),
        34 => Some("pause"),
        35 => Some("nanosleep"),
        42 => Some("connect"),
        43 => Some("accept"),
        44 => Some("sendto"),
        45 => Some("recvfrom"),
        46 => Some("sendmsg"),
        47 => Some("recvmsg"),
        48 => Some("shutdown"),
        49 => Some("bind"),
        50 => Some("listen"),
        56 => Some("clone"),
        57 => Some("fork"),
        58 => Some("vfork"),
        59 => Some("execve"),
        60 => Some("exit"),
        61 => Some("wait4"),
        62 => Some("kill"),
        72 => Some("fcntl"),
        73 => Some("flock"),
        78 => Some("getdents"),
        79 => Some("getcwd"),
        80 => Some("chdir"),
        82 => Some("rename"),
        83 => Some("mkdir"),
        84 => Some("rmdir"),
        85 => Some("creat"),
        86 => Some("link"),
        87 => Some("unlink"),
        89 => Some("readlink"),
        90 => Some("chmod"),
        91 => Some("fchmod"),
        92 => Some("chown"),
        93 => Some("fchown"),
        95 => Some("umask"),
        110 => Some("getppid"),
        127 => Some("rt_sigpending"),
        128 => Some("rt_sigtimedwait"),
        129 => Some("rt_sigqueueinfo"),
        130 => Some("rt_sigsuspend"),
        131 => Some("sigaltstack"),
        186 => Some("gettid"),
        200 => Some("tkill"),
        202 => Some("futex"),
        217 => Some("getdents64"),
        228 => Some("clock_gettime"),
        230 => Some("clock_nanosleep"),
        231 => Some("exit_group"),
        232 => Some("epoll_wait"),
        233 => Some("epoll_ctl"),
        234 => Some("tgkill"),
        257 => Some("openat"),
        262 => Some("newfstatat"),
        270 => Some("pselect6"),
        271 => Some("ppoll"),
        280 => Some("utimensat"),
        281 => Some("epoll_pwait"),
        284 => Some("eventfd"),
        288 => Some("accept4"),
        290 => Some("eventfd2"),
        291 => Some("epoll_create1"),
        292 => Some("dup3"),
        293 => Some("pipe2"),
        302 => Some("prlimit64"),
        318 => Some("getrandom"),
        332 => Some("statx"),
        334 => Some("rseq"),
        435 => Some("clone3"),
        441 => Some("epoll_pwait2"),
        _ => None,
    }
}

#[cfg(target_arch = "aarch64")]
fn syscall_name(nr: i64) -> Option<&'static str> {
    // aarch64 syscall numbers from <asm-generic/unistd.h>
    match nr {
        24 => Some("dup3"),
        25 => Some("fcntl"),
        29 => Some("ioctl"),
        34 => Some("mkdirat"),
        35 => Some("unlinkat"),
        36 => Some("symlinkat"),
        37 => Some("linkat"),
        38 => Some("renameat"),
        48 => Some("faccessat"),
        49 => Some("chdir"),
        50 => Some("fchmod"),
        53 => Some("fchmodat"),
        54 => Some("fchownat"),
        56 => Some("openat"),
        57 => Some("close"),
        59 => Some("pipe2"),
        61 => Some("getdents64"),
        62 => Some("lseek"),
        63 => Some("read"),
        64 => Some("write"),
        65 => Some("readv"),
        66 => Some("writev"),
        67 => Some("pread64"),
        68 => Some("pwrite64"),
        73 => Some("ppoll"),
        78 => Some("readlinkat"),
        79 => Some("newfstatat"),
        93 => Some("exit"),
        94 => Some("exit_group"),
        96 => Some("set_tid_address"),
        98 => Some("futex"),
        101 => Some("nanosleep"),
        113 => Some("clock_gettime"),
        115 => Some("clock_nanosleep"),
        120 => Some("sched_yield"),
        124 => Some("sched_getaffinity"),
        129 => Some("kill"),
        130 => Some("tkill"),
        131 => Some("tgkill"),
        134 => Some("rt_sigaction"),
        135 => Some("rt_sigprocmask"),
        139 => Some("rt_sigreturn"),
        160 => Some("uname"),
        172 => Some("getpid"),
        173 => Some("getppid"),
        174 => Some("getuid"),
        175 => Some("geteuid"),
        176 => Some("getgid"),
        177 => Some("getegid"),
        178 => Some("gettid"),
        198 => Some("socket"),
        200 => Some("bind"),
        201 => Some("listen"),
        202 => Some("accept"),
        203 => Some("connect"),
        204 => Some("getsockname"),
        206 => Some("sendto"),
        207 => Some("recvfrom"),
        210 => Some("shutdown"),
        220 => Some("clone"),
        221 => Some("execve"),
        222 => Some("mmap"),
        226 => Some("mprotect"),
        233 => Some("madvise"),
        242 => Some("accept4"),
        260 => Some("wait4"),
        261 => Some("prlimit64"),
        268 => Some("getrandom"),
        280 => Some("epoll_pwait2"),
        281 => Some("epoll_ctl"),
        291 => Some("statx"),
        435 => Some("clone3"),
        _ => None,
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn syscall_name(_nr: i64) -> Option<&'static str> {
    None
}

struct SyscallInfo {
    name: String,
    args: Vec<String>,
}

fn parse_syscall(tid_path: &str) -> Option<SyscallInfo> {
    let content = fs::read_to_string(format!("{}/syscall", tid_path)).ok()?;
    let content = content.trim();

    if content == "running" {
        return None;
    }

    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let nr: i64 = parts[0].parse().ok()?;
    if nr == -1 {
        return None;
    }

    let name = syscall_name(nr)
        .map(str::to_string)
        .unwrap_or_else(|| format!("syscall_{}", nr));

    // Arguments are fields 1..7 (up to 6 args), followed by SP and PC
    let arg_count = if parts.len() > 7 {
        6
    } else if parts.len() > 1 {
        parts.len() - 1
    } else {
        0
    };
    let args: Vec<String> = parts[1..=arg_count].iter().map(|s| s.to_string()).collect();

    Some(SyscallInfo { name, args })
}

fn parse_signal_set(hex: &str) -> Vec<bool> {
    let trimmed = hex.trim();
    let mut bits = vec![false; 1];
    for (nibble_idx, ch) in trimmed.bytes().rev().enumerate() {
        let nibble = match ch {
            b'0'..=b'9' => ch - b'0',
            b'a'..=b'f' => 10 + (ch - b'a'),
            b'A'..=b'F' => 10 + (ch - b'A'),
            _ => continue,
        };
        for bit in 0..4 {
            if (nibble & (1 << bit)) != 0 {
                let sig = nibble_idx * 4 + bit as usize + 1;
                if sig >= bits.len() {
                    bits.resize(sig + 1, false);
                }
                bits[sig] = true;
            }
        }
    }
    bits
}

fn signal_name(sig: usize) -> String {
    let rtmin = libc::SIGRTMIN() as usize;
    let rtmax = libc::SIGRTMAX() as usize;

    if (rtmin..=rtmax).contains(&sig) {
        if sig == rtmin {
            return "RTMIN".to_string();
        }
        if sig == rtmax {
            return "RTMAX".to_string();
        }
        return format!("RTMIN+{}", sig - rtmin);
    }

    match sig as i32 {
        libc::SIGHUP => "HUP".to_string(),
        libc::SIGINT => "INT".to_string(),
        libc::SIGQUIT => "QUIT".to_string(),
        libc::SIGILL => "ILL".to_string(),
        libc::SIGTRAP => "TRAP".to_string(),
        libc::SIGABRT => "ABRT".to_string(),
        libc::SIGBUS => "BUS".to_string(),
        libc::SIGFPE => "FPE".to_string(),
        libc::SIGKILL => "KILL".to_string(),
        libc::SIGUSR1 => "USR1".to_string(),
        libc::SIGSEGV => "SEGV".to_string(),
        libc::SIGUSR2 => "USR2".to_string(),
        libc::SIGPIPE => "PIPE".to_string(),
        libc::SIGALRM => "ALRM".to_string(),
        libc::SIGTERM => "TERM".to_string(),
        libc::SIGSTKFLT => "STKFLT".to_string(),
        libc::SIGCHLD => "CLD".to_string(),
        libc::SIGCONT => "CONT".to_string(),
        libc::SIGSTOP => "STOP".to_string(),
        libc::SIGTSTP => "TSTP".to_string(),
        libc::SIGTTIN => "TTIN".to_string(),
        libc::SIGTTOU => "TTOU".to_string(),
        libc::SIGURG => "URG".to_string(),
        libc::SIGXCPU => "XCPU".to_string(),
        libc::SIGXFSZ => "XFSZ".to_string(),
        libc::SIGVTALRM => "VTALRM".to_string(),
        libc::SIGPROF => "PROF".to_string(),
        libc::SIGWINCH => "WINCH".to_string(),
        libc::SIGIO => "POLL".to_string(),
        libc::SIGPWR => "PWR".to_string(),
        libc::SIGSYS => "SYS".to_string(),
        _ => format!("SIG{}", sig),
    }
}

fn format_signal_set(bits: &[bool]) -> String {
    let names: Vec<String> = (1..bits.len())
        .filter(|&sig| bits[sig])
        .map(|sig| signal_name(sig))
        .collect();
    names.join(" ")
}

fn is_signal_set_empty(bits: &[bool]) -> bool {
    bits.iter().skip(1).all(|&b| !b)
}

fn print_thread(pid: u64, tid: u64) {
    let tid_path = format!("/proc/{}/task/{}", pid, tid);

    // Read thread state from stat
    let stat_line = match fs::read_to_string(format!("{}/stat", tid_path)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading /proc/{}/task/{}/stat: {}", pid, tid, e);
            return;
        }
    };

    let state = parse_stat_state(&stat_line).unwrap_or('?');
    let state_name = thread_state_name(state);

    // Read current syscall
    let syscall = parse_syscall(&tid_path);

    // Format the thread line
    let tid_label = format!("/{}:", tid);
    if let Some(sc) = &syscall {
        println!(
            " {:>6}\tflags = {}\t{}({})",
            tid_label,
            state_name,
            sc.name,
            sc.args.join(",")
        );
    } else {
        println!(" {:>6}\tflags = {}", tid_label, state_name);
    }

    // Read per-thread signal masks from status
    let status = match fs::read_to_string(format!("{}/status", tid_path)) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut sig_pnd = Vec::new();
    let mut sig_blk = Vec::new();

    for line in status.lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key {
                "SigPnd" => sig_pnd = parse_signal_set(value),
                "SigBlk" => sig_blk = parse_signal_set(value),
                _ => {}
            }
        }
    }

    if !is_signal_set_empty(&sig_pnd) {
        println!("\t  pending signals = {}", format_signal_set(&sig_pnd));
    }
    if !is_signal_set_empty(&sig_blk) {
        println!("\t  held signals = {}", format_signal_set(&sig_blk));
    }
}

fn print_flags(spec: &PidSpec) {
    let pid = spec.pid;

    // Read process-level stat for flags
    let stat_line = match fs::read_to_string(format!("/proc/{}/stat", pid)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading /proc/{}/stat: {}", pid, e);
            return;
        }
    };

    ptools::print_proc_summary(pid);

    // Data model and process flags
    let model = data_model(pid).unwrap_or("unknown");
    let proc_flags = parse_stat_flags(&stat_line).unwrap_or(0);
    println!(
        "\tdata model = {}\tflags = {}",
        model,
        format_proc_flags(proc_flags)
    );

    // Read process-level pending signals (shared pending)
    if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", pid)) {
        for line in status.lines() {
            if let Some((key, value)) = line.split_once(':') {
                if key == "ShdPnd" {
                    let shd_pnd = parse_signal_set(value);
                    if !is_signal_set_empty(&shd_pnd) {
                        println!("\tpending signals = {}", format_signal_set(&shd_pnd));
                    }
                }
            }
        }
    }

    // Per-thread info
    if let Some(tid) = spec.tid {
        print_thread(pid, tid);
    } else {
        let task_dir = format!("/proc/{}/task", pid);
        match fs::read_dir(&task_dir) {
            Ok(entries) => {
                let mut tids: Vec<u64> = entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok())
                    .collect();
                tids.sort();
                for tid in tids {
                    print_thread(pid, tid);
                }
            }
            Err(e) => {
                eprintln!("Error reading {}: {}", task_dir, e);
            }
        }
    }
}

use clap::Parser;
use ptools::cli::PflagsCli;

fn main() {
    let cli = PflagsCli::parse();

    for arg in &cli.pid {
        match ptools::parse_pid_spec(arg) {
            Ok(spec) => print_flags(&spec),
            Err(e) => eprintln!("pflags: {}", e),
        }
    }
}
