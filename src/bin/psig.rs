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

use nix::libc;

#[derive(Copy, Clone)]
enum SignalAction {
    Default,
    Ignored,
    Caught,
}

fn parse_signal_set(hex: &str) -> Result<Vec<bool>, String> {
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

struct SignalMasks {
    sig_ign: Vec<bool>,
    sig_cgt: Vec<bool>,
    sig_blk: Vec<bool>,
    sig_pnd: Vec<bool>,
    shd_pnd: Vec<bool>,
}

fn intersect_blocked_masks(masks: &[Vec<bool>]) -> Vec<bool> {
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

fn read_thread_blocked_masks(pid: u64) -> Option<Vec<Vec<bool>>> {
    let task_dir = format!("/proc/{}/task", pid);
    let entries = std::fs::read_dir(&task_dir).ok()?;
    let mut tids: Vec<u64> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok())
        .collect();
    tids.sort();

    let mut masks = Vec::new();
    for tid in tids {
        let status_path = format!("/proc/{}/task/{}/status", pid, tid);
        let Ok(status) = std::fs::read_to_string(&status_path) else {
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

fn parse_status_signal_masks(pid: u64) -> Option<SignalMasks> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid))
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

    let sig_ign = match sig_ign {
        Some(x) => x,
        None => {
            eprintln!("Error parsing /proc/{}/status: missing SigIgn", pid);
            return None;
        }
    };
    let sig_cgt = match sig_cgt {
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

    let sig_ign = parse("SigIgn", &sig_ign)?;
    let sig_cgt = parse("SigCgt", &sig_cgt)?;

    // Compute blocked mask as intersection across all threads.
    // Falls back to main thread's SigBlk if /proc/[pid]/task/ is unreadable.
    let sig_blk = read_thread_blocked_masks(pid)
        .map(|masks| intersect_blocked_masks(&masks))
        .or_else(|| sig_blk.and_then(|s| parse("SigBlk", &s)))
        .unwrap_or_default();

    let sig_pnd = sig_pnd
        .and_then(|s| parse("SigPnd", &s))
        .unwrap_or_default();
    let shd_pnd = shd_pnd
        .and_then(|s| parse("ShdPnd", &s))
        .unwrap_or_default();

    Some(SignalMasks {
        sig_ign,
        sig_cgt,
        sig_blk,
        sig_pnd,
        shd_pnd,
    })
}

fn has_signal(m: &[bool], sig: usize) -> bool {
    sig < m.len() && m[sig]
}

fn signal_name(sig: usize, rtmin: usize, rtmax: usize) -> String {
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

fn action_for_signal(sig: usize, sig_ign: &[bool], sig_cgt: &[bool]) -> SignalAction {
    if has_signal(sig_ign, sig) {
        SignalAction::Ignored
    } else if has_signal(sig_cgt, sig) {
        SignalAction::Caught
    } else {
        SignalAction::Default
    }
}

fn action_text(action: SignalAction) -> &'static str {
    match action {
        SignalAction::Default => "default",
        SignalAction::Ignored => "ignored",
        SignalAction::Caught => "caught",
    }
}

fn print_signal_actions(pid: u64) -> bool {
    ptools::print_proc_summary(pid);

    let Some(masks) = parse_status_signal_masks(pid) else {
        return false;
    };

    let rtmin = libc::SIGRTMIN() as usize;
    let rtmax = libc::SIGRTMAX() as usize;

    let max_sig = std::cmp::max(
        64,
        std::cmp::max(
            rtmax,
            std::cmp::max(masks.sig_ign.len(), masks.sig_cgt.len()).saturating_sub(1),
        ),
    );

    for sig in 1..=max_sig {
        let name = signal_name(sig, rtmin, rtmax);
        let action = action_for_signal(sig, &masks.sig_ign, &masks.sig_cgt);
        let blocked = has_signal(&masks.sig_blk, sig);
        let pending = has_signal(&masks.sig_pnd, sig) || has_signal(&masks.shd_pnd, sig);

        let mut extra = Vec::new();
        if blocked {
            extra.push("blocked");
        }
        if pending {
            extra.push("pending");
        }

        if extra.is_empty() {
            println!("{:<10}{}", name, action_text(action));
        } else {
            println!("{:<10}{}\t{}", name, action_text(action), extra.join(","));
        }
    }
    true
}

use std::process::exit;

struct Args {
    pid: Vec<u64>,
}

fn print_usage() {
    eprintln!("Usage: psig PID...");
    eprintln!("Print process signal actions.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args { pid: Vec::new() };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("psig: {e}");
        exit(2);
    }) {
        match arg {
            Short('h') | Long("help") => {
                print_usage();
                exit(0);
            }
            Short('V') | Long("version") => {
                println!("psig {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            Value(val) => {
                let s = val.to_string_lossy();
                match s.parse::<u64>() {
                    Ok(pid) if pid >= 1 => args.pid.push(pid),
                    _ => {
                        eprintln!("psig: invalid PID '{s}'");
                        exit(2);
                    }
                }
            }
            _ => {
                eprintln!("psig: unexpected argument: {arg:?}");
                exit(2);
            }
        }
    }

    if args.pid.is_empty() {
        eprintln!("psig: at least one PID required");
        exit(2);
    }
    args
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();

    let mut error = false;
    let mut first = true;
    for &pid in &args.pid {
        if !first {
            println!();
        }
        first = false;
        if !print_signal_actions(pid) {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}
