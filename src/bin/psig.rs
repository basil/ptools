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

use clap::{command, value_parser, Arg};
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

fn parse_status_signal_masks(pid: u64) -> Option<(Vec<bool>, Vec<bool>)> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid))
        .map_err(|e| {
            eprintln!("Error reading /proc/{}/status: {}", pid, e);
            e
        })
        .ok()?;

    let mut sig_ign = None;
    let mut sig_cgt = None;

    for line in status.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key {
                "SigIgn" => sig_ign = Some(value.to_string()),
                "SigCgt" => sig_cgt = Some(value.to_string()),
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

    let sig_ign = parse_signal_set(&sig_ign)
        .map_err(|e| {
            eprintln!("Error parsing /proc/{}/status SigIgn: {}", pid, e);
            e
        })
        .ok()?;
    let sig_cgt = parse_signal_set(&sig_cgt)
        .map_err(|e| {
            eprintln!("Error parsing /proc/{}/status SigCgt: {}", pid, e);
            e
        })
        .ok()?;

    Some((sig_ign, sig_cgt))
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

fn print_signal_actions(pid: u64) {
    ptools::print_proc_summary(pid);

    let Some((sig_ign, sig_cgt)) = parse_status_signal_masks(pid) else {
        return;
    };

    let rtmin = libc::SIGRTMIN() as usize;
    let rtmax = libc::SIGRTMAX() as usize;

    let max_sig = std::cmp::max(
        64,
        std::cmp::max(
            rtmax,
            std::cmp::max(sig_ign.len(), sig_cgt.len()).saturating_sub(1),
        ),
    );

    for sig in 1..=max_sig {
        let name = signal_name(sig, rtmin, rtmax);
        let action = action_for_signal(sig, &sig_ign, &sig_cgt);
        println!("{:<10}{}", name, action_text(action));
    }
}

pub fn build_cli() -> clap::Command {
    command!()
        .name("psig")
        .about("Report process signal actions")
        .long_about("List the signal actions and handlers of each process.")
        .trailing_var_arg(true)
        .arg(
            Arg::new("pid")
                .value_name("PID")
                .help("Process ID (PID)")
                .long_help("A list of process IDs (PIDs)")
                .num_args(1..)
                .required(true)
                .value_parser(value_parser!(u64).range(1..)),
        )
}

fn main() {
    let matches = build_cli().get_matches();

    for pid in matches.get_many::<u64>("pid").unwrap() {
        print_signal_actions(*pid);
    }
}
