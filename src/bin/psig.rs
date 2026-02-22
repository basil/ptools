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
use ptools::ProcHandle;

#[derive(Copy, Clone)]
enum SignalAction {
    Default,
    Ignored,
    Caught,
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

fn print_signal_actions(handle: &ProcHandle) -> bool {
    ptools::print_proc_summary_from(handle);

    let Some(masks) = handle.signal_masks() else {
        return false;
    };

    let rtmin = libc::SIGRTMIN() as usize;
    let rtmax = libc::SIGRTMAX() as usize;

    let max_sig = std::cmp::max(
        64,
        std::cmp::max(
            rtmax,
            std::cmp::max(masks.ignored.len(), masks.caught.len()).saturating_sub(1),
        ),
    );

    for sig in 1..=max_sig {
        let name = signal_name(sig, rtmin, rtmax);
        let action = action_for_signal(sig, &masks.ignored, &masks.caught);
        let blocked = has_signal(&masks.blocked, sig);
        let pending = has_signal(&masks.pending, sig) || has_signal(&masks.shared_pending, sig);

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
    operands: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: psig [pid | core]...");
    eprintln!("Print process signal actions.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        operands: Vec::new(),
    };
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
                args.operands.push(val.to_string_lossy().into_owned());
            }
            _ => {
                eprintln!("psig: unexpected argument: {arg:?}");
                exit(2);
            }
        }
    }

    if args.operands.is_empty() {
        eprintln!("psig: at least one PID or core required");
        exit(2);
    }
    args
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();

    let mut error = false;
    let mut first = true;
    for operand in &args.operands {
        if !first {
            println!();
        }
        first = false;
        let handle = match ptools::resolve_operand(operand) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("psig: {e}");
                error = true;
                continue;
            }
        };
        for w in handle.warnings() {
            eprintln!("{w}");
        }
        if !print_signal_actions(&handle) {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}
