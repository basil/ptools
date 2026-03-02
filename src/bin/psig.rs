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

use std::collections::BTreeSet;
use std::process::exit;

use nix::libc;
use nix::sys::signal::Signal;
use ptools::proc::ProcHandle;

#[derive(Copy, Clone)]
enum SignalAction {
    Default,
    Ignored,
    Caught,
}

/// Return a human-readable name for the given signal number.
///
/// Standard signals use short names like `"HUP"`, `"INT"`.
/// Real-time signals are formatted relative to `rtmin`/`rtmax`
/// (e.g. `"RTMIN"`, `"RTMIN+1"`, `"RTMAX-1"`, `"RTMAX"`).
/// Signals below `rtmin` but above 31 are named relative to RTMIN
/// (e.g. `"RTMIN-2"`, `"RTMIN-1"`).
fn signal_name(sig: usize, rtmin: usize, rtmax: usize) -> String {
    // Standard signals via nix
    if let Ok(signal) = Signal::try_from(sig as i32) {
        return match signal {
            // SIGIO and SIGPOLL share the same value; prefer SIGPOLL.
            Signal::SIGIO => "POLL".to_string(),
            s => s
                .as_str()
                .strip_prefix("SIG")
                .unwrap_or(s.as_str())
                .to_string(),
        };
    }

    // Real-time signals
    if sig == rtmin {
        return "RTMIN".to_string();
    }
    if sig == rtmax {
        return "RTMAX".to_string();
    }
    if sig < rtmin {
        return format!("RTMIN-{}", rtmin - sig);
    }
    let mid = (rtmax - rtmin) / 2;
    if sig - rtmin <= mid {
        return format!("RTMIN+{}", sig - rtmin);
    }
    if sig < rtmax {
        return format!("RTMAX-{}", rtmax - sig);
    }

    format!("SIG{sig}")
}

fn action_for_signal(
    sig: usize,
    sig_ign: &BTreeSet<usize>,
    sig_cgt: &BTreeSet<usize>,
) -> SignalAction {
    if sig_ign.contains(&sig) {
        SignalAction::Ignored
    } else if sig_cgt.contains(&sig) {
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

fn print_signal_actions(handle: &ProcHandle) -> std::io::Result<()> {
    ptools::display::print_proc_summary_from(handle);

    let masks = handle.signal_masks().map_err(|e| {
        eprintln!("psig: {e}");
        e
    })?;

    let rtmin = libc::SIGRTMIN() as usize;
    let rtmax = libc::SIGRTMAX() as usize;

    let max_sig = [rtmax, 64]
        .into_iter()
        .chain(masks.sig_ign.as_ref().and_then(|s| s.last().copied()))
        .chain(masks.sig_cgt.as_ref().and_then(|s| s.last().copied()))
        .max()
        .unwrap_or(64);

    let have_disposition = masks.sig_ign.is_some() && masks.sig_cgt.is_some();
    let empty = BTreeSet::new();
    let ignored = masks.sig_ign.as_ref().unwrap_or(&empty);
    let caught = masks.sig_cgt.as_ref().unwrap_or(&empty);
    let blocked_set = masks.sig_blk.as_ref();
    let pending_set = masks.sig_pnd.as_ref();
    let shared_pending_set = masks.shd_pnd.as_ref();

    for sig in 1..=max_sig {
        let name = signal_name(sig, rtmin, rtmax);
        let blocked = blocked_set.is_some_and(|s| s.contains(&sig));
        let pending = pending_set.is_some_and(|s| s.contains(&sig))
            || shared_pending_set.is_some_and(|s| s.contains(&sig));

        let mut parts = Vec::new();
        if blocked {
            parts.push("blocked");
        }
        if pending {
            parts.push("pending");
        }
        if have_disposition {
            let action = action_for_signal(sig, ignored, caught);
            parts.push(action_text(action));
        } else {
            parts.push("unknown");
        }

        if parts.is_empty() {
            println!("{name}");
        } else {
            println!("{:<10}{}", name, parts.join(","));
        }
    }
    Ok(())
}

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
        if ptools::proc::is_non_pid_proc_path(operand) {
            continue;
        }
        if !first {
            println!();
        }
        first = false;
        let handle = match ptools::proc::resolve_operand(operand) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("psig: {e}");
                error = true;
                continue;
            }
        };
        if print_signal_actions(&handle).is_err() {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_name_standard() {
        assert_eq!(signal_name(1, 34, 64), "HUP");
        assert_eq!(signal_name(9, 34, 64), "KILL");
        assert_eq!(signal_name(29, 34, 64), "POLL");
        assert_eq!(signal_name(31, 34, 64), "SYS");
    }

    #[test]
    fn signal_name_rt_reserved() {
        assert_eq!(signal_name(32, 34, 64), "RTMIN-2");
        assert_eq!(signal_name(33, 34, 64), "RTMIN-1");
    }

    #[test]
    fn signal_name_rt() {
        assert_eq!(signal_name(34, 34, 64), "RTMIN");
        assert_eq!(signal_name(35, 34, 64), "RTMIN+1");
        assert_eq!(signal_name(49, 34, 64), "RTMIN+15");
        assert_eq!(signal_name(50, 34, 64), "RTMAX-14");
        assert_eq!(signal_name(63, 34, 64), "RTMAX-1");
        assert_eq!(signal_name(64, 34, 64), "RTMAX");
    }
}
