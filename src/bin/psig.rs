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
use ptools::{ProcHandle, SignalSet};

#[derive(Copy, Clone)]
enum SignalAction {
    Default,
    Ignored,
    Caught,
}

fn action_for_signal(sig: usize, sig_ign: &SignalSet, sig_cgt: &SignalSet) -> SignalAction {
    if sig_ign.contains(sig) {
        SignalAction::Ignored
    } else if sig_cgt.contains(sig) {
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

fn print_signal_actions(handle: &ProcHandle) -> Result<(), ptools::Error> {
    ptools::print_proc_summary_from(handle);

    let masks = handle.signal_masks().map_err(|e| {
        eprintln!("psig: {}", e);
        e
    })?;

    let rtmin = libc::SIGRTMIN() as usize;
    let rtmax = libc::SIGRTMAX() as usize;

    let max_sig = std::cmp::max(
        64,
        std::cmp::max(
            rtmax,
            std::cmp::max(masks.ignored.max_signal(), masks.caught.max_signal()),
        ),
    );

    for sig in 1..=max_sig {
        let name = ptools::signal_name(sig, rtmin, rtmax);
        let action = action_for_signal(sig, &masks.ignored, &masks.caught);
        let blocked = masks.blocked.contains(sig);
        let pending = masks.pending.contains(sig) || masks.shared_pending.contains(sig);

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
    Ok(())
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
        if print_signal_actions(&handle).is_err() {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}
