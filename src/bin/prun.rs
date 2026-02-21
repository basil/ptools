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

use std::process;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

fn run_process(pid: u64) -> bool {
    let nix_pid = Pid::from_raw(pid as i32);

    // Advisory pre-check: the state can change between this read and the
    // kill(2) below (TOCTOU), but that is harmless -- SIGCONT on a
    // ptrace-stopped process is a no-op, and on a running process it is
    // silently ignored. The diagnostics here are best-effort.
    match ptools::proc_state(pid) {
        None => {
            eprintln!("prun: process {} does not exist", pid);
            return false;
        }
        Some('t') => {
            eprintln!(
                "prun: process {} is ptrace-stopped by a debugger; SIGCONT has no effect",
                pid
            );
            return false;
        }
        Some('T') => {} // stopped -- this is the expected case
        Some(_) => {
            eprintln!("prun: process {} is not stopped", pid);
            return false;
        }
    }

    if let Err(e) = signal::kill(nix_pid, Signal::SIGCONT) {
        eprintln!("prun: cannot resume {}: {}", pid, e);
        return false;
    }

    true
}

struct Args {
    pid: Vec<u64>,
}

fn print_usage() {
    eprintln!("Usage: prun PID...");
    eprintln!("Set stopped processes running with SIGCONT.");
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
        eprintln!("prun: {e}");
        process::exit(2);
    }) {
        match arg {
            Short('h') | Long("help") => {
                print_usage();
                process::exit(0);
            }
            Short('V') | Long("version") => {
                println!("prun {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            Value(val) => {
                let s = val.to_string_lossy();
                match s.parse::<u64>() {
                    Ok(pid) if pid >= 1 && pid <= i32::MAX as u64 => args.pid.push(pid),
                    _ => {
                        eprintln!("prun: invalid PID '{s}'");
                        process::exit(2);
                    }
                }
            }
            _ => {
                eprintln!("prun: unexpected argument: {arg:?}");
                process::exit(2);
            }
        }
    }

    if args.pid.is_empty() {
        eprintln!("prun: at least one PID required");
        process::exit(2);
    }
    args
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();
    let mut failed = false;

    for &pid in &args.pid {
        if !run_process(pid) {
            failed = true;
        }
    }

    if failed {
        process::exit(1);
    }
}
