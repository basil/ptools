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
use std::thread;
use std::time::Duration;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

/// Poll until the process reaches stopped state or no longer exists.
/// Uses exponential backoff starting at 10ms, capped at 100ms.
fn verify_stopped(pid: u64) -> bool {
    use ptools::ProcessState;

    let handle = ptools::ProcHandle::from_pid(pid);
    let mut backoff = Duration::from_millis(10);
    let cap = Duration::from_millis(100);
    let mut warned_d = false;
    loop {
        match handle.state() {
            Some(ProcessState::Stopped) => return true,
            Some(ProcessState::TracingStop) => {
                eprintln!(
                    "pstop: process {} is stopped under a debugger, not by us",
                    pid
                );
                return false;
            }
            None => {
                eprintln!("pstop: process {} has exited", pid);
                return false;
            }
            Some(ProcessState::DiskSleep) => {
                if !warned_d {
                    eprintln!(
                        "pstop: process {} is in uninterruptible sleep; \
                         SIGSTOP is pending but may take time to take effect",
                        pid
                    );
                    warned_d = true;
                }
                thread::sleep(backoff);
                backoff = (backoff * 2).min(cap);
            }
            Some(_) => {
                thread::sleep(backoff);
                backoff = (backoff * 2).min(cap);
            }
        }
    }
}

fn stop_process(pid: u64) -> bool {
    let nix_pid = Pid::from_raw(pid as i32);
    if let Err(e) = signal::kill(nix_pid, Signal::SIGSTOP) {
        eprintln!("pstop: cannot stop {}: {}", pid, e);
        return false;
    }
    verify_stopped(pid)
}

struct Args {
    pid: Vec<u64>,
}

fn print_usage() {
    eprintln!("Usage: pstop PID...");
    eprintln!("Stop processes with SIGSTOP.");
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
        eprintln!("pstop: {e}");
        process::exit(2);
    }) {
        match arg {
            Short('h') | Long("help") => {
                print_usage();
                process::exit(0);
            }
            Short('V') | Long("version") => {
                println!("pstop {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            Value(val) => {
                let s = val.to_string_lossy();
                match s.parse::<u64>() {
                    Ok(pid) if pid >= 1 && pid <= i32::MAX as u64 => args.pid.push(pid),
                    _ => {
                        eprintln!("pstop: invalid PID '{s}'");
                        process::exit(2);
                    }
                }
            }
            _ => {
                eprintln!("pstop: unexpected argument: {arg:?}");
                process::exit(2);
            }
        }
    }

    if args.pid.is_empty() {
        eprintln!("pstop: at least one PID required");
        process::exit(2);
    }
    args
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();
    let mut failed = false;

    for &pid in &args.pid {
        if !stop_process(pid) {
            failed = true;
        }
    }

    if failed {
        process::exit(1);
    }
}
