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

use std::collections::HashMap;
use std::collections::HashSet;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::process;

use nix::errno::Errno;
use nix::poll::PollFd;
use nix::poll::PollFlags;
use nix::poll::PollTimeout;
use nix::poll::{self};
use ptools::proc::pidfd::PidFd;

struct Args {
    verbose: bool,
    pid: Vec<u64>,
}

fn print_usage() {
    eprintln!("Usage: pwait [-v] PID...");
    eprintln!("Wait for processes to terminate. A /proc/pid path may also be used.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -v               Report terminations to standard output");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        verbose: false,
        pid: Vec::new(),
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("pwait: {e}");
        process::exit(2);
    }) {
        match arg {
            Short('h') | Long("help") => {
                print_usage();
                process::exit(0);
            }
            Short('V') | Long("version") => {
                println!("pwait {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            Short('v') => args.verbose = true,
            Value(val) => {
                let s = val.to_string_lossy();
                match ptools::proc::parse_pid_arg(&s) {
                    Ok(ptools::proc::PidArg::Pid(pid)) => args.pid.push(pid),
                    Ok(ptools::proc::PidArg::Skip) => {}
                    Err(msg) => {
                        eprintln!("pwait: {msg}");
                        process::exit(2);
                    }
                }
            }
            _ => {
                eprintln!("pwait: unexpected argument: {arg:?}");
                process::exit(2);
            }
        }
    }

    if args.pid.is_empty() {
        eprintln!("pwait: at least one PID required");
        process::exit(2);
    }
    args
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();
    let mut failed = false;

    // Deduplicate PIDs while preserving order.
    let mut seen = HashSet::new();
    let pids: Vec<u64> = args.pid.into_iter().filter(|p| seen.insert(*p)).collect();

    // Map raw fd -> (PidFd, pid) for O(1) lookup.
    let mut entries: HashMap<i32, (PidFd, u64)> = HashMap::new();

    let my_pid = process::id() as u64;

    for pid in &pids {
        if *pid == my_pid {
            eprintln!("pwait: skipping self PID {pid}");
            failed = true;
            continue;
        }
        match PidFd::open(*pid) {
            Ok(fd) => {
                entries.insert(fd.as_raw_fd(), (fd, *pid));
            }
            Err(e) => {
                eprintln!("pwait: failed to open pidfd for {pid}: {e}");
                failed = true;
            }
        }
    }

    // Poll until all pidfds signal readiness (process exited).
    // Exit status is not propagated: on Linux, waitid(P_PIDFD) only works for
    // child processes, so we cannot reliably obtain the exit status of arbitrary
    // processes. This matches illumos pwait, which exits 0 regardless of how
    // waited processes terminated.
    while !entries.is_empty() {
        let raw_fds: Vec<i32> = entries.keys().copied().collect();
        let mut pollfds: Vec<PollFd> = raw_fds
            .iter()
            .map(|&raw_fd| {
                // SAFETY: the OwnedFd in entries is valid for the duration of poll;
                // pollfds does not outlive entries.
                PollFd::new(unsafe { BorrowedFd::borrow_raw(raw_fd) }, PollFlags::POLLIN)
            })
            .collect();

        match poll::poll(&mut pollfds, PollTimeout::NONE) {
            Err(Errno::EINTR) => continue,
            Err(e) => {
                eprintln!("pwait: poll: {e}");
                process::exit(1);
            }
            Ok(_) => {}
        }

        // Collect the raw fds that are ready.
        let ready_fds: HashSet<i32> = pollfds
            .iter()
            .zip(raw_fds.iter())
            .filter(|(pfd, _)| {
                pfd.revents().is_some_and(|r| {
                    r.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                })
            })
            .map(|(_, &raw_fd)| raw_fd)
            .collect();

        for &raw_fd in &ready_fds {
            let (pidfd, pid) = &entries[&raw_fd];

            if args.verbose {
                // waitid(P_PIDFD) only works for child processes; for
                // non-children it returns ECHILD, and we simply omit the
                // wait status in that case.
                match pidfd.wait_status() {
                    Ok(status) => {
                        println!("{pid}: terminated, wait status {status:#06x}");
                    }
                    Err(Errno::ECHILD) => {
                        println!("{pid}: terminated");
                    }
                    Err(e) => {
                        eprintln!("pwait: waitid for {pid}: {e}");
                        println!("{pid}: terminated");
                    }
                }
            }

            entries.remove(&raw_fd);
        }
    }

    if failed {
        process::exit(1);
    }
}
