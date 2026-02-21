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

use std::collections::{HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::process;

use nix::errno::Errno;
use nix::libc;
use nix::poll::{self, PollFd, PollFlags, PollTimeout};

/// Open a pidfd for the given PID via the pidfd_open(2) syscall.
fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
    }
}

/// Read the wait status from a raw fd via waitid(P_PIDFD, ...).
/// Returns Ok(status) on success, Err(errno) on failure.
fn pidfd_wait_status(raw_fd: i32) -> Result<i32, Errno> {
    let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            raw_fd as libc::id_t,
            &mut siginfo,
            libc::WEXITED,
        )
    };
    if ret < 0 {
        return Err(Errno::last());
    }
    // Reconstruct the traditional wait status from siginfo fields.
    let code = siginfo.si_code;
    let status = unsafe { siginfo.si_status() };
    let wait_status = match code {
        libc::CLD_EXITED => (status & 0xff) << 8,
        libc::CLD_KILLED => status & 0x7f,
        libc::CLD_DUMPED => (status & 0x7f) | 0x80,
        _ => 0,
    };
    Ok(wait_status)
}

struct Args {
    verbose: bool,
    pid: Vec<u64>,
}

fn print_usage() {
    eprintln!("Usage: pwait [-v] PID...");
    eprintln!("Wait for processes to terminate.");
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
                match s.parse::<u64>() {
                    Ok(pid) if pid >= 1 && pid <= i32::MAX as u64 => args.pid.push(pid),
                    _ => {
                        eprintln!("pwait: invalid PID '{s}'");
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

    // Map raw fd -> (OwnedFd, pid) for O(1) lookup.
    let mut entries: HashMap<i32, (OwnedFd, u64)> = HashMap::new();

    for pid in &pids {
        match pidfd_open(*pid as libc::pid_t) {
            Ok(fd) => {
                entries.insert(fd.as_raw_fd(), (fd, *pid));
            }
            Err(e) => {
                eprintln!("pwait: failed to open pidfd for {}: {}", pid, e);
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
                eprintln!("pwait: poll: {}", e);
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
            let (_, pid) = &entries[&raw_fd];

            if args.verbose {
                // waitid(P_PIDFD) only works for child processes; for
                // non-children it returns ECHILD, and we simply omit the
                // wait status in that case.
                match pidfd_wait_status(raw_fd) {
                    Ok(status) => {
                        println!("{}: terminated, wait status {:#06x}", pid, status);
                    }
                    Err(Errno::ECHILD) => {
                        println!("{}: terminated", pid);
                    }
                    Err(e) => {
                        eprintln!("pwait: waitid for {}: {}", pid, e);
                        println!("{}: terminated", pid);
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
