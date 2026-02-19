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

use clap::Parser;
use ptools::cli::PstopCli;

/// Poll until the process reaches stopped state or no longer exists.
/// Uses exponential backoff starting at 10ms, capped at 100ms.
fn verify_stopped(pid: u64) -> bool {
    let mut backoff = Duration::from_millis(10);
    let cap = Duration::from_millis(100);
    let mut warned_d = false;
    loop {
        match ptools::proc_state(pid) {
            Some('T') => return true,
            Some('t') => {
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
            Some('D') => {
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

fn main() {
    let cli = PstopCli::parse();
    let mut failed = false;

    for &pid in &cli.pid {
        if !stop_process(pid) {
            failed = true;
        }
    }

    if failed {
        process::exit(1);
    }
}
