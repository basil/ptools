//
//   Copyright 2018 Delphix
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

// Remove jemalloc and use the system allocator instead. Jemalloc accounts for ~300K in a stripped
// binary, and isn't useful here because we will be doing minimal allocation.
use std::alloc::System;
#[global_allocator]
static ALLOCATOR: System = System;

use std::error::Error;
use std::fs::File;
use std::io::ErrorKind;
use std::io::{BufRead, BufReader, Read};

// TODO May want to save space by removing regex crate
// TODO Add a type alias for Result<Foo, Box<Error>>
// TODO Add support for handling core dumps
// TODO Handle unprintable characters in anything we need to print and non-UTF8 in any input
// TODO Replace top-level .unwrap()s with nicer error messages
// TODO Test against 32-bit processes

// Error handling philosophy: in general these tools should try to recover from errors and continue
// to produce useful output. Debugging tools, much more so than other tools, are expected to be run
// on systems which are in unusual and bad states. Indeed, this is when they are most useful. Note
// that this mainly refers to situations where info on the system doesn't match our expectations.
// For instance, if we expect a particular field in /proc/[pid]/status to have a particular value,
// and it doesn't, we shouldn't panic. On the other hand, we should feel free to assert that some
// purely internal invariant holds, and panic if it doesn't.

pub mod cli;

/// A parsed PID with an optional thread (LWP) filter.
pub struct PidSpec {
    pub pid: u64,
    pub tid: Option<u64>,
}

pub fn parse_pid_spec(s: &str) -> Result<PidSpec, String> {
    if let Some((pid_str, tid_str)) = s.split_once('/') {
        let pid = pid_str
            .parse::<u64>()
            .map_err(|e| format!("invalid PID '{}': {}", pid_str, e))?;
        let tid = tid_str
            .parse::<u64>()
            .map_err(|e| format!("invalid thread ID '{}': {}", tid_str, e))?;
        if pid == 0 {
            return Err("PID must be >= 1".to_string());
        }
        Ok(PidSpec {
            pid,
            tid: Some(tid),
        })
    } else {
        let pid = s
            .parse::<u64>()
            .map_err(|e| format!("invalid PID '{}': {}", s, e))?;
        if pid == 0 {
            return Err("PID must be >= 1".to_string());
        }
        Ok(PidSpec { pid, tid: None })
    }
}

/// Read the state character from /proc/[pid]/stat.
pub fn proc_state(pid: u64) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Use rfind to handle comm fields containing parentheses, e.g. "(a)b)".
    let after_comm = stat.rfind(')')? + 1;
    let rest = stat[after_comm..].trim_start();
    rest.chars().next()
}

pub fn open_or_warn(filename: &str) -> Option<File> {
    match File::open(filename) {
        Ok(file) => Some(file),
        Err(e) => {
            eprintln!("Error opening {}: {}", filename, e);
            None
        }
    }
}

pub fn print_env(pid: u64) {
    // This contains the environ as it was when the proc was started. To get the current
    // environment, we need to inspect its memory to find out how it has changed. POSIX defines a
    // char **__environ symbol that we will need to find. Unfortunately, inspecting the memory of
    // another process is not typically permitted, even if the process is owned by the same user. See
    // /etc/sysctl.d/10-ptrace.conf for details.
    //
    // TODO Long term, we might want to print the current environment if we can, and print a warning
    // + the contents of /proc/[pid]/environ if we can't
    if let Some(file) = open_or_warn(&format!("/proc/{}/environ", pid)) {
        print_proc_summary(pid);

        let mut i = 0;
        for bytes in BufReader::new(file).split('\0' as u8) {
            match &bytes {
                Ok(bytes) => {
                    let arg = String::from_utf8_lossy(bytes);
                    // Skip entries that aren't valid env vars (KEY=VALUE with non-empty KEY).
                    // Processes like sshd overwrite their environ memory with status info,
                    // leaving garbage and null bytes in /proc/[pid]/environ.
                    if let Some(pos) = arg.find('=') {
                        if pos > 0 {
                            println!("envp[{}]: {}", i, arg);
                            i += 1;
                        }
                    }
                }
                Err(e) => {
                    eprint!("Error reading environment: {}", e)
                }
            }
        }
    }
}

// Print the pid and a summary of command line arguments on a single line.
pub fn print_proc_summary(pid: u64) {
    print!("{:8}", format!("{}:", pid));
    print_cmd_summary(pid);
}

#[derive(Debug)]
pub struct ParseError {
    reason: String,
}

impl ParseError {
    pub fn new(item: &str, reason: &str) -> Self {
        ParseError {
            reason: format!("Error parsing {}: {}", item, reason),
        }
    }
    pub fn in_file(file: &str, reason: &str) -> Self {
        ParseError {
            reason: format!("Error parsing /proc/[pid]/{}: {}", file, reason),
        }
    }
}

impl Error for ParseError {
    fn description(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

// Print a summary of command line arguments on a single line.
pub fn print_cmd_summary(pid: u64) {
    match File::open(format!("/proc/{}/cmdline", pid)) {
        Ok(file) => {
            let mut printed_anything = false;
            for arg in BufReader::new(file).take(80).split('\0' as u8) {
                match arg {
                    Ok(arg) => {
                        if !arg.is_empty() {
                            printed_anything = true;
                            print!("{} ", String::from_utf8_lossy(&arg));
                        }
                    }
                    Err(e) => {
                        println!("<error reading cmdline>");
                        eprintln!("{}", e.to_string());
                        break;
                    }
                }
            }
            if !printed_anything {
                match std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
                    Ok(comm) => {
                        let comm = comm.trim_end();
                        if comm.is_empty() {
                            print!("<unknown>");
                        } else {
                            print!("{}", comm);
                        }
                    }
                    Err(ref e) if e.kind() == ErrorKind::NotFound => {
                        print!("<exited>");
                    }
                    Err(_) => {
                        print!("<unknown>");
                    }
                }
            }
            print!("\n");
        }
        Err(ref e) if e.kind() == ErrorKind::NotFound => {
            println!("<exited>");
        }
        Err(e) => {
            println!("<error reading cmdline>");
            eprintln!("{}", e.to_string());
        }
    }
}
