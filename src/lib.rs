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

use getopts::Options;
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

pub fn usage(program: &str, opts: Options) -> ! {
    usage_impl(program, opts, false);
}

pub fn usage_err(program: &str, opts: Options) -> ! {
    usage_impl(program, opts, true);
}

fn usage_impl(program: &str, opts: Options, error: bool) -> ! {
    print!("{}\n", opts.short_usage(program));
    std::process::exit(if error { 1 } else { 0 });
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

        for (i, bytes) in BufReader::new(file).split('\0' as u8).enumerate() {
            match &bytes {
                Ok(bytes) => {
                    let arg = String::from_utf8_lossy(bytes);
                    println!("envp[{}]: {}", i, arg);
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
            for arg in BufReader::new(file).take(80).split('\0' as u8) {
                match arg {
                    Ok(arg) => print!("{} ", String::from_utf8_lossy(&arg)),
                    Err(e) => {
                        println!("<error reading cmdline>");
                        eprintln!("{}", e.to_string());
                        break;
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

pub fn parse_pid(arg: &str) -> Option<u64> {
    match arg.parse::<u64>() {
        Ok(pid) => Some(pid),
        Err(_e) => {
            eprintln!("'{}' is not a valid PID", arg);
            None
        }
    }
}
