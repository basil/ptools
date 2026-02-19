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

use std::process::exit;

struct Args {
    pid: Vec<u64>,
}

fn print_usage() {
    eprintln!("Usage: penv PID...");
    eprintln!("Print process environment variables.");
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
        eprintln!("penv: {e}");
        exit(2);
    }) {
        match arg {
            Short('h') | Long("help") => {
                print_usage();
                exit(0);
            }
            Short('V') | Long("version") => {
                println!("penv {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            Value(val) => {
                let s = val.to_string_lossy();
                match s.parse::<u64>() {
                    Ok(pid) if pid >= 1 => args.pid.push(pid),
                    _ => {
                        eprintln!("penv: invalid PID '{s}'");
                        exit(2);
                    }
                }
            }
            _ => {
                eprintln!("penv: unexpected argument: {arg:?}");
                exit(2);
            }
        }
    }

    if args.pid.is_empty() {
        eprintln!("penv: at least one PID required");
        exit(2);
    }
    args
}

fn main() {
    let args = parse_args();

    let mut error = false;
    let mut first = true;
    for &pid in &args.pid {
        if !first {
            println!();
        }
        first = false;
        if !ptools::print_env(pid) {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}
