//
//   Copyright (c) 2017 Steven Fackler
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

use ptools::ProcHandle;

fn print_stack(handle: &ProcHandle, tid_filter: Option<u64>) -> Result<(), ptools::stack::Error> {
    let process = ptools::stack::trace(handle.pid() as u32)?;

    ptools::print_proc_summary_from(handle);
    println!();
    for thread in process.threads() {
        if let Some(tid) = tid_filter {
            if thread.id() as u64 != tid {
                continue;
            }
        }
        println!("{}: {}", thread.id(), thread.name().unwrap_or("<unknown>"));
        for frame in thread.frames() {
            match frame.symbol() {
                Some(symbol) => println!(
                    "{:#016x} - {} + {:#x}",
                    frame.ip(),
                    symbol.name(),
                    symbol.offset(),
                ),
                None => println!("{:#016x} - ???", frame.ip()),
            }
        }
        println!();
    }

    Ok(())
}

struct Args {
    operands: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: pstack [pid[/thread]]...");
    eprintln!("Print stack traces of running processes.");
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
        eprintln!("pstack: {e}");
        exit(2);
    }) {
        match arg {
            Short('h') | Long("help") => {
                print_usage();
                exit(0);
            }
            Short('V') | Long("version") => {
                println!("pstack {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            Value(val) => {
                args.operands.push(val.to_string_lossy().into_owned());
            }
            _ => {
                eprintln!("pstack: unexpected argument: {arg:?}");
                exit(2);
            }
        }
    }

    if args.operands.is_empty() {
        eprintln!("pstack: at least one PID required");
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
        let (handle, tid) = match ptools::resolve_operand_with_tid(operand) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("pstack: {e}");
                error = true;
                continue;
            }
        };
        for w in handle.drain_warnings() {
            eprintln!("{w}");
        }
        if let Err(e) = print_stack(&handle, tid) {
            eprintln!("pstack: {}: {e}", handle.pid());
            error = true;
        }
        for w in handle.drain_warnings() {
            eprintln!("{w}");
        }
    }
    if error {
        exit(1);
    }
}
