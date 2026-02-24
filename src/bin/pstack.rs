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

use std::path::Path;
use std::process::exit;

use ptools::stack::SourceLocation;
use ptools::ProcHandle;

fn format_source(src: &SourceLocation) -> String {
    let basename = Path::new(src.file())
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_else(|| src.file().into());
    if src.line() > 0 {
        format!("{basename}:{}", src.line())
    } else {
        basename.into_owned()
    }
}

fn print_stack(
    handle: Option<&ProcHandle>,
    tid_filter: Option<u64>,
    core_path: Option<&Path>,
    quiet: bool,
) -> Result<(), ptools::stack::Error> {
    let mut opts = ptools::stack::TraceOptions::new();
    let opts = opts
        .thread_names(true)
        .symbols(true)
        .demangle(!quiet)
        .module(!quiet)
        .source(!quiet)
        .inlines(!quiet);
    let process = if let Some(path) = core_path {
        opts.trace_core(path, handle)?
    } else {
        opts.trace(handle.unwrap().pid() as u32)?
    };

    if let Some(h) = handle {
        ptools::print_proc_summary_from(h);
    } else {
        print!("{}:", process.id());
    }
    println!();
    for thread in process.threads() {
        if let Some(tid) = tid_filter {
            if thread.id() as u64 != tid {
                continue;
            }
        }
        println!("{}: {}", thread.id(), thread.name().unwrap_or("<unknown>"));
        for frame in thread.frames() {
            if frame.is_inline() {
                match frame.symbol() {
                    Some(symbol) => {
                        print!("{:#016x} {} [inlined]", frame.ip(), symbol.name());
                    }
                    None => print!("{:#016x} - ??? [inlined]", frame.ip()),
                }
            } else {
                match frame.symbol() {
                    Some(symbol) => {
                        print!(
                            "{:#016x} {}+{:#x}",
                            frame.ip(),
                            symbol.name(),
                            symbol.offset()
                        );
                    }
                    None => print!("{:#016x} - ???", frame.ip()),
                }
            }
            if let Some(module) = frame.module() {
                print!(" in {module}");
            }
            if let Some(src) = frame.source() {
                print!(" at {}", format_source(src));
            }
            println!();
        }
        println!();
    }

    Ok(())
}

struct Args {
    quiet: bool,
    operands: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: pstack [-q] [pid[/thread] | core]...");
    eprintln!("Print stack traces of running processes or core dumps.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -q, --quiet      Suppress demangling, module, and source info");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        quiet: false,
        operands: Vec::new(),
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("pstack: {e}");
        exit(2);
    }) {
        match arg {
            Short('q') | Long("quiet") => {
                args.quiet = true;
            }
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
        eprintln!("pstack: at least one operand required");
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

        match ptools::resolve_operand_with_tid(operand) {
            Ok((handle, tid)) => {
                for w in handle.drain_warnings() {
                    eprintln!("{w}");
                }
                let core_path = if handle.is_core() {
                    Some(Path::new(operand.as_str()))
                } else {
                    None
                };
                if let Err(e) = print_stack(Some(&handle), tid, core_path, args.quiet) {
                    eprintln!("pstack: {}: {e}", handle.pid());
                    error = true;
                }
                for w in handle.drain_warnings() {
                    eprintln!("{w}");
                }
            }
            Err(e) => {
                // If it looks like a file path, try as a bare core dump
                // (no systemd-coredump metadata available).
                let path = Path::new(operand.as_str());
                if !operand.bytes().all(|b| b.is_ascii_digit()) && path.exists() {
                    if let Err(e) = print_stack(None, None, Some(path), args.quiet) {
                        eprintln!("pstack: {}: {e}", path.display());
                        error = true;
                    }
                } else {
                    eprintln!("pstack: {e}");
                    error = true;
                }
            }
        }
    }
    if error {
        exit(1);
    }
}
