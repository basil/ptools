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

use std::cell::Cell;
use std::io::Write;
use std::path::Path;
use std::process::exit;

use ptools::stack::{SourceLocation, Thread};
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

fn print_thread(
    thread: &Thread,
    tid_filter: Option<u64>,
    max_frames: usize,
    show_header: bool,
    first: &Cell<bool>,
) {
    if let Some(tid) = tid_filter {
        if thread.id() as u64 != tid {
            return;
        }
    }
    if !first.get() {
        println!();
    }
    first.set(false);
    if show_header {
        println!("{}:\t{}", thread.id(), thread.name().unwrap_or("<unknown>"));
    }
    for frame in thread.frames() {
        print!("{:#018x}", frame.ip());

        if let Some(symbol) = frame.symbol() {
            print!(" {}", symbol.name());

            if frame.is_inline() {
                print!(" [inlined]");
            } else {
                print!("+{:#x}", symbol.offset());
            }
        } else {
            print!(" - ???");
        }

        if let Some(module) = frame.module() {
            print!(" in {module}");
        }
        if let Some(src) = frame.source() {
            print!(" ({})", format_source(src));
        }
        println!();
    }
    if max_frames > 0 && thread.frames().len() >= max_frames {
        eprintln!("pstack: maximum number of frames exceeded (use -n 0 for unlimited)");
    }
    std::io::stdout().flush().ok();
}

fn print_stack(
    handle: &ProcHandle,
    tid_filter: Option<u64>,
    is_core: bool,
    args: &Args,
) -> Result<(), std::io::Error> {
    let mut opts = ptools::stack::TraceOptions::new();
    let opts = opts
        .thread_names(true)
        .symbols(true)
        .demangle(true)
        .module(args.module)
        .source(args.verbose)
        .inlines(args.verbose)
        .max_frames(args.max_frames);

    let first_thread = Cell::new(true);
    if is_core {
        opts.trace_core_each(
            handle,
            |pid| {
                print!("{pid}:\t");
                ptools::print_cmd_summary_from(handle);
                println!();
                first_thread.set(true);
            },
            |thread| print_thread(&thread, tid_filter, args.max_frames, true, &first_thread),
        )?;
    } else if let Some(tid) = tid_filter {
        // Single thread requested: push the filter into the backend so it only
        // attaches to (and unwinds) this one TID instead of every thread.
        opts.tid(tid as u32);
        print!("{}:\t", tid);
        ptools::print_cmd_summary_from(handle);
        opts.trace_each(handle, |thread| {
            print_thread(&thread, Some(tid), args.max_frames, false, &first_thread);
        })?;
    } else {
        let multithread = handle.thread_count().is_ok_and(|n| n > 1);
        ptools::print_proc_summary_from(handle);
        if multithread {
            println!();
        }
        opts.trace_each(handle, |thread| {
            print_thread(&thread, None, args.max_frames, multithread, &first_thread);
        })?;
    }

    Ok(())
}

const DEFAULT_MAX_FRAMES: usize = 64;

struct Args {
    verbose: bool,
    module: bool,
    max_frames: usize,
    operands: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: pstack [-mv] [-n count] [pid[/thread] | core]...");
    eprintln!("Print stack traces of running processes or core dumps.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -m, --module         Show module file paths");
    eprintln!("  -n N                 Print at most N frames per thread (0 for unlimited)");
    eprintln!("  -v, --verbose        Show source locations and inline frames");
    eprintln!("  -h, --help           Print help");
    eprintln!("  -V, --version        Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        module: false,
        verbose: false,
        max_frames: DEFAULT_MAX_FRAMES,
        operands: Vec::new(),
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("pstack: {e}");
        exit(2);
    }) {
        match arg {
            Short('m') | Long("module") => {
                args.module = true;
            }
            Short('n') => {
                let val: String = parser
                    .value()
                    .unwrap_or_else(|e| {
                        eprintln!("pstack: {e}");
                        exit(2);
                    })
                    .to_string_lossy()
                    .into_owned();
                args.max_frames = val.parse().unwrap_or_else(|e| {
                    eprintln!("pstack: -n: {e}");
                    exit(2);
                });
            }
            Short('v') | Long("verbose") => {
                args.verbose = true;
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

    // Prevent libdw/debuginfod from downloading debuginfo over the network.
    // Locally installed debug packages are still used.
    std::env::remove_var("DEBUGINFOD_URLS");

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
                    eprintln!("pstack: {w}");
                }
                if let Err(e) = print_stack(&handle, tid, handle.is_core(), &args) {
                    eprintln!("pstack: {}: {e}", handle.pid());
                    error = true;
                }
                for w in handle.drain_warnings() {
                    eprintln!("pstack: {w}");
                }
            }
            Err(e) => {
                eprintln!("pstack: {e}");
                error = true;
            }
        }
    }
    if error {
        exit(1);
    }
}
