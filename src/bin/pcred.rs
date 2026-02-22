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

use std::process::exit;

use ptools::{resolve_gid, resolve_uid, ProcHandle};

struct Args {
    all: bool,
    operands: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: pcred [-a] [pid | core]...");
    eprintln!("Print process credentials.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -a, --all        Print all credential information separately");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        all: false,
        operands: Vec::new(),
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("pcred: {e}");
        exit(2);
    }) {
        match arg {
            Short('a') | Long("all") => {
                args.all = true;
            }
            Short('h') | Long("help") => {
                print_usage();
                exit(0);
            }
            Short('V') | Long("version") => {
                println!("pcred {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            Value(val) => {
                args.operands.push(val.to_string_lossy().into_owned());
            }
            _ => {
                eprintln!("pcred: unexpected argument: {arg:?}");
                exit(2);
            }
        }
    }

    if args.operands.is_empty() {
        eprintln!("pcred: at least one PID or core required");
        exit(2);
    }
    args
}

fn fmt_uid(uid: u32) -> String {
    match resolve_uid(uid) {
        Some(name) => format!("{}({})", uid, name),
        None => uid.to_string(),
    }
}

fn fmt_gid(gid: u32) -> String {
    match resolve_gid(gid) {
        Some(name) => format!("{}({})", gid, name),
        None => gid.to_string(),
    }
}

fn print_cred(handle: &ProcHandle, all: bool) -> Result<(), ptools::Error> {
    let pid = handle.pid();
    let cred = handle.cred().map_err(|e| {
        eprintln!("pcred: {}: {}", pid, e);
        e
    })?;

    if !all && cred.euid == cred.ruid && cred.ruid == cred.suid {
        print!("{}:\te/r/suid={}  ", pid, fmt_uid(cred.euid));
    } else {
        print!(
            "{}:\teuid={} ruid={} suid={}  ",
            pid,
            fmt_uid(cred.euid),
            fmt_uid(cred.ruid),
            fmt_uid(cred.suid)
        );
    }

    if !all && cred.egid == cred.rgid && cred.rgid == cred.sgid {
        println!("e/r/sgid={}", fmt_gid(cred.egid));
    } else {
        println!(
            "egid={} rgid={} sgid={}",
            fmt_gid(cred.egid),
            fmt_gid(cred.rgid),
            fmt_gid(cred.sgid)
        );
    }

    if !cred.groups.is_empty() && (all || cred.groups.len() != 1 || cred.groups[0] != cred.rgid) {
        print!("\tgroups:");
        for gid in &cred.groups {
            print!(" {}", fmt_gid(*gid));
        }
        println!();
    }

    Ok(())
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
        let handle = match ptools::resolve_operand(operand) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("pcred: {e}");
                error = true;
                continue;
            }
        };
        for w in handle.warnings() {
            eprintln!("{w}");
        }
        if print_cred(&handle, args.all).is_err() {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}
