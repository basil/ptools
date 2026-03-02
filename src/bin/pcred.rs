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

use std::process::exit;

use nix::unistd::Gid;
use nix::unistd::Group;
use nix::unistd::Uid;
use nix::unistd::User;
use ptools::proc::ProcHandle;

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
    match User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
    {
        Some(name) => format!("{uid}({name})"),
        None => uid.to_string(),
    }
}

fn fmt_gid(gid: u32) -> String {
    match Group::from_gid(Gid::from_raw(gid))
        .ok()
        .flatten()
        .map(|g| g.name)
    {
        Some(name) => format!("{gid}({name})"),
        None => gid.to_string(),
    }
}

fn print_cred(handle: &ProcHandle, all: bool) -> std::io::Result<()> {
    let pid = handle.pid();

    let euid = handle.euid().map_err(|e| {
        eprintln!("pcred: {pid}: {e}");
        e
    })?;
    let ruid = handle.ruid().map_err(|e| {
        eprintln!("pcred: {pid}: {e}");
        e
    })?;
    let suid = handle.suid().map_err(|e| {
        eprintln!("pcred: {pid}: {e}");
        e
    })?;
    let fsuid = handle.fsuid().map_err(|e| {
        eprintln!("pcred: {pid}: {e}");
        e
    })?;

    let egid = handle.egid().map_err(|e| {
        eprintln!("pcred: {pid}: {e}");
        e
    })?;
    let rgid = handle.rgid().map_err(|e| {
        eprintln!("pcred: {pid}: {e}");
        e
    })?;
    let sgid = handle.sgid().map_err(|e| {
        eprintln!("pcred: {pid}: {e}");
        e
    })?;
    let fsgid = handle.fsgid().map_err(|e| {
        eprintln!("pcred: {pid}: {e}");
        e
    })?;

    if !all && euid == ruid && ruid == suid && suid == fsuid {
        print!("{}:\te/r/s/fsuid={}  ", pid, fmt_uid(euid));
    } else {
        print!(
            "{}:\teuid={} ruid={} suid={} fsuid={}  ",
            pid,
            fmt_uid(euid),
            fmt_uid(ruid),
            fmt_uid(suid),
            fmt_uid(fsuid),
        );
    }

    if !all && egid == rgid && rgid == sgid && sgid == fsgid {
        println!("e/r/s/fsgid={}", fmt_gid(egid));
    } else {
        println!(
            "egid={} rgid={} sgid={} fsgid={}",
            fmt_gid(egid),
            fmt_gid(rgid),
            fmt_gid(sgid),
            fmt_gid(fsgid),
        );
    }

    let groups = handle.groups().unwrap_or_default();
    if !groups.is_empty() && (all || groups.len() != 1 || groups[0] != rgid) {
        print!("\tgroups:");
        for gid in &groups {
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
        if ptools::proc::is_non_pid_proc_path(operand) {
            continue;
        }
        if !first {
            println!();
        }
        first = false;
        let handle = match ptools::proc::resolve_operand(operand) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("pcred: {e}");
                error = true;
                continue;
            }
        };
        if print_cred(&handle, args.all).is_err() {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}
