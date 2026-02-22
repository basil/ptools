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

use ptools::{resolve_gid, resolve_uid, ProcSource};

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

struct Cred {
    euid: u32,
    ruid: u32,
    suid: u32,
    egid: u32,
    rgid: u32,
    sgid: u32,
    groups: Vec<u32>,
}

fn read_cred(source: &dyn ProcSource) -> Option<Cred> {
    let pid = source.pid();
    let status = source
        .read_status()
        .map_err(|e| {
            eprintln!("pcred: {}: {}", pid, e);
            e
        })
        .ok()?;

    let mut uid_fields = None;
    let mut gid_fields = None;
    let mut groups = Vec::new();

    for line in status.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key {
                "Uid" => {
                    let fields: Vec<u32> = value
                        .split_whitespace()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    if fields.len() >= 3 {
                        uid_fields = Some((fields[0], fields[1], fields[2]));
                    }
                }
                "Gid" => {
                    let fields: Vec<u32> = value
                        .split_whitespace()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    if fields.len() >= 3 {
                        gid_fields = Some((fields[0], fields[1], fields[2]));
                    }
                }
                "Groups" => {
                    groups = value
                        .split_whitespace()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                }
                _ => {}
            }
        }
    }

    let (ruid, euid, suid) = match uid_fields {
        Some(f) => f,
        None => {
            eprintln!("pcred: {}: missing Uid in /proc/{}/status", pid, pid);
            return None;
        }
    };

    let (rgid, egid, sgid) = match gid_fields {
        Some(f) => f,
        None => {
            eprintln!("pcred: {}: missing Gid in /proc/{}/status", pid, pid);
            return None;
        }
    };

    Some(Cred {
        euid,
        ruid,
        suid,
        egid,
        rgid,
        sgid,
        groups,
    })
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

fn print_cred(source: &dyn ProcSource, all: bool) -> bool {
    let pid = source.pid();
    let Some(cred) = read_cred(source) else {
        return false;
    };

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

    true
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
        let source = match ptools::resolve_operand(operand) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("pcred: {e}");
                error = true;
                continue;
            }
        };
        if !print_cred(source.as_ref(), args.all) {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}
