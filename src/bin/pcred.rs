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

use ptools::{resolve_gid, resolve_uid};

struct Args {
    all: bool,
    pid: Vec<u64>,
}

fn print_usage() {
    eprintln!("Usage: pcred [-a] PID...");
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
        pid: Vec::new(),
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
                let s = val.to_string_lossy();
                match s.parse::<u64>() {
                    Ok(pid) if pid >= 1 => args.pid.push(pid),
                    _ => {
                        eprintln!("pcred: invalid PID '{s}'");
                        exit(2);
                    }
                }
            }
            _ => {
                eprintln!("pcred: unexpected argument: {arg:?}");
                exit(2);
            }
        }
    }

    if args.pid.is_empty() {
        eprintln!("pcred: at least one PID required");
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

fn read_cred(pid: u64) -> Option<Cred> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid))
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

fn print_cred(pid: u64, all: bool) -> bool {
    let Some(cred) = read_cred(pid) else {
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
    let args = parse_args();

    let mut error = false;
    let mut first = true;
    for &pid in &args.pid {
        if !first {
            println!();
        }
        first = false;
        if !print_cred(pid, args.all) {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}
