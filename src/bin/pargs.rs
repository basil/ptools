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

use std::io::Read;

fn read_cmdline(pid: u64) -> Option<Vec<Vec<u8>>> {
    if let Some(mut file) = ptools::open_or_warn(&format!("/proc/{}/cmdline", pid)) {
        let mut bytes = Vec::new();
        if let Err(e) = file.read_to_end(&mut bytes) {
            eprintln!("Error reading args: {}", e);
            return None;
        }
        let mut args: Vec<Vec<u8>> = bytes.split(|b| *b == b'\0').map(<[u8]>::to_vec).collect();
        if args.last().is_some_and(|arg| arg.is_empty()) {
            args.pop();
        }
        Some(args)
    } else {
        None
    }
}

fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }

    let is_shell_safe = arg
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
    if is_shell_safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\"'\"'"))
    }
}

fn print_args(pid: u64) -> bool {
    if let Some(args) = read_cmdline(pid) {
        ptools::print_proc_summary(pid);
        for (i, bytes) in args.iter().enumerate() {
            let arg = String::from_utf8_lossy(bytes);
            println!("argv[{}]: {}", i, arg);
        }
        true
    } else {
        false
    }
}

fn print_cmdline(pid: u64) -> bool {
    if let Some(args) = read_cmdline(pid) {
        // Use /proc/[pid]/exe to resolve the real executable path instead of
        // argv[0], which may be a relative path or a name set by the process.
        let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).ok();
        let mut quoted = Vec::with_capacity(args.len());
        for (i, bytes) in args.iter().enumerate() {
            let display = if i == 0 {
                if let Some(ref path) = exe {
                    path.to_string_lossy().into_owned()
                } else {
                    String::from_utf8_lossy(bytes).into_owned()
                }
            } else {
                String::from_utf8_lossy(bytes).into_owned()
            };
            quoted.push(shell_quote(&display));
        }
        println!("{}", quoted.join(" "));
        true
    } else {
        false
    }
}

use std::process::exit;

struct Args {
    line: bool,
    args: bool,
    env: bool,
    auxv: bool,
    pid: Vec<u64>,
}

fn print_usage() {
    eprintln!("Usage: pargs [-l] [-a|--args] [-e|--env] [-x|--auxv] PID...");
    eprintln!("Print process arguments.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -l               Display arguments as a single command line");
    eprintln!("  -a, --args       Print process arguments (default)");
    eprintln!("  -e, --env        Print process environment variables");
    eprintln!("  -x, --auxv       Print process auxiliary vector");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        line: false,
        args: false,
        env: false,
        auxv: false,
        pid: Vec::new(),
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("pargs: {e}");
        exit(2);
    }) {
        match arg {
            Short('h') | Long("help") => {
                print_usage();
                exit(0);
            }
            Short('V') | Long("version") => {
                println!("pargs {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            Short('l') => args.line = true,
            Short('a') | Long("args") => args.args = true,
            Short('e') | Long("env") => args.env = true,
            Short('x') | Long("auxv") => args.auxv = true,
            Value(val) => {
                let s = val.to_string_lossy();
                match s.parse::<u64>() {
                    Ok(pid) if pid >= 1 => args.pid.push(pid),
                    _ => {
                        eprintln!("pargs: invalid PID '{s}'");
                        exit(2);
                    }
                }
            }
            _ => {
                eprintln!("pargs: unexpected argument: {arg:?}");
                exit(2);
            }
        }
    }

    if args.line && (args.env || args.auxv) {
        eprintln!("pargs: -l is incompatible with -e and -x");
        exit(2);
    }

    if args.pid.is_empty() {
        eprintln!("pargs: at least one PID required");
        exit(2);
    }
    args
}

fn main() {
    let args = parse_args();

    let want_args = args.args || (!args.env && !args.auxv);

    let mut error = false;
    let mut first = true;
    for &pid in &args.pid {
        if !first {
            println!();
        }
        first = false;
        let mut section = false;
        if want_args {
            if args.line {
                if !print_cmdline(pid) {
                    error = true;
                }
            } else {
                if !print_args(pid) {
                    error = true;
                }
            }
            section = true;
        }
        if args.env {
            if section {
                println!();
            }
            if !ptools::print_env(pid) {
                error = true;
            }
            section = true;
        }
        if args.auxv {
            if section {
                println!();
            }
            if !ptools::print_auxv(pid) {
                error = true;
            }
        }
    }
    if error {
        exit(1);
    }
}
