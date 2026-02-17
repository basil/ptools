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

use clap::{command, value_parser, Arg, ArgAction};
use nix::libc;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::mem::size_of;

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

const AUX_NAMES: &[(u64, &str)] = &[
    (libc::AT_BASE as u64, "AT_BASE"),
    (libc::AT_BASE_PLATFORM as u64, "AT_BASE_PLATFORM"),
    (libc::AT_CLKTCK as u64, "AT_CLKTCK"),
    (libc::AT_EGID as u64, "AT_EGID"),
    (libc::AT_ENTRY as u64, "AT_ENTRY"),
    (libc::AT_EUID as u64, "AT_EUID"),
    (libc::AT_EXECFD as u64, "AT_EXECFD"),
    (libc::AT_EXECFN as u64, "AT_EXECFN"),
    (libc::AT_FLAGS as u64, "AT_FLAGS"),
    (libc::AT_GID as u64, "AT_GID"),
    (libc::AT_HWCAP2 as u64, "AT_HWCAP2"),
    (libc::AT_HWCAP as u64, "AT_HWCAP"),
    (libc::AT_IGNORE as u64, "AT_IGNORE"),
    (libc::AT_MINSIGSTKSZ as u64, "AT_MINSIGSTKSZ"),
    (libc::AT_NOTELF as u64, "AT_NOTELF"),
    (libc::AT_NULL as u64, "AT_NULL"),
    (libc::AT_PAGESZ as u64, "AT_PAGESZ"),
    (libc::AT_PHDR as u64, "AT_PHDR"),
    (libc::AT_PHENT as u64, "AT_PHENT"),
    (libc::AT_PHNUM as u64, "AT_PHNUM"),
    (libc::AT_PLATFORM as u64, "AT_PLATFORM"),
    (libc::AT_RANDOM as u64, "AT_RANDOM"),
    (libc::AT_SECURE as u64, "AT_SECURE"),
    (libc::AT_SYSINFO_EHDR as u64, "AT_SYSINFO_EHDR"),
    (libc::AT_UID as u64, "AT_UID"),
];

fn aux_key_name(key: u64) -> String {
    AUX_NAMES
        .iter()
        .find_map(|(k, name)| (*k == key).then_some(*name))
        .map(str::to_string)
        .unwrap_or_else(|| format!("AT_{}", key))
}

fn parse_word(chunk: &[u8], word_size: usize) -> Result<u64, String> {
    match word_size {
        4 => {
            let raw: [u8; 4] = chunk
                .try_into()
                .map_err(|_| format!("invalid 32-bit word length {}", chunk.len()))?;
            Ok(u32::from_ne_bytes(raw) as u64)
        }
        8 => {
            let raw: [u8; 8] = chunk
                .try_into()
                .map_err(|_| format!("invalid 64-bit word length {}", chunk.len()))?;
            Ok(u64::from_ne_bytes(raw))
        }
        n => Err(format!("unsupported auxv word size {}", n)),
    }
}

fn parse_auxv_records(bytes: &[u8], word_size: usize) -> Result<Vec<(u64, u64)>, String> {
    let record_size = word_size
        .checked_mul(2)
        .ok_or_else(|| "auxv record size overflow".to_string())?;
    if record_size == 0 || bytes.len() % record_size != 0 {
        return Err(format!("unexpected auxv size {}", bytes.len()));
    }

    let mut result = Vec::new();
    let mut saw_terminator = false;
    for chunk in bytes.chunks_exact(record_size) {
        let key = parse_word(&chunk[..word_size], word_size)?;
        let value = parse_word(&chunk[word_size..record_size], word_size)?;
        if key == 0 {
            saw_terminator = true;
            break;
        }
        result.push((key, value));
    }

    if !saw_terminator {
        return Err("missing AT_NULL terminator".to_string());
    }

    Ok(result)
}

fn elf_word_size(pid: u64) -> Option<usize> {
    let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
    let mut exe_file = File::open(exe_path).ok()?;
    let mut header = [0u8; 5];
    exe_file.read_exact(&mut header).ok()?;

    if header[..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }

    match header[4] {
        1 => Some(4), // ELFCLASS32
        2 => Some(8), // ELFCLASS64
        _ => None,
    }
}

fn read_auxv(pid: u64) -> Option<Vec<(u64, u64)>> {
    if let Some(mut file) = ptools::open_or_warn(&format!("/proc/{}/auxv", pid)) {
        let mut bytes = Vec::new();
        if let Err(e) = file.read_to_end(&mut bytes) {
            eprintln!("Error reading auxv: {}", e);
            return None;
        }

        let native_word_size = size_of::<usize>();
        let mut candidate_word_sizes = Vec::new();
        if let Some(ws) = elf_word_size(pid) {
            candidate_word_sizes.push(ws);
        }
        candidate_word_sizes.push(native_word_size);
        candidate_word_sizes.push(4);
        candidate_word_sizes.push(8);

        let mut seen = HashSet::new();
        for word_size in candidate_word_sizes {
            if !seen.insert(word_size) {
                continue;
            }

            if let Ok(result) = parse_auxv_records(&bytes, word_size) {
                return Some(result);
            }
        }

        eprintln!(
            "Error parsing auxv: unexpected auxv format ({} bytes)",
            bytes.len()
        );
        None
    } else {
        None
    }
}

fn print_args(pid: u64) {
    if let Some(args) = read_cmdline(pid) {
        ptools::print_proc_summary(pid);
        for (i, bytes) in args.iter().enumerate() {
            let arg = String::from_utf8_lossy(bytes);
            println!("argv[{}]: {}", i, arg);
        }
    }
}

fn print_cmdline(pid: u64) {
    if let Some(args) = read_cmdline(pid) {
        let quoted = args
            .iter()
            .map(|arg| shell_quote(&String::from_utf8_lossy(arg)))
            .collect::<Vec<_>>();
        println!("{}", quoted.join(" "));
    }
}

fn print_auxv(pid: u64) {
    if let Some(auxv) = read_auxv(pid) {
        ptools::print_proc_summary(pid);
        for (key, value) in auxv {
            println!("{:<15} 0x{:016x}", aux_key_name(key), value);
        }
    }
}

pub fn build_cli() -> clap::Command {
    command!()
        .name("pargs")
        .about("Print process arguments")
        .long_about(
            "Examine a target process and print arguments, environment variables and values, \
or the process auxiliary vector.",
        )
        .trailing_var_arg(true)
        .arg(
            Arg::new("line")
                .short('l')
                .help("Display arguments as command line")
                .long_help(
                    "Display the arguments as a single command line. Print the command line in \
a manner suitable for interpretation by /bin/sh.",
                )
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("args")
                .short('a')
                .long("args")
                .help("Print process arguments")
                .long_help("Print process arguments as contained in /proc/pid/cmdline (default).")
                .action(ArgAction::SetTrue),
        )
        // We have a separate penv command, but keep this option for compatibility with Solaris
        .arg(
            Arg::new("env")
                .short('e')
                .long("env")
                .help("Print process environment variables")
                .long_help(
                    "Print process environment variables and values as contained in \
/proc/pid/environ.",
                )
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("auxv")
                .short('x')
                .long("auxv")
                .help("Print process auxiliary vector")
                .long_help("Print the process auxiliary vector as contained in /proc/pid/auxv.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pid")
                .value_name("PID")
                .help("Process ID (PID)")
                .long_help("A list of process IDs (PIDs)")
                .num_args(1..)
                .required(true)
                .value_parser(value_parser!(u64).range(1..)),
        )
}

fn main() {
    let matches = build_cli().get_matches();

    let do_print_args = matches.get_flag("args");
    let do_print_env = matches.get_flag("env");
    let do_print_auxv = matches.get_flag("auxv");
    let do_print_line = matches.get_flag("line");
    let want_args = do_print_args || (!do_print_env && !do_print_auxv);

    for pid in matches.get_many::<u64>("pid").unwrap() {
        if want_args {
            if do_print_line {
                print_cmdline(*pid);
            } else {
                print_args(*pid);
            }
        }
        if do_print_env {
            ptools::print_env(*pid);
        }
        if do_print_auxv {
            print_auxv(*pid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auxv_records_64_bit() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(6u64).to_ne_bytes()); // AT_PAGESZ
        bytes.extend_from_slice(&(4096u64).to_ne_bytes());
        bytes.extend_from_slice(&(0u64).to_ne_bytes()); // AT_NULL
        bytes.extend_from_slice(&(0u64).to_ne_bytes());

        let auxv = parse_auxv_records(&bytes, 8).expect("parse 64-bit auxv");
        assert_eq!(auxv, vec![(6, 4096)]);
    }

    #[test]
    fn parse_auxv_records_32_bit() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(6u32).to_ne_bytes()); // AT_PAGESZ
        bytes.extend_from_slice(&(4096u32).to_ne_bytes());
        bytes.extend_from_slice(&(0u32).to_ne_bytes()); // AT_NULL
        bytes.extend_from_slice(&(0u32).to_ne_bytes());

        let auxv = parse_auxv_records(&bytes, 4).expect("parse 32-bit auxv");
        assert_eq!(auxv, vec![(6, 4096)]);
    }

    #[test]
    fn parse_auxv_records_rejects_missing_terminator() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(6u64).to_ne_bytes());
        bytes.extend_from_slice(&(4096u64).to_ne_bytes());

        assert!(parse_auxv_records(&bytes, 8).is_err());
    }
}
