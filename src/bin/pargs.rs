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

use nix::libc;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
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

// Not yet in the libc crate for Linux (only Android).
const AT_RSEQ_FEATURE_SIZE: u64 = 27;
const AT_RSEQ_ALIGN: u64 = 28;

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
    (AT_RSEQ_FEATURE_SIZE, "AT_RSEQ_FEATURE_SIZE"),
    (AT_RSEQ_ALIGN, "AT_RSEQ_ALIGN"),
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

fn is_string_auxv_key(key: u64) -> bool {
    key == libc::AT_EXECFN as u64
        || key == libc::AT_PLATFORM as u64
        || key == libc::AT_BASE_PLATFORM as u64
}

#[cfg(target_arch = "x86_64")]
fn decode_hwcap(key: u64, value: u64) -> Option<String> {
    // AT_HWCAP on x86_64: CPUID leaf 1 EDX register bits
    const HWCAP_NAMES: &[(u32, &str)] = &[
        (0, "FPU"),
        (1, "VME"),
        (2, "DE"),
        (3, "PSE"),
        (4, "TSC"),
        (5, "MSR"),
        (6, "PAE"),
        (7, "MCE"),
        (8, "CX8"),
        (9, "APIC"),
        (11, "SEP"),
        (12, "MTRR"),
        (13, "PGE"),
        (14, "MCA"),
        (15, "CMOV"),
        (16, "PAT"),
        (17, "PSE36"),
        (18, "PSN"),
        (19, "CLFSH"),
        (21, "DS"),
        (22, "ACPI"),
        (23, "MMX"),
        (24, "FXSR"),
        (25, "SSE"),
        (26, "SSE2"),
        (27, "SS"),
        (28, "HTT"),
        (29, "TM"),
        (31, "PBE"),
    ];

    // AT_HWCAP2 on x86_64: kernel-defined bits from asm/hwcap2.h
    const HWCAP2_NAMES: &[(u32, &str)] = &[(0, "RING3MWAIT"), (1, "FSGSBASE")];

    let table = if key == libc::AT_HWCAP as u64 {
        HWCAP_NAMES
    } else if key == libc::AT_HWCAP2 as u64 {
        HWCAP2_NAMES
    } else {
        return None;
    };

    let names: Vec<&str> = table
        .iter()
        .filter(|(bit, _)| value & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();

    if names.is_empty() {
        None
    } else {
        Some(names.join(" | "))
    }
}

#[cfg(target_arch = "aarch64")]
fn decode_hwcap(key: u64, value: u64) -> Option<String> {
    // AT_HWCAP on aarch64: bits from arch/arm64/include/uapi/asm/hwcap.h
    const HWCAP_NAMES: &[(u32, &str)] = &[
        (0, "FP"),
        (1, "ASIMD"),
        (2, "EVTSTRM"),
        (3, "AES"),
        (4, "PMULL"),
        (5, "SHA1"),
        (6, "SHA2"),
        (7, "CRC32"),
        (8, "ATOMICS"),
        (9, "FPHP"),
        (10, "ASIMDHP"),
        (11, "CPUID"),
        (12, "ASIMDRDM"),
        (13, "JSCVT"),
        (14, "FCMA"),
        (15, "LRCPC"),
        (16, "DCPOP"),
        (17, "SHA3"),
        (18, "SM3"),
        (19, "SM4"),
        (20, "ASIMDDP"),
        (21, "SHA512"),
        (22, "SVE"),
        (23, "ASIMDFHM"),
        (24, "DIT"),
        (25, "USCAT"),
        (26, "ILRCPC"),
        (27, "FLAGM"),
        (28, "SSBS"),
        (29, "SB"),
        (30, "PACA"),
        (31, "PACG"),
    ];

    // AT_HWCAP2 on aarch64: bits from arch/arm64/include/uapi/asm/hwcap.h
    const HWCAP2_NAMES: &[(u32, &str)] = &[
        (0, "DCPODP"),
        (1, "SVE2"),
        (2, "SVEAES"),
        (3, "SVEPMULL"),
        (4, "SVEBITPERM"),
        (5, "SVESHA3"),
        (6, "SVESM4"),
        (7, "FLAGM2"),
        (8, "FRINT"),
        (9, "SVEI8MM"),
        (10, "SVEF32MM"),
        (11, "SVEF64MM"),
        (12, "SVEBF16"),
        (13, "I8MM"),
        (14, "BF16"),
        (15, "DGH"),
        (16, "RNG"),
        (17, "BTI"),
        (18, "MTE"),
        (19, "ECV"),
        (20, "AFP"),
        (21, "RPRES"),
        (22, "MTE3"),
        (23, "SME"),
        (24, "SME_I16I64"),
        (25, "SME_F64F64"),
        (26, "SME_I8I32"),
        (27, "SME_F16F32"),
        (28, "SME_B16F32"),
        (29, "SME_F32F32"),
        (30, "SME_FA64"),
        (31, "WFXT"),
        (32, "EBF16"),
        (33, "SVE_EBF16"),
        (34, "CSSC"),
        (35, "RPRFM"),
        (36, "SVE2P1"),
        (37, "SME2"),
        (38, "SME2P1"),
        (39, "SME_I16I32"),
        (40, "SME_BI32I32"),
        (41, "SME_B16B16"),
        (42, "SME_F16F16"),
        (43, "MOPS"),
        (44, "HBC"),
    ];

    let table = if key == libc::AT_HWCAP as u64 {
        HWCAP_NAMES
    } else if key == libc::AT_HWCAP2 as u64 {
        HWCAP2_NAMES
    } else {
        return None;
    };

    let names: Vec<&str> = table
        .iter()
        .filter(|(bit, _)| value & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();

    if names.is_empty() {
        None
    } else {
        Some(names.join(" | "))
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn decode_hwcap(_key: u64, _value: u64) -> Option<String> {
    None
}

fn read_proc_string(pid: u64, addr: u64) -> Option<String> {
    let mut file = File::open(format!("/proc/{}/mem", pid)).ok()?;
    file.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = vec![0u8; 256];
    let n = file.read(&mut buf).ok()?;
    buf.truncate(n);
    let end = buf.iter().position(|&b| b == 0).unwrap_or(n);
    String::from_utf8(buf[..end].to_vec()).ok()
}

fn print_auxv(pid: u64) {
    if let Some(auxv) = read_auxv(pid) {
        ptools::print_proc_summary(pid);
        for (key, value) in auxv {
            if is_string_auxv_key(key) {
                let s = read_proc_string(pid, value).unwrap_or_default();
                println!("{:<15} 0x{:016x} {}", aux_key_name(key), value, s);
            } else if let Some(flags) = decode_hwcap(key, value) {
                println!("{:<15} 0x{:016x} {}", aux_key_name(key), value, flags);
            } else {
                println!("{:<15} 0x{:016x}", aux_key_name(key), value);
            }
        }
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

    if args.pid.is_empty() {
        eprintln!("pargs: at least one PID required");
        exit(2);
    }
    args
}

fn main() {
    let args = parse_args();

    let want_args = args.args || (!args.env && !args.auxv);

    for &pid in &args.pid {
        if want_args {
            if args.line {
                print_cmdline(pid);
            } else {
                print_args(pid);
            }
        }
        if args.env {
            ptools::print_env(pid);
        }
        if args.auxv {
            print_auxv(pid);
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
