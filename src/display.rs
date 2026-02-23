//! Presentation layer: human-readable formatting of process data.
//!
//! This module is the sole place where process information is formatted for
//! output.  It consumes the [`crate::proc`] module (specifically
//! [`ProcHandle`] and its associated types) and turns structured data into
//! text written to stdout.
//!
//! **Contract:**
//! - This module must **not** depend on [`crate::source`] or know anything
//!   about how raw procfs / coredump data is obtained.  All data arrives
//!   pre-parsed through the proc-handle API.
//! - All user-visible formatting and presentation decisions belong here.

use std::borrow::Cow;

use crate::proc::auxv::{decode_hwcap, AuxvType};
use crate::proc::cred::{resolve_gid, resolve_uid};
use crate::proc::{Error, ProcHandle};

fn auxv_type_str(key: &AuxvType) -> Cow<'static, str> {
    match key {
        AuxvType::Null => "AT_NULL".into(),
        AuxvType::Ignore => "AT_IGNORE".into(),
        AuxvType::ExecFd => "AT_EXECFD".into(),
        AuxvType::Phdr => "AT_PHDR".into(),
        AuxvType::PhEnt => "AT_PHENT".into(),
        AuxvType::PhNum => "AT_PHNUM".into(),
        AuxvType::PageSz => "AT_PAGESZ".into(),
        AuxvType::Base => "AT_BASE".into(),
        AuxvType::Flags => "AT_FLAGS".into(),
        AuxvType::Entry => "AT_ENTRY".into(),
        AuxvType::NotElf => "AT_NOTELF".into(),
        AuxvType::Uid => "AT_UID".into(),
        AuxvType::Euid => "AT_EUID".into(),
        AuxvType::Gid => "AT_GID".into(),
        AuxvType::Egid => "AT_EGID".into(),
        AuxvType::ClkTck => "AT_CLKTCK".into(),
        AuxvType::Platform => "AT_PLATFORM".into(),
        AuxvType::Hwcap => "AT_HWCAP".into(),
        AuxvType::Hwcap2 => "AT_HWCAP2".into(),
        AuxvType::Secure => "AT_SECURE".into(),
        AuxvType::BasePlatform => "AT_BASE_PLATFORM".into(),
        AuxvType::Random => "AT_RANDOM".into(),
        AuxvType::ExecFn => "AT_EXECFN".into(),
        AuxvType::SysinfoEhdr => "AT_SYSINFO_EHDR".into(),
        AuxvType::MinSigStkSz => "AT_MINSIGSTKSZ".into(),
        AuxvType::RseqFeatureSize => "AT_RSEQ_FEATURE_SIZE".into(),
        AuxvType::RseqAlign => "AT_RSEQ_ALIGN".into(),
        AuxvType::Unknown(v) => format!("AT_{}", v).into(),
    }
}

pub fn print_env_from(handle: &ProcHandle) -> Result<(), Error> {
    // This contains the environ as it was when the proc was started. To get the current
    // environment, we need to inspect its memory to find out how it has changed. POSIX defines a
    // char **__environ symbol that we will need to find. Unfortunately, inspecting the memory of
    // another process is not typically permitted, even if the process is owned by the same user. See
    // /etc/sysctl.d/10-ptrace.conf for details.
    //
    // TODO Long term, we might want to print the current environment if we can, and print a warning
    // + the contents of /proc/[pid]/environ if we can't
    let vars = handle.environ()?;

    print_proc_summary_from(handle);

    for (i, (key, value)) in vars.iter().enumerate() {
        println!(
            "envp[{}]: {}={}",
            i,
            key.to_string_lossy(),
            value.to_string_lossy()
        );
    }
    Ok(())
}

#[allow(clippy::unnecessary_cast)]
pub fn print_auxv_from(handle: &ProcHandle) -> Result<(), Error> {
    let auxv = handle.auxv()?;

    print_proc_summary_from(handle);
    for entry in &auxv {
        if entry.key == AuxvType::ExecFn {
            let s = handle
                .exe()
                .ok()
                .and_then(|p| p.to_str().map(str::to_string))
                .unwrap_or_default();
            let key = auxv_type_str(&entry.key);
            println!("{:<15} 0x{:016x} {}", key, entry.value, s);
        } else if let Some(flags) = decode_hwcap(entry.key, entry.value) {
            let key = auxv_type_str(&entry.key);
            println!("{:<15} 0x{:016x} {}", key, entry.value, flags.join(" | "));
        } else if entry.key.is_uid() {
            let key = auxv_type_str(&entry.key);
            if let Some(name) = resolve_uid(entry.value as u32) {
                println!(
                    "{:<15} 0x{:016x} {}({})",
                    key, entry.value, entry.value, name
                );
            } else {
                println!("{:<15} 0x{:016x}", key, entry.value);
            }
        } else if entry.key.is_gid() {
            let key = auxv_type_str(&entry.key);
            if let Some(name) = resolve_gid(entry.value as u32) {
                println!(
                    "{:<15} 0x{:016x} {}({})",
                    key, entry.value, entry.value, name
                );
            } else {
                println!("{:<15} 0x{:016x}", key, entry.value);
            }
        } else {
            let key = auxv_type_str(&entry.key);
            println!("{:<15} 0x{:016x}", key, entry.value);
        }
    }
    Ok(())
}

pub fn print_proc_summary_from(handle: &ProcHandle) {
    print!("{}:\t", handle.pid());
    print_cmd_summary_from(handle);
}

pub fn print_cmd_summary_from(handle: &ProcHandle) {
    match handle.argv() {
        Ok(args) if !args.is_empty() => {
            let summary: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
            println!("{}", summary.join(" "));
        }
        Ok(_) => {
            // Empty cmdline -- fall back to comm name.
            let is_zombie = matches!(handle.state(), Ok(crate::ProcessState::Zombie));
            match handle.comm() {
                Ok(ref comm) if !comm.is_empty() => {
                    print!("{}", comm);
                    if is_zombie {
                        print!(" <defunct>");
                    }
                    println!();
                }
                Ok(_) => println!("<unknown>"),
                Err(ref e) if e.is_not_found() => {
                    println!("<exited>");
                }
                Err(_) => println!("<unknown>"),
            }
        }
        Err(ref e) if e.is_not_found() => {
            println!("<exited>");
        }
        Err(e) => {
            println!("<error reading cmdline>");
            eprintln!("{}", e);
        }
    }
}
