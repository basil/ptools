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

//! Shared formatting helpers for process data.
//!
//! This module formats environment variables, auxiliary vectors, and
//! process/command summaries via [`ProcHandle`].  Individual binaries
//! (e.g. `pfiles`, `pcred`, `psig`, `ptree`) contain their own
//! specialised formatting.
//!
//! **Contract:**
//! - This module must **not** depend on [`crate::source`] or know anything
//!   about how raw procfs / coredump data is obtained.  All data arrives
//!   pre-parsed through the proc-handle API.

use std::borrow::Cow;

use nix::unistd::{sysconf, Gid, Group, SysconfVar, Uid, User};

use crate::proc::auxv::{decode_hwcap, AuxvType};
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
    let hex_width = auxv.word_size * 2;
    let page_size = auxv
        .entries
        .iter()
        .find(|e| e.key == AuxvType::PageSz)
        .map(|e| e.value)
        .or_else(|| {
            sysconf(SysconfVar::PAGE_SIZE)
                .ok()
                .flatten()
                .map(|v| v as u64)
        })
        .unwrap_or(4096);

    print_proc_summary_from(handle);
    for entry in &auxv.entries {
        let key = auxv_type_str(&entry.key);
        if entry.key.is_string_pointer() {
            if let Some(s) = handle.read_cstring_at(entry.value, page_size) {
                println!(
                    "{:<15} 0x{:0width$x} {}",
                    key,
                    entry.value,
                    s,
                    width = hex_width
                );
            } else {
                println!("{:<15} 0x{:0width$x}", key, entry.value, width = hex_width);
            }
        } else if let Some(flags) = decode_hwcap(entry.key, entry.value) {
            println!(
                "{:<15} 0x{:0width$x} {}",
                key,
                entry.value,
                flags.join(" | "),
                width = hex_width
            );
        } else if entry.key.is_uid() {
            if let Some(name) = User::from_uid(Uid::from_raw(entry.value as u32))
                .ok()
                .flatten()
                .map(|u| u.name)
            {
                println!(
                    "{:<15} 0x{:0width$x} {}({})",
                    key,
                    entry.value,
                    entry.value,
                    name,
                    width = hex_width
                );
            } else {
                println!("{:<15} 0x{:0width$x}", key, entry.value, width = hex_width);
            }
        } else if entry.key.is_gid() {
            if let Some(name) = Group::from_gid(Gid::from_raw(entry.value as u32))
                .ok()
                .flatten()
                .map(|g| g.name)
            {
                println!(
                    "{:<15} 0x{:0width$x} {}({})",
                    key,
                    entry.value,
                    entry.value,
                    name,
                    width = hex_width
                );
            } else {
                println!("{:<15} 0x{:0width$x}", key, entry.value, width = hex_width);
            }
        } else {
            println!("{:<15} 0x{:0width$x}", key, entry.value, width = hex_width);
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
