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
use std::io;

use nix::unistd::sysconf;
use nix::unistd::Gid;
use nix::unistd::Group;
use nix::unistd::SysconfVar;
use nix::unistd::Uid;
use nix::unistd::User;

use crate::model::auxv::AuxvType;
use crate::proc::ProcHandle;

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
        AuxvType::Unknown(v) => format!("AT_{v}").into(),
    }
}

pub fn print_env_from(handle: &ProcHandle) -> io::Result<()> {
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
pub fn print_auxv_from(handle: &ProcHandle) -> io::Result<()> {
    let auxv = handle.auxv()?;
    let hex_width = handle.word_size() * 2;
    let page_size = auxv
        .0
        .iter()
        .find(|(typ, _)| *typ == AuxvType::PageSz)
        .map(|(_, value)| *value)
        .or_else(|| {
            sysconf(SysconfVar::PAGE_SIZE)
                .ok()
                .flatten()
                .map(|v| v as u64)
        })
        .unwrap_or(4096);

    print_proc_summary_from(handle);
    for &(typ, value) in &auxv.0 {
        let key = auxv_type_str(&typ);
        if typ.is_string_pointer() {
            if let Some(s) = handle.read_cstring_at(value, page_size) {
                println!("{key:<15} 0x{value:0hex_width$x} {s}");
            } else {
                println!("{key:<15} 0x{value:0hex_width$x}");
            }
        } else if let Some(flags) = decode_hwcap(typ, value) {
            println!(
                "{:<15} 0x{:0width$x} {}",
                key,
                value,
                flags.join(" | "),
                width = hex_width
            );
        } else if typ.is_uid() {
            if let Some(name) = User::from_uid(Uid::from_raw(value as u32))
                .ok()
                .flatten()
                .map(|u| u.name)
            {
                println!("{key:<15} 0x{value:0hex_width$x} {value}({name})");
            } else {
                println!("{key:<15} 0x{value:0hex_width$x}");
            }
        } else if typ.is_gid() {
            if let Some(name) = Group::from_gid(Gid::from_raw(value as u32))
                .ok()
                .flatten()
                .map(|g| g.name)
            {
                println!("{key:<15} 0x{value:0hex_width$x} {value}({name})");
            } else {
                println!("{key:<15} 0x{value:0hex_width$x}");
            }
        } else {
            println!("{key:<15} 0x{value:0hex_width$x}");
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
            let is_zombie = matches!(handle.state(), Ok(crate::proc::ProcState::Zombie));
            match handle.comm() {
                Ok(ref comm) if !comm.is_empty() => {
                    print!("{comm}");
                    if is_zombie {
                        print!(" <defunct>");
                    }
                    println!();
                }
                Ok(_) => println!("<unknown>"),
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                    println!("<exited>");
                }
                Err(_) => println!("<unknown>"),
            }
        }
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            println!("<exited>");
        }
        Err(e) => {
            println!("<error reading cmdline>");
            eprintln!("{e}");
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn decode_hwcap(key: AuxvType, value: u64) -> Option<Vec<&'static str>> {
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

    let table = match key {
        AuxvType::Hwcap => HWCAP_NAMES,
        AuxvType::Hwcap2 => HWCAP2_NAMES,
        _ => return None,
    };

    let names: Vec<&str> = table
        .iter()
        .filter(|(bit, _)| value & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();

    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

#[cfg(target_arch = "aarch64")]
fn decode_hwcap(key: AuxvType, value: u64) -> Option<Vec<&'static str>> {
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

    let table = match key {
        AuxvType::Hwcap => HWCAP_NAMES,
        AuxvType::Hwcap2 => HWCAP2_NAMES,
        _ => return None,
    };

    let names: Vec<&str> = table
        .iter()
        .filter(|(bit, _)| value & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();

    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

#[cfg(target_arch = "s390x")]
fn decode_hwcap(key: AuxvType, value: u64) -> Option<Vec<&'static str>> {
    // AT_HWCAP on s390x: bits from arch/s390/include/asm/elf.h
    const HWCAP_NAMES: &[(u32, &str)] = &[
        (0, "ESAN3"),
        (1, "ZARCH"),
        (2, "STFLE"),
        (3, "MSA"),
        (4, "LDISP"),
        (5, "EIMM"),
        (6, "DFP"),
        (7, "HPAGE"),
        (8, "ETF3EH"),
        (9, "HIGH_GPRS"),
        (10, "TE"),
        (11, "VXRS"),
        (12, "VXRS_BCD"),
        (13, "VXRS_EXT"),
        (14, "GS"),
        (15, "VXRS_EXT2"),
        (16, "VXRS_PDE"),
        (17, "SORT"),
        (18, "DFLT"),
        (19, "VXRS_PDE2"),
        (20, "NNPA"),
        (21, "PCI_MIO"),
        (22, "SIE"),
    ];

    // s390x does not currently define AT_HWCAP2 bits
    let table = match key {
        AuxvType::Hwcap => HWCAP_NAMES,
        _ => return None,
    };

    let names: Vec<&str> = table
        .iter()
        .filter(|(bit, _)| value & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();

    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

#[cfg(target_arch = "powerpc64")]
fn decode_hwcap(key: AuxvType, value: u64) -> Option<Vec<&'static str>> {
    // AT_HWCAP on powerpc64: PPC_FEATURE_* from arch/powerpc/include/uapi/asm/cputable.h
    const HWCAP_NAMES: &[(u32, &str)] = &[
        (0, "PPC_LE"),
        (1, "TRUE_LE"),
        (6, "PSERIES_PERFMON_COMPAT"),
        (7, "VSX"),
        (8, "ARCH_2_06"),
        (9, "POWER6_EXT"),
        (10, "DFP"),
        (11, "PA6T"),
        (12, "ARCH_2_05"),
        (13, "ICACHE_SNOOP"),
        (14, "SMT"),
        (15, "BOOKE"),
        (16, "CELL"),
        (17, "POWER5+"),
        (18, "POWER5"),
        (19, "POWER4"),
        (20, "NO_TB"),
        (21, "EFP_DOUBLE"),
        (22, "EFP_SINGLE"),
        (23, "SPE"),
        (24, "UNIFIED_CACHE"),
        (25, "4xxMAC"),
        (26, "MMU"),
        (27, "FPU"),
        (28, "ALTIVEC"),
        (29, "601_INSTR"),
        (30, "64"),
        (31, "32"),
    ];

    // AT_HWCAP2 on powerpc64: PPC_FEATURE2_* from arch/powerpc/include/uapi/asm/cputable.h
    const HWCAP2_NAMES: &[(u32, &str)] = &[
        (17, "MMA"),
        (18, "ARCH_3_1"),
        (19, "HTM_NO_SUSPEND"),
        (20, "SCV"),
        (21, "DARN"),
        (22, "IEEE128"),
        (23, "ARCH_3_00"),
        (24, "HTM_NOSC"),
        (25, "VEC_CRYPTO"),
        (26, "TAR"),
        (27, "ISEL"),
        (28, "EBB"),
        (29, "DSCR"),
        (30, "HTM"),
        (31, "ARCH_2_07"),
    ];

    let table = match key {
        AuxvType::Hwcap => HWCAP_NAMES,
        AuxvType::Hwcap2 => HWCAP2_NAMES,
        _ => return None,
    };

    let names: Vec<&str> = table
        .iter()
        .filter(|(bit, _)| value & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();

    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "s390x",
    target_arch = "powerpc64"
)))]
fn decode_hwcap(_key: AuxvType, _value: u64) -> Option<Vec<&'static str>> {
    None
}
