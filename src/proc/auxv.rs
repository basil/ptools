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

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::mem::size_of;
use std::path::Path;

use nix::libc;

use super::ProcHandle;

// Not yet in the libc crate for Linux (only Android).
const AT_RSEQ_FEATURE_SIZE: u64 = 27;
const AT_RSEQ_ALIGN: u64 = 28;

/// An auxiliary vector entry type (`AT_*` constant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxvType {
    Null,
    Ignore,
    ExecFd,
    Phdr,
    PhEnt,
    PhNum,
    PageSz,
    Base,
    Flags,
    Entry,
    NotElf,
    Uid,
    Euid,
    Gid,
    Egid,
    ClkTck,
    Platform,
    Hwcap,
    Hwcap2,
    Secure,
    BasePlatform,
    Random,
    ExecFn,
    SysinfoEhdr,
    MinSigStkSz,
    RseqFeatureSize,
    RseqAlign,
    Unknown(u64),
}

#[allow(clippy::unnecessary_cast)]
impl From<u64> for AuxvType {
    fn from(v: u64) -> Self {
        match v {
            x if x == libc::AT_NULL as u64 => Self::Null,
            x if x == libc::AT_IGNORE as u64 => Self::Ignore,
            x if x == libc::AT_EXECFD as u64 => Self::ExecFd,
            x if x == libc::AT_PHDR as u64 => Self::Phdr,
            x if x == libc::AT_PHENT as u64 => Self::PhEnt,
            x if x == libc::AT_PHNUM as u64 => Self::PhNum,
            x if x == libc::AT_PAGESZ as u64 => Self::PageSz,
            x if x == libc::AT_BASE as u64 => Self::Base,
            x if x == libc::AT_FLAGS as u64 => Self::Flags,
            x if x == libc::AT_ENTRY as u64 => Self::Entry,
            x if x == libc::AT_NOTELF as u64 => Self::NotElf,
            x if x == libc::AT_UID as u64 => Self::Uid,
            x if x == libc::AT_EUID as u64 => Self::Euid,
            x if x == libc::AT_GID as u64 => Self::Gid,
            x if x == libc::AT_EGID as u64 => Self::Egid,
            x if x == libc::AT_CLKTCK as u64 => Self::ClkTck,
            x if x == libc::AT_PLATFORM as u64 => Self::Platform,
            x if x == libc::AT_HWCAP as u64 => Self::Hwcap,
            x if x == libc::AT_HWCAP2 as u64 => Self::Hwcap2,
            x if x == libc::AT_SECURE as u64 => Self::Secure,
            x if x == libc::AT_BASE_PLATFORM as u64 => Self::BasePlatform,
            x if x == libc::AT_RANDOM as u64 => Self::Random,
            x if x == libc::AT_EXECFN as u64 => Self::ExecFn,
            x if x == libc::AT_SYSINFO_EHDR as u64 => Self::SysinfoEhdr,
            x if x == libc::AT_MINSIGSTKSZ as u64 => Self::MinSigStkSz,
            x if x == AT_RSEQ_FEATURE_SIZE => Self::RseqFeatureSize,
            x if x == AT_RSEQ_ALIGN => Self::RseqAlign,
            other => Self::Unknown(other),
        }
    }
}

impl AuxvType {
    pub fn is_uid(self) -> bool {
        matches!(self, Self::Uid | Self::Euid)
    }

    pub fn is_gid(self) -> bool {
        matches!(self, Self::Gid | Self::Egid)
    }

    pub fn is_string_pointer(self) -> bool {
        matches!(self, Self::ExecFn | Self::Platform | Self::BasePlatform)
    }
}

/// A single entry from the auxiliary vector.
pub struct AuxvEntry {
    pub key: AuxvType,
    pub value: u64,
}

/// Parsed auxiliary vector with metadata about the originating process.
pub struct AuxvData {
    pub entries: Vec<AuxvEntry>,
    /// Word size of the process (4 for 32-bit, 8 for 64-bit).
    pub word_size: usize,
}

fn parse_word(chunk: &[u8], word_size: usize) -> Result<u64, super::Error> {
    match word_size {
        4 => {
            let raw: [u8; 4] = chunk.try_into().map_err(|_| {
                super::Error::parse(
                    "auxv",
                    &format!("invalid 32-bit word length {}", chunk.len()),
                )
            })?;
            Ok(u32::from_ne_bytes(raw) as u64)
        }
        8 => {
            let raw: [u8; 8] = chunk.try_into().map_err(|_| {
                super::Error::parse(
                    "auxv",
                    &format!("invalid 64-bit word length {}", chunk.len()),
                )
            })?;
            Ok(u64::from_ne_bytes(raw))
        }
        n => Err(super::Error::parse(
            "auxv",
            &format!("unsupported word size {}", n),
        )),
    }
}

fn parse_auxv_records(bytes: &[u8], word_size: usize) -> Result<Vec<AuxvEntry>, super::Error> {
    let record_size = word_size
        .checked_mul(2)
        .ok_or_else(|| super::Error::parse("auxv", "record size overflow"))?;
    if record_size == 0 || !bytes.len().is_multiple_of(record_size) {
        return Err(super::Error::parse(
            "auxv",
            &format!("unexpected size {}", bytes.len()),
        ));
    }

    let mut result = Vec::new();
    let mut saw_terminator = false;
    for chunk in bytes.chunks_exact(record_size) {
        let raw_key = parse_word(&chunk[..word_size], word_size)?;
        let value = parse_word(&chunk[word_size..record_size], word_size)?;
        if raw_key == 0 {
            saw_terminator = true;
            break;
        }
        result.push(AuxvEntry {
            key: AuxvType::from(raw_key),
            value,
        });
    }

    if !saw_terminator {
        return Err(super::Error::parse("auxv", "missing AT_NULL terminator"));
    }

    Ok(result)
}

fn elf_word_size_from_path(exe_path: &Path) -> Option<usize> {
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

/// Read and parse the auxiliary vector from a process handle.
pub(crate) fn read_auxv(handle: &ProcHandle) -> Result<AuxvData, super::Error> {
    let bytes = handle.auxv_bytes()?;

    if bytes.is_empty() {
        return Err(super::Error::parse("auxv", "empty file"));
    }

    let native_word_size = size_of::<usize>();
    let mut candidate_word_sizes = Vec::new();
    if let Ok(exe_path) = handle.exe() {
        if let Some(ws) = elf_word_size_from_path(&exe_path) {
            candidate_word_sizes.push(ws);
        }
    }
    candidate_word_sizes.push(native_word_size);
    candidate_word_sizes.push(4);
    candidate_word_sizes.push(8);

    let mut seen = HashSet::new();
    for word_size in candidate_word_sizes {
        if !seen.insert(word_size) {
            continue;
        }

        if let Ok(entries) = parse_auxv_records(&bytes, word_size) {
            return Ok(AuxvData { entries, word_size });
        }
    }

    Err(super::Error::parse(
        "auxv",
        &format!("unexpected format ({} bytes)", bytes.len()),
    ))
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn decode_hwcap(key: AuxvType, value: u64) -> Option<Vec<&'static str>> {
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
pub(crate) fn decode_hwcap(key: AuxvType, value: u64) -> Option<Vec<&'static str>> {
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
pub(crate) fn decode_hwcap(key: AuxvType, value: u64) -> Option<Vec<&'static str>> {
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
pub(crate) fn decode_hwcap(key: AuxvType, value: u64) -> Option<Vec<&'static str>> {
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
pub fn decode_hwcap(_key: AuxvType, _value: u64) -> Option<Vec<&'static str>> {
    None
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
        assert_eq!(auxv.len(), 1);
        assert_eq!(auxv[0].key, AuxvType::PageSz);
        assert_eq!(auxv[0].value, 4096);
    }

    #[test]
    fn parse_auxv_records_32_bit() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(6u32).to_ne_bytes()); // AT_PAGESZ
        bytes.extend_from_slice(&(4096u32).to_ne_bytes());
        bytes.extend_from_slice(&(0u32).to_ne_bytes()); // AT_NULL
        bytes.extend_from_slice(&(0u32).to_ne_bytes());

        let auxv = parse_auxv_records(&bytes, 4).expect("parse 32-bit auxv");
        assert_eq!(auxv.len(), 1);
        assert_eq!(auxv[0].key, AuxvType::PageSz);
        assert_eq!(auxv[0].value, 4096);
    }

    #[test]
    fn parse_auxv_records_rejects_missing_terminator() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(6u64).to_ne_bytes());
        bytes.extend_from_slice(&(4096u64).to_ne_bytes());

        assert!(parse_auxv_records(&bytes, 8).is_err());
    }
}
