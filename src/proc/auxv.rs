use std::collections::HashSet;
use std::fmt;
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
}

impl fmt::Display for AuxvType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            Self::Null => "AT_NULL",
            Self::Ignore => "AT_IGNORE",
            Self::ExecFd => "AT_EXECFD",
            Self::Phdr => "AT_PHDR",
            Self::PhEnt => "AT_PHENT",
            Self::PhNum => "AT_PHNUM",
            Self::PageSz => "AT_PAGESZ",
            Self::Base => "AT_BASE",
            Self::Flags => "AT_FLAGS",
            Self::Entry => "AT_ENTRY",
            Self::NotElf => "AT_NOTELF",
            Self::Uid => "AT_UID",
            Self::Euid => "AT_EUID",
            Self::Gid => "AT_GID",
            Self::Egid => "AT_EGID",
            Self::ClkTck => "AT_CLKTCK",
            Self::Platform => "AT_PLATFORM",
            Self::Hwcap => "AT_HWCAP",
            Self::Hwcap2 => "AT_HWCAP2",
            Self::Secure => "AT_SECURE",
            Self::BasePlatform => "AT_BASE_PLATFORM",
            Self::Random => "AT_RANDOM",
            Self::ExecFn => "AT_EXECFN",
            Self::SysinfoEhdr => "AT_SYSINFO_EHDR",
            Self::MinSigStkSz => "AT_MINSIGSTKSZ",
            Self::RseqFeatureSize => "AT_RSEQ_FEATURE_SIZE",
            Self::RseqAlign => "AT_RSEQ_ALIGN",
            Self::Unknown(v) => return write!(f, "AT_{}", v),
        };
        f.write_str(name)
    }
}

/// A single entry from the auxiliary vector.
pub struct AuxvEntry {
    pub key: AuxvType,
    pub value: u64,
}

pub fn parse_word(chunk: &[u8], word_size: usize) -> Result<u64, super::Error> {
    match word_size {
        4 => {
            let raw: [u8; 4] = chunk.try_into().map_err(|_| {
                super::Error::Parse(format!("invalid 32-bit word length {}", chunk.len()))
            })?;
            Ok(u32::from_ne_bytes(raw) as u64)
        }
        8 => {
            let raw: [u8; 8] = chunk.try_into().map_err(|_| {
                super::Error::Parse(format!("invalid 64-bit word length {}", chunk.len()))
            })?;
            Ok(u64::from_ne_bytes(raw))
        }
        n => Err(super::Error::Parse(format!(
            "unsupported auxv word size {}",
            n
        ))),
    }
}

pub fn parse_auxv_records(bytes: &[u8], word_size: usize) -> Result<Vec<AuxvEntry>, super::Error> {
    let record_size = word_size
        .checked_mul(2)
        .ok_or_else(|| super::Error::Parse("auxv record size overflow".to_string()))?;
    if record_size == 0 || !bytes.len().is_multiple_of(record_size) {
        return Err(super::Error::Parse(format!(
            "unexpected auxv size {}",
            bytes.len()
        )));
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
        return Err(super::Error::Parse(
            "missing AT_NULL terminator".to_string(),
        ));
    }

    Ok(result)
}

pub fn elf_word_size_from_path(exe_path: &Path) -> Option<usize> {
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
pub fn read_auxv(handle: &ProcHandle) -> Result<Vec<AuxvEntry>, super::Error> {
    let bytes = handle.auxv_bytes()?;

    if bytes.is_empty() {
        return Err(super::Error::Parse(
            "error reading auxv: empty file".to_string(),
        ));
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

        if let Ok(result) = parse_auxv_records(&bytes, word_size) {
            return Ok(result);
        }
    }

    Err(super::Error::Parse(format!(
        "error parsing auxv: unexpected auxv format ({} bytes)",
        bytes.len()
    )))
}

#[cfg(target_arch = "x86_64")]
pub fn decode_hwcap(key: AuxvType, value: u64) -> Option<Vec<&'static str>> {
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
pub fn decode_hwcap(key: AuxvType, value: u64) -> Option<Vec<&'static str>> {
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

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
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
