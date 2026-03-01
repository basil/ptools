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

use std::io::Read;
use std::io::{self};

use nix::libc;

// Not yet in the libc crate for Linux (only Android).
const AT_RSEQ_FEATURE_SIZE: u64 = 27;
const AT_RSEQ_ALIGN: u64 = 28;

/// Byte order for parsing multi-byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    pub fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            ByteOrder::Little => u16::from_le_bytes(bytes),
            ByteOrder::Big => u16::from_be_bytes(bytes),
        }
    }

    pub fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            ByteOrder::Little => u32::from_le_bytes(bytes),
            ByteOrder::Big => u32::from_be_bytes(bytes),
        }
    }

    pub fn u64(self, bytes: [u8; 8]) -> u64 {
        match self {
            ByteOrder::Little => u64::from_le_bytes(bytes),
            ByteOrder::Big => u64::from_be_bytes(bytes),
        }
    }
}

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

/// Parsed auxiliary vector with metadata about the originating process.
#[derive(Debug, Clone)]
pub struct Auxv(pub Vec<(AuxvType, u64)>);

impl Auxv {
    /// Parse an auxiliary vector from a reader with explicit platform parameters.
    pub fn from_read(
        mut reader: impl Read,
        word_size: usize,
        byte_order: ByteOrder,
    ) -> io::Result<Self> {
        // A real auxv has ~20-30 entries. 1024 is generous but prevents unbounded growth.
        const MAX_AUXV_ENTRIES: usize = 1024;

        let read_word = |reader: &mut dyn Read| -> io::Result<u64> {
            match word_size {
                4 => {
                    let mut buf = [0u8; 4];
                    reader.read_exact(&mut buf)?;
                    Ok(byte_order.u32(buf) as u64)
                }
                8 => {
                    let mut buf = [0u8; 8];
                    reader.read_exact(&mut buf)?;
                    Ok(byte_order.u64(buf))
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported word size: {word_size}"),
                )),
            }
        };

        let mut entries = Vec::new();
        loop {
            let key = read_word(&mut reader)?;
            let value = read_word(&mut reader)?;
            let typ = AuxvType::from(key);
            if typ == AuxvType::Null {
                break;
            }
            if entries.len() >= MAX_AUXV_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auxv exceeds maximum of 1024 entries without AT_NULL terminator",
                ));
            }
            entries.push((typ, value));
        }
        Ok(Self(entries))
    }
}
