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

//! ELF core dump file handling.
//!
//! Owns the ELF handle and (optionally decompressed) file descriptor for a
//! core dump.  Provides memory reading via PT_LOAD segments.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::{self};
use std::os::raw::c_int;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use nix::libc;

use crate::model::auxv::ByteOrder;

/// RAII wrapper for `*mut Elf`.
struct OwnedElf(*mut crate::dw_sys::Elf);

impl Drop for OwnedElf {
    fn drop(&mut self) {
        unsafe {
            crate::dw_sys::elf_end(self.0);
        }
    }
}

/// An opened ELF core dump file.
///
/// Owns the file descriptor and ELF handle, transparently decompressing
/// zstd-compressed cores into a memfd.
pub(super) struct CoreElf {
    elf: OwnedElf,
    _fd: File, // kept alive for the duration of the ELF handle
}

/// Zstd magic bytes.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

impl CoreElf {
    /// Open a core dump file, decompressing zstd if needed.
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let mut fd = File::open(path)?;
        let mut magic = [0u8; 4];
        let is_zst = fd.read_exact(&mut magic).is_ok() && magic == ZSTD_MAGIC;
        fd.seek(SeekFrom::Start(0))?;

        let fd = if is_zst {
            let mut decoder = zstd::Decoder::new(fd)?;
            let name = c"pstack-core";
            let memfd = nix::sys::memfd::memfd_create(name, nix::sys::memfd::MFdFlags::empty())
                .map_err(io::Error::from)?;
            let mut memfile = File::from(memfd);
            io::copy(&mut decoder, &mut memfile)?;
            memfile.seek(SeekFrom::Start(0))?;
            memfile
        } else {
            fd
        };

        Self::from_fd(fd)
    }

    /// Create from an already-opened file descriptor (e.g., a memfd with
    /// decompressed core data).  Validates ELF structure and ET_CORE type.
    pub(super) fn from_fd(fd: File) -> io::Result<Self> {
        unsafe {
            crate::dw_sys::elf_version(1); // EV_CURRENT
        }

        let elf_ptr = unsafe {
            crate::dw_sys::elf_begin(
                fd.as_raw_fd(),
                crate::dw_sys::ELF_C_READ_MMAP,
                std::ptr::null_mut(),
            )
        };
        if elf_ptr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "failed to open ELF core file",
            ));
        }

        // Verify this is actually an ELF file (not an archive or raw data).
        let kind = unsafe { crate::dw_sys::elf_kind(elf_ptr) };
        if kind != crate::dw_sys::ELF_K_ELF {
            unsafe { crate::dw_sys::elf_end(elf_ptr) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not an ELF file",
            ));
        }

        // Verify this is a core dump (ET_CORE), not a regular executable or shared object.
        let mut ehdr = unsafe { std::mem::zeroed::<crate::dw_sys::GElf_Ehdr>() };
        let ret = unsafe { crate::dw_sys::gelf_getehdr(elf_ptr, &mut ehdr) };
        if ret.is_null() || ehdr.e_type != libc::ET_CORE {
            unsafe { crate::dw_sys::elf_end(elf_ptr) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ELF type is not ET_CORE",
            ));
        }

        Ok(CoreElf {
            elf: OwnedElf(elf_ptr),
            _fd: fd,
        })
    }

    /// Return the raw ELF pointer for use with Dwfl.
    pub(super) fn as_elf_ptr(&self) -> *mut crate::dw_sys::Elf {
        self.elf.0
    }

    /// Read memory from the core file's PT_LOAD segments.
    pub(super) fn read_memory(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let mut phnum: libc::size_t = 0;
            if crate::dw_sys::elf_getphdrnum(self.elf.0, &mut phnum) != 0 {
                return Err(io::Error::other("failed to get ELF program header count"));
            }
            for i in 0..phnum as c_int {
                let mut phdr = std::mem::zeroed::<crate::dw_sys::GElf_Phdr>();
                if crate::dw_sys::gelf_getphdr(self.elf.0, i, &mut phdr).is_null() {
                    continue;
                }
                if phdr.p_type != libc::PT_LOAD {
                    continue;
                }
                let seg_end = match phdr.p_vaddr.checked_add(phdr.p_filesz) {
                    Some(e) => e,
                    None => {
                        eprintln!(
                            "core: arithmetic overflow computing PT_LOAD segment {i} end \
                             (p_vaddr {:#x}, p_filesz {:#x})",
                            phdr.p_vaddr, phdr.p_filesz,
                        );
                        continue;
                    }
                };
                if addr >= phdr.p_vaddr && addr < seg_end {
                    let available = (seg_end - addr) as usize;
                    let to_read = buf.len().min(available);
                    let Some(offset) = (addr - phdr.p_vaddr).checked_add(phdr.p_offset) else {
                        eprintln!(
                            "core: arithmetic overflow computing PT_LOAD segment {i} offset \
                             (addr {addr:#x}, p_vaddr {:#x}, p_offset {:#x})",
                            phdr.p_vaddr, phdr.p_offset,
                        );
                        continue;
                    };
                    let offset = offset as i64;
                    let data = crate::dw_sys::elf_getdata_rawchunk(
                        self.elf.0,
                        offset,
                        to_read,
                        crate::dw_sys::ELF_T_BYTE,
                    );
                    if data.is_null() {
                        return Err(io::Error::other(format!(
                            "failed to read core data at offset {offset:#x}"
                        )));
                    }
                    let d = &*data;
                    if d.d_buf.is_null() || d.d_size < to_read {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "core data at offset {offset:#x} too small \
                                 (got {}, need {to_read})",
                                d.d_size,
                            ),
                        ));
                    }
                    std::ptr::copy_nonoverlapping(d.d_buf.cast::<u8>(), buf.as_mut_ptr(), to_read);
                    return Ok(to_read);
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("address {addr:#x} not in any PT_LOAD segment"),
        ))
    }
}

// ---------------------------------------------------------------------------
// NT_PRSTATUS parsing
// ---------------------------------------------------------------------------

/// Parsed ELF64 NT_PRSTATUS note.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(super) struct Prstatus {
    pub pr_cursig: u16,
    pub pr_sigpend: u64,
    pub pr_sighold: u64,
    pub pr_pid: u32,
    pub pr_ppid: u32,
    pub pr_pgrp: u32,
    pub pr_sid: u32,
    pub pr_utime_sec: u64,
    pub pr_utime_usec: u64,
    pub pr_stime_sec: u64,
    pub pr_stime_usec: u64,
    pub pr_cutime_sec: u64,
    pub pr_cutime_usec: u64,
    pub pr_cstime_sec: u64,
    pub pr_cstime_usec: u64,
    pub pr_reg: Vec<u8>,
}

/// Parsed ELF64 NT_PRPSINFO note.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(super) struct Prpsinfo {
    pub pr_sname: char,
    pub pr_nice: i8,
    pub pr_uid: u32,
    pub pr_gid: u32,
    pub pr_pid: u32,
    pub pr_ppid: u32,
    pub pr_pgrp: u32,
    pub pr_sid: u32,
    pub pr_fname: String,
    pub pr_psargs: String,
}

/// ELF64 prstatus layout offsets (from <sys/procfs.h> / <linux/elfcore.h>):
///
/// ```text
///  0: si_signo  (i32)
///  4: si_code   (i32)
///  8: si_errno  (i32)
/// 12: pr_cursig (u16)
/// 14: (2 bytes padding)
/// 16: pr_sigpend (u64)
/// 24: pr_sighold (u64)
/// 32: pr_pid     (u32)
/// 36: pr_ppid    (u32)
/// 40: pr_pgrp    (u32)
/// 44: pr_sid     (u32)
/// 48: pr_utime   (timeval: u64 sec + u64 usec)
/// 64: pr_stime   (timeval: u64 sec + u64 usec)
/// 80: pr_cutime  (timeval)
/// 96: pr_cstime  (timeval)
/// ```
fn parse_prstatus64(desc: &[u8], endian: ByteOrder) -> Option<Prstatus> {
    if desc.len() < 112 {
        return None;
    }
    let rd16 = |off: usize| endian.u16(desc[off..][..2].try_into().unwrap());
    let rd32 = |off: usize| endian.u32(desc[off..][..4].try_into().unwrap());
    let rd64 = |off: usize| endian.u64(desc[off..][..8].try_into().unwrap());

    Some(Prstatus {
        pr_cursig: rd16(12),
        pr_sigpend: rd64(16),
        pr_sighold: rd64(24),
        pr_pid: rd32(32),
        pr_ppid: rd32(36),
        pr_pgrp: rd32(40),
        pr_sid: rd32(44),
        pr_utime_sec: rd64(48),
        pr_utime_usec: rd64(56),
        pr_stime_sec: rd64(64),
        pr_stime_usec: rd64(72),
        pr_cutime_sec: rd64(80),
        pr_cutime_usec: rd64(88),
        pr_cstime_sec: rd64(96),
        pr_cstime_usec: rd64(104),
        pr_reg: desc[112..].to_vec(),
    })
}

/// ELF32 prstatus layout offsets (from <sys/procfs.h> / <linux/elfcore.h>):
///
/// ```text
///  0: si_signo   (i32)
///  4: si_code    (i32)
///  8: si_errno   (i32)
/// 12: pr_cursig  (u16)
/// 14: (2 bytes padding)
/// 16: pr_sigpend (u32)
/// 20: pr_sighold (u32)
/// 24: pr_pid     (i32)
/// 28: pr_ppid    (i32)
/// 32: pr_pgrp    (i32)
/// 36: pr_sid     (i32)
/// 40: pr_utime   (timeval: i32 sec + i32 usec)
/// 48: pr_stime   (timeval: i32 sec + i32 usec)
/// 56: pr_cutime  (timeval)
/// 64: pr_cstime  (timeval)
/// 72: pr_reg
/// ```
fn parse_prstatus32(desc: &[u8], endian: ByteOrder) -> Option<Prstatus> {
    if desc.len() < 72 {
        return None;
    }
    let rd16 = |off: usize| endian.u16(desc[off..][..2].try_into().unwrap());
    let rd32 = |off: usize| endian.u32(desc[off..][..4].try_into().unwrap());

    Some(Prstatus {
        pr_cursig: rd16(12),
        pr_sigpend: rd32(16) as u64,
        pr_sighold: rd32(20) as u64,
        pr_pid: rd32(24),
        pr_ppid: rd32(28),
        pr_pgrp: rd32(32),
        pr_sid: rd32(36),
        pr_utime_sec: rd32(40) as u64,
        pr_utime_usec: rd32(44) as u64,
        pr_stime_sec: rd32(48) as u64,
        pr_stime_usec: rd32(52) as u64,
        pr_cutime_sec: rd32(56) as u64,
        pr_cutime_usec: rd32(60) as u64,
        pr_cstime_sec: rd32(64) as u64,
        pr_cstime_usec: rd32(68) as u64,
        pr_reg: desc[72..].to_vec(),
    })
}

/// ELF64 prpsinfo layout offsets (from <sys/procfs.h>):
///
/// ```text
///  0: pr_state   (i8)
///  1: pr_sname   (char)
///  2: pr_zomb    (i8)
///  3: pr_nice    (i8)
///  4: (4 bytes padding)
///  8: pr_flag    (u64)
/// 16: pr_uid     (u32)
/// 20: pr_gid     (u32)
/// 24: pr_pid     (i32)
/// 28: pr_ppid    (i32)
/// 32: pr_pgrp    (i32)
/// 36: pr_sid     (i32)
/// 40: pr_fname   ([u8; 16])
/// 56: pr_psargs  ([u8; 80])
/// Total: 136 bytes
/// ```
fn parse_prpsinfo64(desc: &[u8], endian: ByteOrder) -> Option<Prpsinfo> {
    if desc.len() < 136 {
        return None;
    }
    let rd32 = |off: usize| endian.u32(desc[off..][..4].try_into().unwrap());

    let nul_trimmed = |start: usize, len: usize| -> String {
        let slice = &desc[start..start + len];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(len);
        String::from_utf8_lossy(&slice[..end]).into_owned()
    };

    Some(Prpsinfo {
        pr_sname: desc[1] as char,
        pr_nice: desc[3] as i8,
        pr_uid: rd32(16),
        pr_gid: rd32(20),
        pr_pid: rd32(24),
        pr_ppid: rd32(28),
        pr_pgrp: rd32(32),
        pr_sid: rd32(36),
        pr_fname: nul_trimmed(40, 16),
        pr_psargs: nul_trimmed(56, 80),
    })
}

/// ELF32 prpsinfo layout offsets (from <sys/procfs.h>):
///
/// ```text
///   0: pr_state   (i8)
///   1: pr_sname   (char)
///   2: pr_zomb    (i8)
///   3: pr_nice    (i8)
///   4: pr_flag    (u32)
///   8: pr_uid     (u16)  -- kernel uses u16 for 32-bit
///  10: pr_gid     (u16)
///  12: pr_pid     (i32)
///  16: pr_ppid    (i32)
///  20: pr_pgrp    (i32)
///  24: pr_sid     (i32)
///  28: pr_fname   ([u8; 16])
///  44: pr_psargs  ([u8; 80])
/// Total: 124 bytes
/// ```
fn parse_prpsinfo32(desc: &[u8], endian: ByteOrder) -> Option<Prpsinfo> {
    if desc.len() < 124 {
        return None;
    }
    let rd16 = |off: usize| endian.u16(desc[off..][..2].try_into().unwrap());
    let rd32 = |off: usize| endian.u32(desc[off..][..4].try_into().unwrap());

    let nul_trimmed = |start: usize, len: usize| -> String {
        let slice = &desc[start..start + len];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(len);
        String::from_utf8_lossy(&slice[..end]).into_owned()
    };

    Some(Prpsinfo {
        pr_sname: desc[1] as char,
        pr_nice: desc[3] as i8,
        pr_uid: rd16(8) as u32,
        pr_gid: rd16(10) as u32,
        pr_pid: rd32(12),
        pr_ppid: rd32(16),
        pr_pgrp: rd32(20),
        pr_sid: rd32(24),
        pr_fname: nul_trimmed(28, 16),
        pr_psargs: nul_trimmed(44, 80),
    })
}

const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;
const NT_AUXV: u32 = 6;
const ELFCLASS32: c_int = 1;
const ELFCLASS64: c_int = 2;
const EI_DATA: usize = 5;
const ELFDATA2MSB: u8 = 2;

impl CoreElf {
    /// Return the word size (4 or 8) from the ELF class.
    pub(super) fn word_size(&self) -> Option<usize> {
        match unsafe { crate::dw_sys::gelf_getclass(self.elf.0) } {
            ELFCLASS32 => Some(4),
            ELFCLASS64 => Some(8),
            _ => None,
        }
    }

    /// Return the byte order from the ELF header.
    pub(super) fn byte_order(&self) -> Option<ByteOrder> {
        unsafe {
            let mut ehdr = std::mem::zeroed::<crate::dw_sys::GElf_Ehdr>();
            if crate::dw_sys::gelf_getehdr(self.elf.0, &mut ehdr).is_null() {
                return None;
            }
            Some(if ehdr.e_ident[EI_DATA] == ELFDATA2MSB {
                ByteOrder::Big
            } else {
                ByteOrder::Little
            })
        }
    }

    /// Parse all NT_PRSTATUS, NT_PRPSINFO, and NT_AUXV notes from the core file.
    ///
    /// Returns a map of TID -> Prstatus, an optional Prpsinfo (first one found),
    /// and optional raw auxv bytes (first NT_AUXV note found).
    pub(super) fn parse_notes(
        &self,
    ) -> (HashMap<u64, Prstatus>, Option<Prpsinfo>, Option<Vec<u8>>) {
        let mut map = HashMap::new();
        let mut prpsinfo = None;
        let mut auxv_bytes: Option<Vec<u8>> = None;

        let is_64 = match self.word_size() {
            Some(8) => true,
            Some(4) => false,
            _ => return (map, prpsinfo, auxv_bytes),
        };

        let endian = match self.byte_order() {
            Some(b) => b,
            None => return (map, prpsinfo, auxv_bytes),
        };

        unsafe {
            let mut phnum: libc::size_t = 0;
            if crate::dw_sys::elf_getphdrnum(self.elf.0, &mut phnum) != 0 {
                return (map, prpsinfo, auxv_bytes);
            }

            for i in 0..phnum as c_int {
                let mut phdr = std::mem::zeroed::<crate::dw_sys::GElf_Phdr>();
                if crate::dw_sys::gelf_getphdr(self.elf.0, i, &mut phdr).is_null() {
                    continue;
                }
                if phdr.p_type != libc::PT_NOTE {
                    continue;
                }

                // Get the raw data for this PT_NOTE segment.
                let data = crate::dw_sys::elf_getdata_rawchunk(
                    self.elf.0,
                    phdr.p_offset as i64,
                    phdr.p_filesz as libc::size_t,
                    crate::dw_sys::ELF_T_NHDR,
                );
                if data.is_null() {
                    continue;
                }
                let data_ref = &*data;
                if data_ref.d_buf.is_null() || data_ref.d_size == 0 {
                    continue;
                }

                let buf = std::slice::from_raw_parts(data_ref.d_buf as *const u8, data_ref.d_size);

                // Iterate notes within this segment.
                let mut offset: libc::size_t = 0;
                loop {
                    let mut nhdr = std::mem::zeroed::<crate::dw_sys::GElf_Nhdr>();
                    let mut name_offset: libc::size_t = 0;
                    let mut desc_offset: libc::size_t = 0;

                    let next = crate::dw_sys::gelf_getnote(
                        data as *mut _,
                        offset,
                        &mut nhdr,
                        &mut name_offset,
                        &mut desc_offset,
                    );
                    if next == 0 {
                        break;
                    }

                    // Verify name starts with "CORE".  The ELF spec says
                    // n_namesz includes the NUL terminator (so 5 for "CORE"),
                    // but some producers set n_namesz == 4.
                    let namesz = nhdr.n_namesz as usize;
                    let name_ok = namesz >= 4
                        && name_offset
                            .checked_add(namesz)
                            .is_some_and(|end| end <= buf.len())
                        && buf[name_offset..name_offset + 4] == *b"CORE";

                    if name_ok && desc_offset + nhdr.n_descsz as usize <= buf.len() {
                        let desc = &buf[desc_offset..desc_offset + nhdr.n_descsz as usize];

                        match nhdr.n_type {
                            NT_PRSTATUS => {
                                let parsed = if is_64 {
                                    parse_prstatus64(desc, endian)
                                } else {
                                    parse_prstatus32(desc, endian)
                                };
                                if let Some(prstatus) = parsed {
                                    map.insert(prstatus.pr_pid as u64, prstatus);
                                }
                            }
                            NT_PRPSINFO if prpsinfo.is_none() => {
                                prpsinfo = if is_64 {
                                    parse_prpsinfo64(desc, endian)
                                } else {
                                    parse_prpsinfo32(desc, endian)
                                };
                            }
                            NT_AUXV if auxv_bytes.is_none() => {
                                auxv_bytes = Some(desc.to_vec());
                            }
                            _ => {}
                        }
                    }

                    offset = next;
                }
            }
        }

        (map, prpsinfo, auxv_bytes)
    }
}

// SAFETY: CoreElf is Send + Sync because the ELF handle is opened read-only
// (ELF_C_READ_MMAP) and all methods take &self.  The libelf read-only
// operations do not mutate shared state.
unsafe impl Send for CoreElf {}
unsafe impl Sync for CoreElf {}
