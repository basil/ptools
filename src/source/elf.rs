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
//! core dump.  Provides memory reading via PT_LOAD segments and PID
//! extraction from NT_PRSTATUS notes.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::raw::c_int;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use nix::libc;

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

/// NT_PRSTATUS note type.
const NT_PRSTATUS: u32 = 1;

/// PT_NOTE program header type.
const PT_NOTE: u32 = 4;

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
    pub(super) fn read_memory(&self, addr: u64, buf: &mut [u8]) -> bool {
        unsafe {
            let mut phnum: libc::size_t = 0;
            if crate::dw_sys::elf_getphdrnum(self.elf.0, &mut phnum) != 0 {
                return false;
            }
            for i in 0..phnum as c_int {
                let mut phdr = std::mem::zeroed::<crate::dw_sys::GElf_Phdr>();
                if crate::dw_sys::gelf_getphdr(self.elf.0, i, &mut phdr).is_null() {
                    continue;
                }
                // PT_LOAD = 1
                if phdr.p_type != 1 {
                    continue;
                }
                if addr >= phdr.p_vaddr && addr + buf.len() as u64 <= phdr.p_vaddr + phdr.p_filesz {
                    let offset = (addr - phdr.p_vaddr + phdr.p_offset) as i64;
                    let data = crate::dw_sys::elf_getdata_rawchunk(
                        self.elf.0,
                        offset,
                        buf.len(),
                        crate::dw_sys::ELF_T_BYTE,
                    );
                    if data.is_null() {
                        return false;
                    }
                    let d = &*data;
                    if d.d_buf.is_null() || d.d_size < buf.len() {
                        return false;
                    }
                    std::ptr::copy_nonoverlapping(
                        d.d_buf.cast::<u8>(),
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                    return true;
                }
            }
        }
        false
    }

    /// Extract the PID from the first NT_PRSTATUS note in the core file.
    ///
    /// Returns 0 if no NT_PRSTATUS note is found.
    pub(super) fn pid(&self) -> u32 {
        unsafe {
            let elf = self.elf.0;

            // Determine PID offset within prstatus based on ELF class.
            // ELFCLASS64: pr_pid is at offset 32 (after siginfo(12) + cursig(2) + pad(2) + sigpend(8) + sighold(8))
            // ELFCLASS32: pr_pid is at offset 24 (after siginfo(12) + cursig(2) + pad(2) + sigpend(4) + sighold(4))
            let class = crate::dw_sys::gelf_getclass(elf);
            let pid_offset: usize = if class == 2 { 32 } else { 24 };

            let mut phnum: libc::size_t = 0;
            if crate::dw_sys::elf_getphdrnum(elf, &mut phnum) != 0 {
                return 0;
            }

            for i in 0..phnum as c_int {
                let mut phdr = std::mem::zeroed::<crate::dw_sys::GElf_Phdr>();
                if crate::dw_sys::gelf_getphdr(elf, i, &mut phdr).is_null() {
                    continue;
                }
                if phdr.p_type != PT_NOTE {
                    continue;
                }

                let data = crate::dw_sys::elf_getdata_rawchunk(
                    elf,
                    phdr.p_offset as i64,
                    phdr.p_filesz as usize,
                    crate::dw_sys::ELF_T_NHDR,
                );
                if data.is_null() {
                    continue;
                }

                let mut offset: libc::size_t = 0;
                loop {
                    let mut nhdr = std::mem::zeroed::<crate::dw_sys::GElf_Nhdr>();
                    let mut name_offset: libc::size_t = 0;
                    let mut desc_offset: libc::size_t = 0;

                    let next = crate::dw_sys::gelf_getnote(
                        data,
                        offset,
                        &mut nhdr,
                        &mut name_offset,
                        &mut desc_offset,
                    );
                    if next == 0 {
                        break;
                    }

                    if nhdr.n_type == NT_PRSTATUS {
                        let d = &*data;
                        let name_end = name_offset + nhdr.n_namesz as usize;
                        if name_end <= d.d_size {
                            let name_slice = std::slice::from_raw_parts(
                                (d.d_buf as *const u8).add(name_offset),
                                nhdr.n_namesz as usize,
                            );
                            let name = name_slice.strip_suffix(b"\0").unwrap_or(name_slice);
                            if name == b"CORE" && desc_offset + pid_offset + 4 <= d.d_size {
                                let desc_start = (d.d_buf as *const u8).add(desc_offset);
                                let pid_ptr = desc_start.add(pid_offset) as *const i32;
                                let pid = std::ptr::read_unaligned(pid_ptr);
                                return pid as u32;
                            }
                        }
                    }

                    offset = next;
                }
            }

            0
        }
    }
}

// SAFETY: CoreElf is Send + Sync because the ELF handle is opened read-only
// (ELF_C_READ_MMAP) and all methods take &self.  The libelf read-only
// operations do not mutate shared state.
unsafe impl Send for CoreElf {}
unsafe impl Sync for CoreElf {}
