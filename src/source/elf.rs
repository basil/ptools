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
                if phdr.p_type != libc::PT_LOAD {
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
}

// SAFETY: CoreElf is Send + Sync because the ELF handle is opened read-only
// (ELF_C_READ_MMAP) and all methods take &self.  The libelf read-only
// operations do not mutate shared state.
unsafe impl Send for CoreElf {}
unsafe impl Sync for CoreElf {}
