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

//! Data-source abstraction layer for process introspection.
//!
//! This module provides a uniform [`ProcSource`] trait that abstracts over
//! where process data comes from -- a live `/proc/[pid]/...` filesystem or
//! an ELF coredump with systemd journal fields.  The rest of the crate
//! programs against this trait so the same parsing logic works for both
//! backends.
//!
//! **Only consumer:** [`crate::proc`] -- the proc-handle module.  Nothing
//! outside `proc` should depend on this module directly.
//!
//! **Contract:**
//! - This module must **never** write to stdout.
//! - Types defined here should **not** implement `Display`; formatting is
//!   the responsibility of the presentation layer.

mod apport;
mod coredump;
mod dw;
mod elf;
mod initial;
mod live;
mod systemd;

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use nix::unistd::sysconf;
use nix::unistd::SysconfVar;

use crate::model;
use crate::model::auxv::AuxvType;

/// Abstraction over process data sources.
///
/// A live process reads from `/proc/[pid]/...`; a coredump backend
/// supplies the same data from journal fields or ELF notes.
pub(crate) trait ProcSource {
    fn pid(&self) -> u64;

    // Per-process
    fn read_comm(&self) -> io::Result<OsString>;
    fn read_cmdline(&self) -> io::Result<Vec<OsString>>;
    fn is_cmdline_lossy(&self) -> bool;
    fn read_environ(&self) -> io::Result<Vec<OsString>>;
    fn read_auxv(&self) -> io::Result<model::auxv::Auxv>;
    fn read_stat(&self) -> io::Result<model::stat::Stat>;
    fn read_status(&self) -> io::Result<model::status::Status>;
    fn read_utime_us(&self) -> io::Result<u64>;
    fn read_stime_us(&self) -> io::Result<u64>;
    fn read_cutime_us(&self) -> io::Result<u64>;
    fn read_cstime_us(&self) -> io::Result<u64>;
    fn read_exe(&self) -> io::Result<PathBuf>;
    fn read_limits(&self) -> io::Result<model::limits::Limits>;
    fn read_schedstat(&self) -> io::Result<model::schedstat::SchedStat>;

    // Per-thread
    fn list_tids(&self) -> io::Result<Vec<u64>>;
    fn read_tid_stat(&self, tid: u64) -> io::Result<model::stat::Stat>;
    fn read_tid_status(&self, tid: u64) -> io::Result<model::status::Status>;

    // Per-fd
    fn list_fds(&self) -> io::Result<Vec<u64>>;
    fn read_fd_link(&self, fd: u64) -> io::Result<PathBuf>;
    fn read_fdinfo(&self, fd: u64) -> io::Result<model::fdinfo::FdInfo>;

    // Network namespace
    fn read_net_file(&self, name: &str) -> io::Result<Box<dyn io::BufRead>>;

    // Memory
    fn word_size(&self) -> usize;
    fn byte_order(&self) -> model::auxv::ByteOrder;
    fn read_memory(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Look up a string that was already read and cached from the initial
    /// stack walk.  Returns `None` if the address is not in the cache.
    fn cached_string(&self, _addr: u64) -> Option<OsString> {
        None
    }

    /// Walk and symbolize frames for one thread.  Manages dwfl internally.
    fn trace_thread(
        &self,
        tid: u32,
        options: &crate::stack::TraceOptions,
    ) -> Vec<crate::stack::Frame>;

    /// Return the page size for the target process.
    ///
    /// Prefers `AT_PAGESZ` from the auxiliary vector, falls back to
    /// `sysconf(_SC_PAGE_SIZE)`.
    fn page_size(&self) -> io::Result<u64> {
        if let Some(page_sz) = self.read_auxv().ok().and_then(|auxv| {
            auxv.0
                .iter()
                .find(|(typ, _)| *typ == AuxvType::PageSz)
                .map(|(_, value)| *value)
        }) {
            return Ok(page_sz);
        }

        eprintln!("warning: AT_PAGESZ not available, falling back to sysconf");
        match sysconf(SysconfVar::PAGE_SIZE) {
            Ok(Some(v)) => Ok(v as u64),
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "sysconf(_SC_PAGE_SIZE) returned no value",
            )),
            Err(e) => Err(io::Error::other(format!(
                "sysconf(_SC_PAGE_SIZE) failed: {e}"
            ))),
        }
    }

    /// Read `count` consecutive pointer-sized words starting at `addr`.
    ///
    /// Loops on short reads so that page/segment boundaries do not cause
    /// spurious failures.
    fn read_words(&self, addr: u64, count: usize) -> io::Result<Vec<u64>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let ws = self.word_size();
        let bo = self.byte_order();
        let total = count * ws;
        let mut buf = vec![0u8; total];
        let mut filled = 0usize;
        while filled < total {
            let n = self.read_memory(
                addr.checked_add(filled as u64).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "address overflow in read_words")
                })?,
                &mut buf[filled..],
            )?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "zero-byte read at {:#x} ({filled} of {total} bytes read)",
                        addr + filled as u64,
                    ),
                ));
            }
            filled += n;
        }
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let off = i * ws;
            let val = match ws {
                4 => {
                    let b: [u8; 4] = buf[off..off + 4].try_into().unwrap();
                    bo.u32(b) as u64
                }
                8 => {
                    let b: [u8; 8] = buf[off..off + 8].try_into().unwrap();
                    bo.u64(b)
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("unsupported word size {ws}"),
                    ));
                }
            };
            result.push(val);
        }
        Ok(result)
    }

    /// Read a NUL-terminated C string from the target's address space.
    ///
    /// Reads in page-sized chunks to avoid crossing into unmapped memory.
    fn read_cstring(&self, addr: u64) -> io::Result<OsString> {
        if addr == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "null pointer"));
        }
        let page_size = self.page_size()?.max(1) as usize;
        // Linux limits each argv/environ string to MAX_ARG_STRLEN
        // (PAGE_SIZE * 32) bytes.
        let max_string_len = page_size * 32;
        let mut result = Vec::new();
        let mut cur = addr;
        while result.len() < max_string_len {
            // Read up to the end of the current page.
            let page_offset = (cur as usize) % page_size;
            let chunk_len = (page_size - page_offset).min(max_string_len - result.len());
            let mut buf = vec![0u8; chunk_len];
            let n = self.read_memory(cur, &mut buf)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("zero-byte read at {cur:#x} while reading C string"),
                ));
            }
            let buf = &buf[..n];
            if let Some(nul_pos) = buf.iter().position(|&b| b == 0) {
                result.extend_from_slice(&buf[..nul_pos]);
                return Ok(OsString::from(std::ffi::OsStr::from_bytes(&result)));
            }
            result.extend_from_slice(buf);
            cur = cur.checked_add(n as u64).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "address overflow reading string",
                )
            })?;
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no NUL terminator within {max_string_len} bytes at {addr:#x}"),
        ))
    }

    fn read_auxv_string(&self, typ: AuxvType) -> io::Result<OsString> {
        if !matches!(
            typ,
            AuxvType::ExecFn | AuxvType::Platform | AuxvType::BasePlatform
        ) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "not a string auxv type",
            ));
        }
        let auxv = self.read_auxv()?;
        let addr = auxv
            .0
            .iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, v)| *v)
            .filter(|&v| v != 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "auxv type not found"))?;
        match self.cached_string(addr) {
            Some(s) => Ok(s),
            None => self.read_cstring(addr),
        }
    }

    /// Read the current environment from the `environ`/`__environ` symbol.
    ///
    /// `environ_sym_addr` is the address of the `char **environ` global
    /// variable.  Reads the pointer at that address to get the environ
    /// array, then walks it reading strings until a NULL pointer.
    fn read_environ_from_symbol(&self, environ_sym_addr: u64) -> io::Result<Vec<OsString>> {
        const MAX_ENTRIES: usize = 1_000_000;
        const CHUNK: usize = 512;

        let ws = self.word_size() as u64;

        let array_addr = self.read_words(environ_sym_addr, 1)?[0];
        if array_addr == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "environ pointer is null",
            ));
        }

        let mut result = Vec::new();
        let mut cur = array_addr;
        'outer: loop {
            let n = CHUNK.min(MAX_ENTRIES + 1 - result.len());
            let words = self.read_words(cur, n)?;
            for &ptr in &words {
                if ptr == 0 {
                    break 'outer;
                }
                if result.len() >= MAX_ENTRIES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "environ array too large",
                    ));
                }
                let s = match self.cached_string(ptr) {
                    Some(s) => s,
                    None => self.read_cstring(ptr)?,
                };
                result.push(s);
            }
            cur = cur.checked_add(n as u64 * ws).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "address overflow reading environ",
                )
            })?;
        }

        Ok(result)
    }
}

/// Split a NUL-delimited byte buffer into `OsString` entries,
/// discarding any trailing empty entry from a final NUL.
fn split_nul_bytes(bytes: &[u8]) -> Vec<OsString> {
    let mut result: Vec<OsString> = bytes
        .split(|b| *b == b'\0')
        .map(|b| OsString::from(std::ffi::OsStr::from_bytes(b)))
        .collect();
    if result.last().is_some_and(|s| s.is_empty()) {
        result.pop();
    }
    result
}

pub(crate) fn open_live(pid: u64) -> Box<dyn ProcSource> {
    Box::new(live::LiveProcess::new(pid))
}

pub(crate) fn open_coredump(path: &Path) -> io::Result<Box<dyn ProcSource>> {
    let core_elf = match elf::CoreElf::open(path) {
        Ok(e) => Some(Arc::new(e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            // Not a valid ELF file -- check if it's an apport crash file.
            if apport::is_apport_crash(path) {
                let source = coredump::CoredumpSource::from_apport(path)?;
                return Ok(Box::new(source));
            }
            return Err(io::Error::new(
                e.kind(),
                format!("{}: {}", path.display(), e),
            ));
        }
    };
    let source = coredump::CoredumpSource::from_corefile(path, core_elf.as_ref())?;
    Ok(Box::new(source))
}
