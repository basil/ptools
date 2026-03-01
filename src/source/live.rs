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

use std::cell::OnceCell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use nix::libc;

use super::dw::Dwfl;
use super::dw::{self};
use super::ProcSource;
use crate::model::FromBufRead;
use crate::model::FromRead;
use crate::model::{self};

/// Live-process backend: reads everything from `/proc/[pid]/...`.
///
/// Each `/proc` file is read at most once per `LiveProcess` lifetime;
/// subsequent calls return a clone from the cache.
pub(super) struct LiveProcess {
    pid: u64,

    // Lazy dwfl session (only created when trace_thread is called).
    dwfl: OnceCell<Option<RefCell<Dwfl<'static>>>>,

    // Cached ELF identity (word size + byte order) from /proc/[pid]/exe.
    elf_ident: OnceCell<(usize, model::auxv::ByteOrder)>,

    // Per-process caches (no parameters).
    stat: OnceCell<model::stat::Stat>,
    status: OnceCell<model::status::Status>,
    comm: OnceCell<String>,
    cmdline: OnceCell<Vec<u8>>,
    environ: OnceCell<Vec<u8>>,
    auxv: OnceCell<model::auxv::Auxv>,
    exe: OnceCell<PathBuf>,
    limits: OnceCell<model::limits::Limits>,
    schedstat: OnceCell<model::schedstat::SchedStat>,
    tids: OnceCell<Vec<u64>>,
    fds: OnceCell<Vec<u64>>,

    // Parameterized caches.
    tid_stat: RefCell<HashMap<u64, model::stat::Stat>>,
    tid_status: RefCell<HashMap<u64, model::status::Status>>,
    fd_link: RefCell<HashMap<u64, PathBuf>>,
    fdinfo: RefCell<HashMap<u64, model::fdinfo::FdInfo>>,
}

impl LiveProcess {
    pub(super) fn new(pid: u64) -> Self {
        LiveProcess {
            pid,
            dwfl: OnceCell::new(),
            elf_ident: OnceCell::new(),
            stat: OnceCell::new(),
            status: OnceCell::new(),
            comm: OnceCell::new(),
            cmdline: OnceCell::new(),
            environ: OnceCell::new(),
            auxv: OnceCell::new(),
            exe: OnceCell::new(),
            limits: OnceCell::new(),
            schedstat: OnceCell::new(),
            tids: OnceCell::new(),
            fds: OnceCell::new(),
            tid_stat: RefCell::new(HashMap::new()),
            tid_status: RefCell::new(HashMap::new()),
            fd_link: RefCell::new(HashMap::new()),
            fdinfo: RefCell::new(HashMap::new()),
        }
    }

    /// Return the target process's word size and byte order, read from the
    /// ELF header of `/proc/[pid]/exe`.  Falls back to local values with a
    /// warning if the header cannot be read (e.g., permission denied).
    fn elf_ident(&self) -> (usize, model::auxv::ByteOrder) {
        const ELFCLASS32: libc::c_int = 1;
        const ELFCLASS64: libc::c_int = 2;
        const EI_DATA: usize = 5;
        const ELFDATA2MSB: u8 = 2;

        *self.elf_ident.get_or_init(|| {
            let path = format!("/proc/{}/exe", self.pid);
            let result = (|| -> Option<(usize, model::auxv::ByteOrder)> {
                let file = std::fs::File::open(&path).ok()?;
                unsafe {
                    crate::dw_sys::elf_version(1); // EV_CURRENT
                    let elf = crate::dw_sys::elf_begin(
                        file.as_raw_fd(),
                        crate::dw_sys::ELF_C_READ,
                        std::ptr::null_mut(),
                    );
                    if elf.is_null() {
                        return None;
                    }
                    let word_size = match crate::dw_sys::gelf_getclass(elf) {
                        ELFCLASS32 => 4,
                        ELFCLASS64 => 8,
                        _ => {
                            crate::dw_sys::elf_end(elf);
                            return None;
                        }
                    };
                    let mut ehdr = std::mem::zeroed::<crate::dw_sys::GElf_Ehdr>();
                    let byte_order = if crate::dw_sys::gelf_getehdr(elf, &mut ehdr).is_null() {
                        crate::dw_sys::elf_end(elf);
                        return None;
                    } else if ehdr.e_ident[EI_DATA] == ELFDATA2MSB {
                        model::auxv::ByteOrder::Big
                    } else {
                        model::auxv::ByteOrder::Little
                    };
                    crate::dw_sys::elf_end(elf);
                    Some((word_size, byte_order))
                }
            })();
            result.unwrap_or_else(|| {
                eprintln!(
                    "warning: failed to read ELF header from {path}; \
                     falling back to local word size and byte order"
                );
                let ws = std::mem::size_of::<usize>();
                let bo = if cfg!(target_endian = "big") {
                    model::auxv::ByteOrder::Big
                } else {
                    model::auxv::ByteOrder::Little
                };
                (ws, bo)
            })
        })
    }

    /// Lazily create and cache the dwfl session for live stack walking.
    fn ensure_dwfl(&self) -> Option<&RefCell<Dwfl<'static>>> {
        self.dwfl
            .get_or_init(|| match dw::create_dwfl_live(self.pid as u32) {
                Ok(d) => Some(RefCell::new(d)),
                Err(e) => {
                    eprintln!("warning: failed to create dwfl session: {e}");
                    None
                }
            })
            .as_ref()
    }
}

impl ProcSource for LiveProcess {
    fn pid(&self) -> u64 {
        self.pid
    }

    fn read_comm(&self) -> io::Result<String> {
        if let Some(val) = self.comm.get() {
            return Ok(val.clone());
        }
        let val = std::fs::read_to_string(format!("/proc/{}/comm", self.pid))?;
        let val = val.trim_end().to_string();
        let _ = self.comm.set(val.clone());
        Ok(val)
    }

    fn read_cmdline(&self) -> io::Result<Vec<u8>> {
        if let Some(val) = self.cmdline.get() {
            return Ok(val.clone());
        }
        let val = std::fs::read(format!("/proc/{}/cmdline", self.pid))?;
        let _ = self.cmdline.set(val.clone());
        Ok(val)
    }

    fn read_environ(&self) -> io::Result<Vec<u8>> {
        if let Some(val) = self.environ.get() {
            return Ok(val.clone());
        }
        let val = std::fs::read(format!("/proc/{}/environ", self.pid))?;
        let _ = self.environ.set(val.clone());
        Ok(val)
    }

    fn read_auxv(&self) -> io::Result<model::auxv::Auxv> {
        if let Some(val) = self.auxv.get() {
            return Ok(val.clone());
        }
        let path = format!("/proc/{}/auxv", self.pid);
        let bytes = std::fs::read(&path)?;
        let val = model::auxv::Auxv::from_read(&*bytes, self.word_size(), self.byte_order())?;
        let _ = self.auxv.set(val.clone());
        Ok(val)
    }

    fn read_stat(&self) -> io::Result<model::stat::Stat> {
        if let Some(val) = self.stat.get() {
            return Ok(val.clone());
        }
        let path = format!("/proc/{}/stat", self.pid);
        let val = model::stat::Stat::from_file(&path)?;
        let _ = self.stat.set(val.clone());
        Ok(val)
    }

    fn read_status(&self) -> io::Result<model::status::Status> {
        if let Some(val) = self.status.get() {
            return Ok(val.clone());
        }
        let path = format!("/proc/{}/status", self.pid);
        let val = model::status::Status::from_file(&path)?;
        let _ = self.status.set(val.clone());
        Ok(val)
    }

    fn read_utime_us(&self) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "high-precision utime not available",
        ))
    }
    fn read_stime_us(&self) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "high-precision stime not available",
        ))
    }
    fn read_cutime_us(&self) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "high-precision cutime not available",
        ))
    }
    fn read_cstime_us(&self) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "high-precision cstime not available",
        ))
    }

    fn read_exe(&self) -> io::Result<PathBuf> {
        if let Some(val) = self.exe.get() {
            return Ok(val.clone());
        }
        let val = std::fs::read_link(format!("/proc/{}/exe", self.pid))?;
        let _ = self.exe.set(val.clone());
        Ok(val)
    }

    fn read_limits(&self) -> io::Result<model::limits::Limits> {
        if let Some(val) = self.limits.get() {
            return Ok(val.clone());
        }
        let path = format!("/proc/{}/limits", self.pid);
        let val = model::limits::Limits::from_file(&path)?;
        let _ = self.limits.set(val.clone());
        Ok(val)
    }

    fn read_schedstat(&self) -> io::Result<model::schedstat::SchedStat> {
        if let Some(val) = self.schedstat.get() {
            return Ok(val.clone());
        }
        let path = format!("/proc/{}/schedstat", self.pid);
        let val = model::schedstat::SchedStat::from_file(&path)?;
        let _ = self.schedstat.set(val.clone());
        Ok(val)
    }

    fn list_tids(&self) -> io::Result<Vec<u64>> {
        if let Some(val) = self.tids.get() {
            return Ok(val.clone());
        }
        let mut tids: Vec<u64> = std::fs::read_dir(format!("/proc/{}/task", self.pid))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok())
            .collect();
        tids.sort();
        let _ = self.tids.set(tids.clone());
        Ok(tids)
    }

    fn read_tid_stat(&self, tid: u64) -> io::Result<model::stat::Stat> {
        if let Some(cached) = self.tid_stat.borrow().get(&tid) {
            return Ok(cached.clone());
        }
        let path = format!("/proc/{}/task/{}/stat", self.pid, tid);
        let val = model::stat::Stat::from_file(&path)?;
        self.tid_stat.borrow_mut().insert(tid, val.clone());
        Ok(val)
    }

    fn read_tid_status(&self, tid: u64) -> io::Result<model::status::Status> {
        if let Some(cached) = self.tid_status.borrow().get(&tid) {
            return Ok(cached.clone());
        }
        let path = format!("/proc/{}/task/{}/status", self.pid, tid);
        let val = model::status::Status::from_file(&path)?;
        self.tid_status.borrow_mut().insert(tid, val.clone());
        Ok(val)
    }

    fn list_fds(&self) -> io::Result<Vec<u64>> {
        if let Some(val) = self.fds.get() {
            return Ok(val.clone());
        }
        let mut fds: Vec<u64> = std::fs::read_dir(format!("/proc/{}/fd", self.pid))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok())
            .collect();
        fds.sort();
        let _ = self.fds.set(fds.clone());
        Ok(fds)
    }

    fn read_fd_link(&self, fd: u64) -> io::Result<PathBuf> {
        if let Some(cached) = self.fd_link.borrow().get(&fd) {
            return Ok(cached.clone());
        }
        let val = std::fs::read_link(format!("/proc/{}/fd/{}", self.pid, fd))?;
        self.fd_link.borrow_mut().insert(fd, val.clone());
        Ok(val)
    }

    fn read_fdinfo(&self, fd: u64) -> io::Result<model::fdinfo::FdInfo> {
        if let Some(cached) = self.fdinfo.borrow().get(&fd) {
            return Ok(cached.clone());
        }
        let path = format!("/proc/{}/fdinfo/{}", self.pid, fd);
        let val = model::fdinfo::FdInfo::from_file(&path)?;
        self.fdinfo.borrow_mut().insert(fd, val.clone());
        Ok(val)
    }

    fn read_net_file(&self, name: &str) -> io::Result<Box<dyn io::BufRead>> {
        let path = format!("/proc/{}/net/{}", self.pid, name);
        let file = std::fs::File::open(&path)?;
        Ok(Box::new(io::BufReader::new(file)))
    }

    fn word_size(&self) -> usize {
        self.elf_ident().0
    }

    fn byte_order(&self) -> model::auxv::ByteOrder {
        self.elf_ident().1
    }

    fn read_memory(&self, addr: u64, buf: &mut [u8]) -> bool {
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: buf.len(),
        };
        unsafe {
            libc::process_vm_readv(self.pid as libc::pid_t, &local, 1, &remote, 1, 0)
                == buf.len() as isize
        }
    }

    fn trace_thread(
        &self,
        tid: u32,
        options: &crate::stack::TraceOptions,
    ) -> Vec<crate::stack::Frame> {
        let dwfl_cell = match self.ensure_dwfl() {
            Some(d) => d,
            None => {
                eprintln!("warning: error tracing thread {tid}: no dwfl session");
                return Vec::new();
            }
        };
        let mut dwfl_ref = dwfl_cell.borrow_mut();
        match dw::walk_thread_frames(&mut dwfl_ref, tid, options) {
            Ok(frames) => frames,
            Err(e) => {
                eprintln!("warning: error tracing thread {tid}: {e}");
                Vec::new()
            }
        }
    }
}
