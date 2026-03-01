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
use std::path::PathBuf;

use nix::libc;

use super::dw::Dwfl;
use super::dw::{self};
use super::ProcSource;

/// Live-process backend: reads everything from `/proc/[pid]/...`.
///
/// Each `/proc` file is read at most once per `LiveProcess` lifetime;
/// subsequent calls return a clone from the cache.
pub(super) struct LiveProcess {
    pid: u64,

    // Lazy dwfl session (only created when trace_thread is called).
    dwfl: OnceCell<Option<RefCell<Dwfl<'static>>>>,

    // Per-process caches (no parameters).
    stat: OnceCell<String>,
    status: OnceCell<String>,
    comm: OnceCell<String>,
    cmdline: OnceCell<Vec<u8>>,
    environ: OnceCell<Vec<u8>>,
    auxv: OnceCell<Vec<u8>>,
    exe: OnceCell<PathBuf>,
    limits: OnceCell<String>,
    schedstat: OnceCell<String>,
    tids: OnceCell<Vec<u64>>,
    fds: OnceCell<Vec<u64>>,

    // Parameterized caches.
    tid_stat: RefCell<HashMap<u64, String>>,
    tid_status: RefCell<HashMap<u64, String>>,
    fd_link: RefCell<HashMap<u64, PathBuf>>,
    fdinfo: RefCell<HashMap<u64, String>>,
    net_file: RefCell<HashMap<String, String>>,
}

impl LiveProcess {
    pub(super) fn new(pid: u64) -> Self {
        LiveProcess {
            pid,
            dwfl: OnceCell::new(),
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
            net_file: RefCell::new(HashMap::new()),
        }
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

    fn read_stat(&self) -> io::Result<String> {
        if let Some(val) = self.stat.get() {
            return Ok(val.clone());
        }
        let val = std::fs::read_to_string(format!("/proc/{}/stat", self.pid))?;
        let _ = self.stat.set(val.clone());
        Ok(val)
    }

    fn read_status(&self) -> io::Result<String> {
        if let Some(val) = self.status.get() {
            return Ok(val.clone());
        }
        let val = std::fs::read_to_string(format!("/proc/{}/status", self.pid))?;
        let _ = self.status.set(val.clone());
        Ok(val)
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

    fn read_auxv(&self) -> io::Result<Vec<u8>> {
        if let Some(val) = self.auxv.get() {
            return Ok(val.clone());
        }
        let val = std::fs::read(format!("/proc/{}/auxv", self.pid))?;
        let _ = self.auxv.set(val.clone());
        Ok(val)
    }

    fn read_exe(&self) -> io::Result<PathBuf> {
        if let Some(val) = self.exe.get() {
            return Ok(val.clone());
        }
        let val = std::fs::read_link(format!("/proc/{}/exe", self.pid))?;
        let _ = self.exe.set(val.clone());
        Ok(val)
    }

    fn read_limits(&self) -> io::Result<String> {
        if let Some(val) = self.limits.get() {
            return Ok(val.clone());
        }
        let val = std::fs::read_to_string(format!("/proc/{}/limits", self.pid))?;
        let _ = self.limits.set(val.clone());
        Ok(val)
    }

    fn read_schedstat(&self) -> io::Result<String> {
        if let Some(val) = self.schedstat.get() {
            return Ok(val.clone());
        }
        let val = std::fs::read_to_string(format!("/proc/{}/schedstat", self.pid))?;
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

    fn read_tid_stat(&self, tid: u64) -> io::Result<String> {
        if let Some(cached) = self.tid_stat.borrow().get(&tid) {
            return Ok(cached.clone());
        }
        let val = std::fs::read_to_string(format!("/proc/{}/task/{}/stat", self.pid, tid))?;
        self.tid_stat.borrow_mut().insert(tid, val.clone());
        Ok(val)
    }

    fn read_tid_status(&self, tid: u64) -> io::Result<String> {
        if let Some(cached) = self.tid_status.borrow().get(&tid) {
            return Ok(cached.clone());
        }
        let val = std::fs::read_to_string(format!("/proc/{}/task/{}/status", self.pid, tid))?;
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

    fn read_fdinfo(&self, fd: u64) -> io::Result<String> {
        if let Some(cached) = self.fdinfo.borrow().get(&fd) {
            return Ok(cached.clone());
        }
        let val = std::fs::read_to_string(format!("/proc/{}/fdinfo/{}", self.pid, fd))?;
        self.fdinfo.borrow_mut().insert(fd, val.clone());
        Ok(val)
    }

    fn read_net_file(&self, name: &str) -> io::Result<String> {
        if let Some(cached) = self.net_file.borrow().get(name) {
            return Ok(cached.clone());
        }
        let val = std::fs::read_to_string(format!("/proc/{}/net/{}", self.pid, name))?;
        self.net_file
            .borrow_mut()
            .insert(name.to_string(), val.clone());
        Ok(val)
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
