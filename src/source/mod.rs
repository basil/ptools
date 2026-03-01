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

mod coredump;
mod dw;
mod elf;
mod live;

use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use crate::model;

/// Abstraction over process data sources.
///
/// A live process reads from `/proc/[pid]/...`; a coredump backend
/// supplies the same data from journal fields or ELF notes.
pub(crate) trait ProcSource {
    fn pid(&self) -> u64;

    // Per-process files
    fn read_stat(&self) -> io::Result<String>;
    fn read_status(&self) -> io::Result<String>;
    fn read_comm(&self) -> io::Result<String>;
    fn read_cmdline(&self) -> io::Result<Vec<u8>>;
    fn read_environ(&self) -> io::Result<Vec<u8>>;
    fn read_auxv(&self) -> io::Result<Vec<u8>>;
    fn read_exe(&self) -> io::Result<PathBuf>;
    fn read_limits(&self) -> io::Result<String>;
    fn read_schedstat(&self) -> io::Result<model::schedstat::SchedStat>;

    // Per-thread
    fn list_tids(&self) -> io::Result<Vec<u64>>;
    fn read_tid_stat(&self, tid: u64) -> io::Result<String>;
    fn read_tid_status(&self, tid: u64) -> io::Result<String>;

    // Per-fd
    fn list_fds(&self) -> io::Result<Vec<u64>>;
    fn read_fd_link(&self, fd: u64) -> io::Result<PathBuf>;
    fn read_fdinfo(&self, fd: u64) -> io::Result<model::fdinfo::FdInfo>;

    // Network namespace
    fn read_net_file(&self, name: &str) -> io::Result<String>;

    // Memory
    fn read_memory(&self, addr: u64, buf: &mut [u8]) -> bool;

    /// Walk and symbolize frames for one thread.  Manages dwfl internally.
    fn trace_thread(
        &self,
        tid: u32,
        options: &crate::stack::TraceOptions,
    ) -> Vec<crate::stack::Frame>;
}

pub(crate) fn open_live(pid: u64) -> Box<dyn ProcSource> {
    Box::new(live::LiveProcess::new(pid))
}

pub(crate) fn open_coredump(path: &Path) -> io::Result<Box<dyn ProcSource>> {
    let core_elf = match elf::CoreElf::open(path) {
        Ok(e) => Some(Arc::new(e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("{}: {}", path.display(), e),
            ));
        }
    };
    let source = coredump::CoredumpSource::from_corefile(path, core_elf.as_ref())?;
    Ok(Box::new(source))
}
