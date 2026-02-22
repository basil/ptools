mod coredump;
mod live;

use std::io;
use std::path::{Path, PathBuf};

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

    // Per-thread
    fn list_tids(&self) -> io::Result<Vec<u64>>;
    fn read_tid_stat(&self, tid: u64) -> io::Result<String>;
    fn read_tid_status(&self, tid: u64) -> io::Result<String>;

    // Per-fd
    fn list_fds(&self) -> io::Result<Vec<u64>>;
    fn read_fd_link(&self, fd: u64) -> io::Result<PathBuf>;
    fn read_fdinfo(&self, fd: u64) -> io::Result<String>;

    // Network namespace
    fn read_net_file(&self, name: &str) -> io::Result<String>;
}

pub(crate) fn open_live(pid: u64) -> Box<dyn ProcSource> {
    Box::new(live::LiveProcess::new(pid))
}

pub(crate) fn open_coredump(path: &Path) -> io::Result<(Box<dyn ProcSource>, Vec<String>)> {
    let source = coredump::CoredumpSource::from_corefile(path)?;
    let warnings = source.warnings().to_vec();
    Ok((Box::new(source), warnings))
}
