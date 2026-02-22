use std::io;
use std::path::PathBuf;

/// Abstraction over process data sources.
///
/// A live process reads from `/proc/[pid]/...`; a future coredump backend
/// could supply the same data from journal fields or ELF notes.
pub trait ProcSource {
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

/// Live-process backend: reads everything from `/proc/[pid]/...`.
pub struct LiveProcess {
    pid: u64,
}

impl LiveProcess {
    pub fn new(pid: u64) -> Self {
        LiveProcess { pid }
    }
}

impl ProcSource for LiveProcess {
    fn pid(&self) -> u64 {
        self.pid
    }

    fn read_stat(&self) -> io::Result<String> {
        std::fs::read_to_string(format!("/proc/{}/stat", self.pid))
    }

    fn read_status(&self) -> io::Result<String> {
        std::fs::read_to_string(format!("/proc/{}/status", self.pid))
    }

    fn read_comm(&self) -> io::Result<String> {
        std::fs::read_to_string(format!("/proc/{}/comm", self.pid))
    }

    fn read_cmdline(&self) -> io::Result<Vec<u8>> {
        std::fs::read(format!("/proc/{}/cmdline", self.pid))
    }

    fn read_environ(&self) -> io::Result<Vec<u8>> {
        std::fs::read(format!("/proc/{}/environ", self.pid))
    }

    fn read_auxv(&self) -> io::Result<Vec<u8>> {
        std::fs::read(format!("/proc/{}/auxv", self.pid))
    }

    fn read_exe(&self) -> io::Result<PathBuf> {
        std::fs::read_link(format!("/proc/{}/exe", self.pid))
    }

    fn read_limits(&self) -> io::Result<String> {
        std::fs::read_to_string(format!("/proc/{}/limits", self.pid))
    }

    fn list_tids(&self) -> io::Result<Vec<u64>> {
        let mut tids: Vec<u64> = std::fs::read_dir(format!("/proc/{}/task", self.pid))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok())
            .collect();
        tids.sort();
        Ok(tids)
    }

    fn read_tid_stat(&self, tid: u64) -> io::Result<String> {
        std::fs::read_to_string(format!("/proc/{}/task/{}/stat", self.pid, tid))
    }

    fn read_tid_status(&self, tid: u64) -> io::Result<String> {
        std::fs::read_to_string(format!("/proc/{}/task/{}/status", self.pid, tid))
    }

    fn list_fds(&self) -> io::Result<Vec<u64>> {
        let mut fds: Vec<u64> = std::fs::read_dir(format!("/proc/{}/fd", self.pid))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok())
            .collect();
        fds.sort();
        Ok(fds)
    }

    fn read_fd_link(&self, fd: u64) -> io::Result<PathBuf> {
        std::fs::read_link(format!("/proc/{}/fd/{}", self.pid, fd))
    }

    fn read_fdinfo(&self, fd: u64) -> io::Result<String> {
        std::fs::read_to_string(format!("/proc/{}/fdinfo/{}", self.pid, fd))
    }

    fn read_net_file(&self, name: &str) -> io::Result<String> {
        std::fs::read_to_string(format!("/proc/{}/net/{}", self.pid, name))
    }
}
