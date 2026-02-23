//
//   Copyright 2026 Basil Crow
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

//! pidfd wrapper for process-handle operations.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use nix::errno::Errno;
use nix::libc;

/// An owned pidfd handle for a process.
pub struct PidFd {
    fd: OwnedFd,
}

impl PidFd {
    /// Open a pidfd for the given PID via the pidfd_open(2) syscall.
    pub fn open(pid: u64) -> io::Result<PidFd> {
        let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0_u32) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(PidFd {
                fd: unsafe { OwnedFd::from_raw_fd(ret as i32) },
            })
        }
    }

    /// Read the wait status via waitid(P_PIDFD).
    ///
    /// Returns `Ok(status)` on success, `Err(ECHILD)` for non-child processes.
    pub fn wait_status(&self) -> Result<i32, Errno> {
        let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.fd.as_raw_fd() as libc::id_t,
                &mut siginfo,
                libc::WEXITED,
            )
        };
        if ret < 0 {
            return Err(Errno::last());
        }
        // Reconstruct the traditional wait status from siginfo fields.
        let code = siginfo.si_code;
        let status = unsafe { siginfo.si_status() };
        let wait_status = match code {
            libc::CLD_EXITED => (status & 0xff) << 8,
            libc::CLD_KILLED => status & 0x7f,
            libc::CLD_DUMPED => (status & 0x7f) | 0x80,
            _ => 0,
        };
        Ok(wait_status)
    }
}

impl AsRawFd for PidFd {
    fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}
