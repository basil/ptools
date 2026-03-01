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

//! File descriptor enumeration: gathering fully-populated [`FileDescriptor`]
//! structs for every open fd in a process.

use std::collections::HashMap;
use std::io;

use nix::sys::stat::FileStat;

use super::net::derive_peer_processes;
use super::net::get_sockprotoname;
use super::net::has_loopback_tcp_peers;
use super::net::parse_socket_info;
use super::net::query_socket_details;
use super::net::unix_peer_process;
use super::net::Socket;
use super::ProcHandle;
use crate::model::fd::FDTarget;
use crate::model::fdinfo::FdInfo;
use crate::model::net::NetEntry;

/// Fully-populated file descriptor information gathered from the library.
///
/// Produced by [`ProcHandle::file_descriptors()`].
pub struct FileDescriptor {
    pub fd: u64,
    pub target: FDTarget,
    pub stat: Option<FileStat>,
    pub fdinfo: FdInfo,
    pub socket: Option<Socket>,
    pub sockprotoname: Option<String>,
}

impl ProcHandle {
    /// Gather fully-populated [`FileDescriptor`] structs for every open
    /// file descriptor in the process.
    ///
    /// This is the primary entry point for tools that need to enumerate a
    /// process's open files.  It combines fd path/stat/fdinfo, socket info
    /// from `/proc/net/*`, socket details via `getsockopt`, and peer process
    /// resolution into a single call.
    pub fn file_descriptors(&self) -> io::Result<Vec<FileDescriptor>> {
        let fds = self.fds()?;
        let sockets = parse_socket_info(&*self.source);

        // Compute TCP peer processes in bulk (system-wide /proc scan).
        // Skip for coredumps or when no loopback TCP sockets exist.
        let tcp_peers = if !self.is_core && has_loopback_tcp_peers(&sockets) {
            derive_peer_processes(self.pid(), &sockets)
        } else {
            HashMap::new()
        };

        let mut result = Vec::with_capacity(fds.len());
        for fd_num in fds {
            match self.gather_fd(fd_num, &sockets, &tcp_peers) {
                Ok(fd_desc) => result.push(fd_desc),
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    eprintln!("fd {fd_num}: permission denied");
                }
                Err(e) => {
                    eprintln!("fd {fd_num}: {e}");
                }
            }
        }

        Ok(result)
    }

    /// Gather all available information for a single file descriptor.
    #[allow(clippy::unnecessary_cast)]
    fn gather_fd(
        &self,
        fd_num: u64,
        sockets: &HashMap<u64, NetEntry>,
        tcp_peers: &HashMap<u64, (u64, String)>,
    ) -> io::Result<FileDescriptor> {
        let link_path = self.fd_path(fd_num)?;
        let link_text = link_path.to_string_lossy();
        let info = self.fdinfo(fd_num)?;

        // stat() -- live only
        let stat_result = if !self.is_core {
            nix::sys::stat::stat(format!("/proc/{}/fd/{}", self.pid(), fd_num).as_str()).ok()
        } else {
            None
        };

        // Classify file type
        let target = if let Some(ref st) = stat_result {
            FDTarget::from_stat(st.st_mode, st.st_ino as u64, &link_text)
        } else {
            FDTarget::from_link(&link_text)
        };

        // Socket resolution
        let mut socket = None;
        let mut sockprotoname = None;

        if matches!(target, FDTarget::Socket(_)) {
            let inode = target.inode();

            if let Some(inode) = inode {
                if let Some(sock_info) = sockets.get(&inode) {
                    let details = query_socket_details(self.pid(), fd_num);

                    // Resolve peer process: TCP peers from bulk map, Unix via SO_PEERCRED
                    let peer = tcp_peers.get(&inode).cloned().or_else(|| {
                        if matches!(sock_info, NetEntry::Unix(_)) && !self.is_core {
                            unix_peer_process(self.pid(), fd_num)
                        } else {
                            None
                        }
                    });

                    socket = Some(Socket::from_parts(sock_info.clone(), details, peer));
                }
            }

            // Fallback: sockprotoname xattr when not found in /proc/net/*
            if socket.is_none() && !self.is_core {
                sockprotoname = get_sockprotoname(self.pid(), fd_num);
            }
        }

        Ok(FileDescriptor {
            fd: fd_num,
            target,
            stat: stat_result,
            fdinfo: info,
            socket,
            sockprotoname,
        })
    }
}
