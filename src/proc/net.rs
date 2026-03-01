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

//! Socket/network resolution: parsing `/proc/net/*`, querying socket options
//! via `getsockopt`, and resolving peer processes for TCP and Unix sockets.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt;
use nix::sys::socket::AddressFamily;

use crate::model::fd::parse_socket_inode;
use crate::model::net::NetEntry;
use crate::model::net::NetlinkNetEntries;
use crate::model::net::RawNetEntries;
use crate::model::net::SockType;
use crate::model::net::SocketDetails;
use crate::model::net::SocketOptions;
use crate::model::net::TcpNetEntries;
use crate::model::net::UdpNetEntries;
use crate::model::net::UnixNetEntries;
use crate::model::FromBufRead;
use crate::source::ProcSource;

/// Unified socket metadata combining `/proc/net/*` info, `getsockopt` details,
/// and peer process resolution.
pub struct Socket {
    pub entry: NetEntry,
    pub family: AddressFamily,
    pub sock_type: SockType,
    pub options: SocketOptions,
    pub tcp_info: Option<nix::libc::tcp_info>,
    pub congestion_control: Option<String>,
    pub peer_pid: Option<u64>,
    pub peer_comm: Option<String>,
}

impl Socket {
    pub(super) fn from_parts(
        entry: NetEntry,
        details: Option<SocketDetails>,
        peer: Option<(u64, String)>,
    ) -> Self {
        let (tcp_info, congestion_control, options) = if let Some(d) = details {
            (d.tcp_info, d.congestion_control, d.options)
        } else {
            (None, None, SocketOptions::default())
        };

        let (peer_pid, peer_comm) = match peer {
            Some((pid, comm)) => (Some(pid), Some(comm)),
            None => (None, None),
        };

        let family_from_addr = |addr: &SocketAddr| {
            if addr.is_ipv4() {
                AddressFamily::Inet
            } else {
                AddressFamily::Inet6
            }
        };

        let (family, sock_type) = match &entry {
            NetEntry::Tcp(e) => (family_from_addr(&e.local_address), SockType::Stream),
            NetEntry::Udp(e) => (family_from_addr(&e.local_address), SockType::Datagram),
            NetEntry::Unix(e) => (AddressFamily::Unix, e.socket_type),
            NetEntry::Raw(e) => (family_from_addr(&e.local_address), SockType::Raw),
            NetEntry::Netlink(_) => (AddressFamily::Netlink, SockType::Datagram),
        };

        Socket {
            entry,
            family,
            sock_type,
            options,
            tcp_info,
            congestion_control,
            peer_pid,
            peer_comm,
        }
    }
}

/// Parse socket metadata from all `/proc/[pid]/net/*` files, returning a map
/// keyed by inode number.
pub(super) fn parse_socket_info(source: &dyn ProcSource) -> HashMap<u64, NetEntry> {
    use crate::model::auxv::ByteOrder;
    let mut sockets = HashMap::new();
    let is_le = source.byte_order() == ByteOrder::Little;
    let mut warned_permission = false;

    let mut try_read = |result: io::Result<_>| -> Option<_> {
        match result {
            Ok(reader) => Some(reader),
            Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied && !warned_permission => {
                warned_permission = true;
                eprintln!("could not read network socket information: permission denied");
                None
            }
            // Other errors (I/O, unexpected formats) are silently ignored.
            // Network files may not exist in all namespace configurations or
            // kernel versions, so missing files are expected and non-fatal.
            Err(_) => None,
        }
    };

    // Socket table data is namespace-scoped in procfs. Always read from
    // /proc/<target-pid>/net/* so inode->socket metadata resolution is done in
    // the target process's network namespace instead of our own.
    if let Some(reader) = try_read(source.read_net_file("unix")) {
        if let Ok(entries) = UnixNetEntries::from_buf_read(reader) {
            for entry in entries.0 {
                let inode = entry.inode;
                sockets.insert(inode, NetEntry::Unix(entry));
            }
        }
    }

    if let Some(reader) = try_read(source.read_net_file("netlink")) {
        if let Ok(entries) = NetlinkNetEntries::from_buf_read(reader) {
            for entry in entries.0 {
                let inode = entry.inode;
                sockets.insert(inode, NetEntry::Netlink(entry));
            }
        }
    }

    for &(filename, family) in &[("tcp", AddressFamily::Inet), ("tcp6", AddressFamily::Inet6)] {
        if let Some(reader) = try_read(source.read_net_file(filename)) {
            if let Ok(entries) = TcpNetEntries::from_buf_read(reader, family, is_le) {
                for entry in entries.0 {
                    let inode = entry.inode;
                    sockets.insert(inode, NetEntry::Tcp(entry));
                }
            }
        }
    }

    for &(filename, family) in &[("udp", AddressFamily::Inet), ("udp6", AddressFamily::Inet6)] {
        if let Some(reader) = try_read(source.read_net_file(filename)) {
            if let Ok(entries) = UdpNetEntries::from_buf_read(reader, family, is_le) {
                for entry in entries.0 {
                    let inode = entry.inode;
                    sockets.insert(inode, NetEntry::Udp(entry));
                }
            }
        }
    }

    for &(filename, family) in &[("raw", AddressFamily::Inet), ("raw6", AddressFamily::Inet6)] {
        if let Some(reader) = try_read(source.read_net_file(filename)) {
            if let Ok(entries) = RawNetEntries::from_buf_read(reader, family, is_le) {
                for entry in entries.0 {
                    let inode = entry.inode;
                    sockets.insert(inode, NetEntry::Raw(entry));
                }
            }
        }
    }

    sockets
}

pub(super) fn duplicate_target_fd(pid: u64, fd: u64) -> Option<OwnedFd> {
    let pid_i32 = i32::try_from(pid).ok()?;
    let fd_i32 = i32::try_from(fd).ok()?;

    let pidfd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid_i32, 0) };
    if pidfd < 0 {
        return None;
    }

    let duplicated = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_getfd, pidfd, fd_i32, 0) };
    let _ = unsafe { nix::libc::close(pidfd as i32) };

    if duplicated < 0 {
        return None;
    }

    Some(unsafe { OwnedFd::from_raw_fd(duplicated as i32) })
}

fn query_socket_options(sock_fd: &OwnedFd) -> SocketOptions {
    SocketOptions {
        reuse_addr: matches!(getsockopt(sock_fd, sockopt::ReuseAddr), Ok(true)),
        keep_alive: matches!(getsockopt(sock_fd, sockopt::KeepAlive), Ok(true)),
        broadcast: matches!(getsockopt(sock_fd, sockopt::Broadcast), Ok(true)),
        accept_conn: matches!(getsockopt(sock_fd, sockopt::AcceptConn), Ok(true)),
        oob_inline: matches!(getsockopt(sock_fd, sockopt::OobInline), Ok(true)),
        snd_buf: getsockopt(sock_fd, sockopt::SndBuf).ok(),
        rcv_buf: getsockopt(sock_fd, sockopt::RcvBuf).ok(),
    }
}

fn query_tcp_congestion_control(sock_fd: &OwnedFd) -> Option<String> {
    let mut buf = [0u8; 64];
    let mut len = buf.len() as nix::libc::socklen_t;
    let rc = unsafe {
        nix::libc::getsockopt(
            sock_fd.as_raw_fd(),
            nix::libc::IPPROTO_TCP,
            nix::libc::TCP_CONGESTION,
            buf.as_mut_ptr().cast::<nix::libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 || len == 0 {
        return None;
    }

    let len = len as usize;
    let end = buf[..len].iter().position(|&b| b == 0).unwrap_or(len);
    std::str::from_utf8(&buf[..end])
        .ok()
        .map(|name| name.to_string())
}

fn query_tcp_info(sock_fd: &OwnedFd) -> Option<nix::libc::tcp_info> {
    let mut info: nix::libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<nix::libc::tcp_info>() as nix::libc::socklen_t;
    let rc = unsafe {
        nix::libc::getsockopt(
            sock_fd.as_raw_fd(),
            nix::libc::IPPROTO_TCP,
            nix::libc::TCP_INFO,
            (&raw mut info).cast::<nix::libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(info)
}

/// Query socket details (options, TCP info, congestion control) for a file
/// descriptor belonging to a target process.
///
/// Duplicates the target fd via `pidfd_open`/`pidfd_getfd`, queries all
/// socket-level and TCP-level options, and returns the results bundled
/// in a [`SocketDetails`].
///
/// Returns `None` if the fd cannot be duplicated (e.g., coredumps,
/// insufficient privileges, or non-Linux platforms).
pub(super) fn query_socket_details(pid: u64, fd: u64) -> Option<SocketDetails> {
    let sock_fd = duplicate_target_fd(pid, fd)?;
    Some(SocketDetails {
        options: query_socket_options(&sock_fd),
        tcp_info: query_tcp_info(&sock_fd),
        congestion_control: query_tcp_congestion_control(&sock_fd),
    })
}

// -- Peer process resolution --------------------------------------------------

fn read_comm(pid: u64) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|comm| comm.trim_end().to_string())
}

fn list_socket_owners() -> HashMap<u64, std::collections::HashSet<u64>> {
    let mut owners = HashMap::<u64, std::collections::HashSet<u64>>::new();
    let proc_entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("failed to read /proc for socket ownership lookup: {e}");
            return owners;
        }
    };

    for entry in proc_entries.flatten() {
        let pid = match entry.file_name().to_string_lossy().parse::<u64>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fd_entries) = std::fs::read_dir(fd_dir) else {
            continue;
        };

        for fd_entry in fd_entries.flatten() {
            if let Some(inode) = std::fs::read_link(fd_entry.path())
                .ok()
                .and_then(|link| parse_socket_inode(&link.to_string_lossy()))
            {
                owners.entry(inode).or_default().insert(pid);
            }
        }
    }

    owners
}

fn local_tcp_peer_inodes(sockets: &HashMap<u64, NetEntry>) -> HashMap<u64, u64> {
    let tcp_entries: Vec<&crate::model::net::TcpNetEntry> = sockets
        .values()
        .filter_map(|entry| match entry {
            NetEntry::Tcp(e) => Some(e),
            _ => None,
        })
        .collect();

    let mut by_tuple = HashMap::<(SocketAddr, SocketAddr), Vec<u64>>::new();
    for e in &tcp_entries {
        if e.remote_address.ip().is_unspecified() {
            continue;
        }
        by_tuple
            .entry((e.local_address, e.remote_address))
            .or_default()
            .push(e.inode);
    }

    let mut peers = HashMap::new();
    for e in &tcp_entries {
        if e.remote_address.ip().is_unspecified() {
            continue;
        }
        if !(e.local_address.ip().is_loopback() && e.remote_address.ip().is_loopback()) {
            continue;
        }

        if let Some(candidates) = by_tuple.get(&(e.remote_address, e.local_address)) {
            if let Some(peer_inode) = candidates.iter().copied().find(|inode| *inode != e.inode) {
                peers.insert(e.inode, peer_inode);
            }
        }
    }
    peers
}

pub(super) fn has_loopback_tcp_peers(sockets: &HashMap<u64, NetEntry>) -> bool {
    sockets.values().any(|entry| {
        matches!(
            entry,
            NetEntry::Tcp(e)
                if e.local_address.ip().is_loopback()
                    && e.remote_address.ip().is_loopback()
        )
    })
}

pub(super) fn derive_peer_processes(
    target_pid: u64,
    sockets: &HashMap<u64, NetEntry>,
) -> HashMap<u64, (u64, String)> {
    let mut peers = HashMap::new();
    let owners = list_socket_owners();
    let mut comm_cache = HashMap::<u64, String>::new();

    for (inode, peer_inode) in local_tcp_peer_inodes(sockets) {
        let Some(pids) = owners.get(&peer_inode) else {
            continue;
        };

        let chosen_pid = pids
            .iter()
            .copied()
            .find(|pid| *pid != target_pid)
            .or_else(|| pids.iter().copied().next());
        let Some(chosen_pid) = chosen_pid else {
            continue;
        };

        let comm = if let Some(comm) = comm_cache.get(&chosen_pid) {
            comm.clone()
        } else {
            let Some(comm) = read_comm(chosen_pid) else {
                continue;
            };
            comm_cache.insert(chosen_pid, comm.clone());
            comm
        };

        peers.insert(inode, (chosen_pid, comm));
    }

    peers
}

pub(super) fn unix_peer_process(pid: u64, fd: u64) -> Option<(u64, String)> {
    let sock_fd = duplicate_target_fd(pid, fd)?;
    let creds = getsockopt(&sock_fd, sockopt::PeerCredentials).ok()?;
    let peer_pid = creds.pid() as u64;
    let comm = read_comm(peer_pid)?;
    Some((peer_pid, comm))
}

/// Read `system.sockprotoname` xattr from `/proc/[pid]/fd/[fd]`.
pub(super) fn get_sockprotoname(pid: u64, fd: u64) -> Option<String> {
    let path = std::ffi::CString::new(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let name = std::ffi::CString::new("system.sockprotoname").ok()?;

    let size =
        unsafe { nix::libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };

    if size < 0 {
        handle_sockprotoname_xattr_error(pid, fd);
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let filled = unsafe {
        nix::libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast::<nix::libc::c_void>(),
            buf.len(),
        )
    };
    if filled < 0 {
        handle_sockprotoname_xattr_error(pid, fd);
        return None;
    }

    buf.truncate(filled as usize);
    if buf.last() == Some(&0) {
        buf.pop();
    }

    if buf.is_empty() {
        return None;
    }

    String::from_utf8(buf).ok()
}

fn handle_sockprotoname_xattr_error(pid: u64, fd: u64) {
    use nix::errno::Errno;
    match Errno::last() {
        Errno::ENODATA | Errno::EOPNOTSUPP | Errno::ENOENT | Errno::EPERM | Errno::EACCES => {}
        errno => {
            eprintln!("failed to read system.sockprotoname xattr for /proc/{pid}/fd/{fd}: {errno}");
        }
    }
}
