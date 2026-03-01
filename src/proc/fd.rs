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

use std::path::PathBuf;

use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::socket::AddressFamily;
use nix::sys::stat::stat;
use nix::sys::stat::FileStat;
use nix::sys::stat::SFlag;

use super::net::Socket;

/// POSIX file type as identified by the `st_mode` bits from `stat(2)`.
#[derive(Debug, PartialEq)]
pub enum PosixFileType {
    Regular,
    Directory,
    Socket,
    SymLink,
    BlockDevice,
    CharDevice,
    Fifo,
    Unknown(u32),
}

/// Anonymous inode type parsed from `/proc/[pid]/fd/<fd>` symlink text.
#[derive(Debug, PartialEq)]
pub enum AnonFileType {
    Epoll,
    EventFd,
    SignalFd,
    TimerFd,
    Inotify,
    PidFd,
    Unknown(String),
}

/// Unified file type combining POSIX stat-derived types and Linux anonymous
/// inode types.
#[derive(Debug, PartialEq)]
pub enum FileType {
    Posix(PosixFileType),
    Anon(AnonFileType),
    Unknown,
}

/// Fully-populated file descriptor information gathered from the library.
///
/// Produced by [`ProcHandle::file_descriptors()`](super::ProcHandle::file_descriptors).
pub struct FileDescriptor {
    pub fd: u64,
    pub path: PathBuf,
    pub file_type: FileType,
    pub stat: Option<FileStat>,
    pub offset: u64,
    pub open_flags: OFlag,
    pub mnt_id: Option<u64>,
    pub extra_lines: Vec<String>,
    pub socket: Option<Socket>,
    pub sockprotoname: Option<String>,
}

/// Classify a file from its `stat(2)` mode bits and the symlink text from
/// `/proc/[pid]/fd/<fd>`.
///
/// When the mode bits identify a concrete POSIX type, that is returned.
/// When the mode bits are zero (as for anonymous inodes), the link text
/// is examined for `anon_inode:` patterns.
pub(crate) fn file_type_from_stat(mode: u32, link_text: &str) -> FileType {
    let masked = mode & SFlag::S_IFMT.bits();
    if masked != 0 {
        let posix = match SFlag::from_bits_truncate(masked) {
            SFlag::S_IFSOCK => PosixFileType::Socket,
            SFlag::S_IFLNK => PosixFileType::SymLink,
            SFlag::S_IFREG => PosixFileType::Regular,
            SFlag::S_IFBLK => PosixFileType::BlockDevice,
            SFlag::S_IFDIR => PosixFileType::Directory,
            SFlag::S_IFCHR => PosixFileType::CharDevice,
            SFlag::S_IFIFO => PosixFileType::Fifo,
            _ => PosixFileType::Unknown(masked),
        };
        FileType::Posix(posix)
    } else {
        file_type_from_link(link_text)
    }
}

/// Classify a file from the symlink text alone (used when `stat()` is
/// unavailable, e.g. coredumps).
pub(crate) fn file_type_from_link(link_text: &str) -> FileType {
    if link_text.starts_with("anon_inode:") {
        let fd_type_str = link_text
            .trim_start_matches("anon_inode:")
            .trim_start_matches('[')
            .trim_end_matches(']');
        let anon = match fd_type_str {
            "eventpoll" => AnonFileType::Epoll,
            "eventfd" => AnonFileType::EventFd,
            "signalfd" => AnonFileType::SignalFd,
            "timerfd" => AnonFileType::TimerFd,
            "inotify" => AnonFileType::Inotify,
            "pidfd" => AnonFileType::PidFd,
            x => AnonFileType::Unknown(x.to_string()),
        };
        FileType::Anon(anon)
    } else {
        FileType::Unknown
    }
}

/// Extract the inode number from a `"socket:[12345]"` link text.
pub(crate) fn parse_socket_inode(link_text: &str) -> Option<u64> {
    let inner = link_text.strip_prefix("socket:[")?;
    let inner = inner.strip_suffix(']')?;
    inner.parse::<u64>().ok()
}

/// Read `system.sockprotoname` xattr from `/proc/[pid]/fd/[fd]`.
pub(crate) fn get_sockprotoname(pid: u64, fd: u64, warnings: &mut Vec<String>) -> Option<String> {
    let path = std::ffi::CString::new(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let name = std::ffi::CString::new("system.sockprotoname").ok()?;

    let size =
        unsafe { nix::libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };

    if size < 0 {
        warnings.extend(handle_sockprotoname_xattr_error(pid, fd));
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
        warnings.extend(handle_sockprotoname_xattr_error(pid, fd));
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

fn handle_sockprotoname_xattr_error(pid: u64, fd: u64) -> Option<String> {
    match Errno::last() {
        Errno::ENODATA | Errno::EOPNOTSUPP | Errno::ENOENT | Errno::EPERM | Errno::EACCES => None,
        errno => Some(format!(
            "failed to read system.sockprotoname xattr for /proc/{pid}/fd/{fd}: {errno}"
        )),
    }
}

/// Map a `system.sockprotoname` value to an `AddressFamily`.
pub fn address_family_from_sockprotoname(
    sockprotoname: &str,
) -> Option<nix::sys::socket::AddressFamily> {
    let name = sockprotoname.strip_prefix("AF_").unwrap_or(sockprotoname);
    Some(match name {
        "UNIX" | "UNIX-STREAM" => AddressFamily::Unix,
        "TCP" | "UDP" | "RAW" | "PING" | "MPTCP" | "L2TP/IP" => AddressFamily::Inet,
        "TCPv6" | "UDPv6" | "RAWv6" | "SCTPv6" | "SMC6" | "L2TP/IPv6" => AddressFamily::Inet6,
        "SCTP" | "SMC" => AddressFamily::Inet,
        "NETLINK" => AddressFamily::Netlink,
        "PACKET" => AddressFamily::Packet,
        "ALG" => AddressFamily::Alg,
        "XDP" => AddressFamily::Packet,
        "ROSE" => AddressFamily::Rose,
        _ => return None,
    })
}

/// Call `stat(2)` on `/proc/[pid]/fd/[fd]`.
pub(crate) fn stat_fd(pid: u64, fd: u64) -> std::io::Result<FileStat> {
    let path = format!("/proc/{pid}/fd/{fd}");
    stat(path.as_str()).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use nix::sys::stat::SFlag;

    use super::*;

    #[test]
    fn test_file_type_from_stat_regular() {
        let ft = file_type_from_stat(SFlag::S_IFREG.bits(), "/dev/null");
        assert_eq!(ft, FileType::Posix(PosixFileType::Regular));
    }

    #[test]
    fn test_file_type_from_stat_socket() {
        let ft = file_type_from_stat(SFlag::S_IFSOCK.bits(), "socket:[123]");
        assert_eq!(ft, FileType::Posix(PosixFileType::Socket));
    }

    #[test]
    fn test_file_type_from_stat_block_device() {
        let ft = file_type_from_stat(SFlag::S_IFBLK.bits(), "/dev/sda");
        assert_eq!(ft, FileType::Posix(PosixFileType::BlockDevice));
    }

    #[test]
    fn test_file_type_from_stat_char_device() {
        let ft = file_type_from_stat(SFlag::S_IFCHR.bits(), "/dev/null");
        assert_eq!(ft, FileType::Posix(PosixFileType::CharDevice));
    }

    #[test]
    fn test_file_type_from_stat_directory() {
        let ft = file_type_from_stat(SFlag::S_IFDIR.bits(), "/tmp");
        assert_eq!(ft, FileType::Posix(PosixFileType::Directory));
    }

    #[test]
    fn test_file_type_from_stat_symlink() {
        let ft = file_type_from_stat(SFlag::S_IFLNK.bits(), "/some/link");
        assert_eq!(ft, FileType::Posix(PosixFileType::SymLink));
    }

    #[test]
    fn test_file_type_from_stat_fifo() {
        let ft = file_type_from_stat(SFlag::S_IFIFO.bits(), "/tmp/pipe");
        assert_eq!(ft, FileType::Posix(PosixFileType::Fifo));
    }

    #[test]
    fn test_file_type_from_stat_anon_inode_fallback() {
        let ft = file_type_from_stat(0, "anon_inode:[eventpoll]");
        assert_eq!(ft, FileType::Anon(AnonFileType::Epoll));
    }

    #[test]
    fn test_file_type_from_link_eventpoll() {
        let ft = file_type_from_link("anon_inode:[eventpoll]");
        assert_eq!(ft, FileType::Anon(AnonFileType::Epoll));
    }

    #[test]
    fn test_file_type_from_link_inotify_no_brackets() {
        let ft = file_type_from_link("anon_inode:inotify");
        assert_eq!(ft, FileType::Anon(AnonFileType::Inotify));
    }

    #[test]
    fn test_file_type_from_link_eventfd() {
        let ft = file_type_from_link("anon_inode:[eventfd]");
        assert_eq!(ft, FileType::Anon(AnonFileType::EventFd));
    }

    #[test]
    fn test_file_type_from_link_signalfd() {
        let ft = file_type_from_link("anon_inode:[signalfd]");
        assert_eq!(ft, FileType::Anon(AnonFileType::SignalFd));
    }

    #[test]
    fn test_file_type_from_link_timerfd() {
        let ft = file_type_from_link("anon_inode:[timerfd]");
        assert_eq!(ft, FileType::Anon(AnonFileType::TimerFd));
    }

    #[test]
    fn test_file_type_from_link_pidfd() {
        let ft = file_type_from_link("anon_inode:[pidfd]");
        assert_eq!(ft, FileType::Anon(AnonFileType::PidFd));
    }

    #[test]
    fn test_file_type_from_link_unknown_anon() {
        let ft = file_type_from_link("anon_inode:[io_uring]");
        assert_eq!(
            ft,
            FileType::Anon(AnonFileType::Unknown("io_uring".to_string()))
        );
    }

    #[test]
    fn test_file_type_from_link_socket() {
        let ft = file_type_from_link("socket:[123]");
        assert_eq!(ft, FileType::Unknown);
    }

    #[test]
    fn test_file_type_from_link_regular_path() {
        let ft = file_type_from_link("/dev/null");
        assert_eq!(ft, FileType::Unknown);
    }

    #[test]
    fn test_parse_socket_inode_valid() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
    }

    #[test]
    fn test_parse_socket_inode_not_socket() {
        assert_eq!(parse_socket_inode("/dev/null"), None);
    }

    #[test]
    fn test_parse_socket_inode_anon() {
        assert_eq!(parse_socket_inode("anon_inode:[eventpoll]"), None);
    }

    #[test]
    fn test_address_family_from_sockprotoname_known() {
        use nix::sys::socket::AddressFamily;
        assert_eq!(
            address_family_from_sockprotoname("TCP"),
            Some(AddressFamily::Inet)
        );
        assert_eq!(
            address_family_from_sockprotoname("TCPv6"),
            Some(AddressFamily::Inet6)
        );
        assert_eq!(
            address_family_from_sockprotoname("UNIX"),
            Some(AddressFamily::Unix)
        );
        assert_eq!(
            address_family_from_sockprotoname("NETLINK"),
            Some(AddressFamily::Netlink)
        );
        assert_eq!(
            address_family_from_sockprotoname("ALG"),
            Some(AddressFamily::Alg)
        );
        assert_eq!(
            address_family_from_sockprotoname("AF_ALG"),
            Some(AddressFamily::Alg)
        );
    }

    #[test]
    fn test_address_family_from_sockprotoname_unknown() {
        assert_eq!(address_family_from_sockprotoname("SOMETHING_UNKNOWN"), None);
    }
}
