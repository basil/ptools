use nix::fcntl::OFlag;
use nix::sys::stat::SFlag;
use std::fmt;
use std::path::PathBuf;

use super::net::{SocketDetails, SocketInfo};

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

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileType::Posix(PosixFileType::Regular) => write!(f, "S_IFREG"),
            FileType::Posix(PosixFileType::Directory) => write!(f, "S_IFDIR"),
            FileType::Posix(PosixFileType::Socket) => write!(f, "S_IFSOCK"),
            FileType::Posix(PosixFileType::SymLink) => write!(f, "S_IFLNK"),
            FileType::Posix(PosixFileType::BlockDevice) => write!(f, "S_IFBLK"),
            FileType::Posix(PosixFileType::CharDevice) => write!(f, "S_IFCHR"),
            FileType::Posix(PosixFileType::Fifo) => write!(f, "S_IFIFO"),
            FileType::Posix(PosixFileType::Unknown(x)) => {
                write!(f, "UNKNOWN_TYPE(mode={})", x)
            }
            FileType::Anon(AnonFileType::Epoll) => write!(f, "anon_inode(epoll)"),
            FileType::Anon(AnonFileType::EventFd) => write!(f, "anon_inode(eventfd)"),
            FileType::Anon(AnonFileType::SignalFd) => write!(f, "anon_inode(signalfd)"),
            FileType::Anon(AnonFileType::TimerFd) => write!(f, "anon_inode(timerfd)"),
            FileType::Anon(AnonFileType::Inotify) => write!(f, "anon_inode(inotify)"),
            FileType::Anon(AnonFileType::PidFd) => write!(f, "anon_inode(pidfd)"),
            FileType::Anon(AnonFileType::Unknown(s)) => write!(f, "anon_inode({})", s),
            FileType::Unknown => write!(f, "UNKNOWN_TYPE"),
        }
    }
}

/// Open-file flags wrapper with Display formatting.
pub struct OpenFlags(pub OFlag);

const FLAG_NAMES: &[(OFlag, &str)] = &[
    (OFlag::O_APPEND, "O_APPEND"),
    (OFlag::O_ASYNC, "O_ASYNC"),
    (OFlag::O_CLOEXEC, "O_CLOEXEC"),
    (OFlag::O_CREAT, "O_CREAT"),
    (OFlag::O_DIRECT, "O_DIRECT"),
    (OFlag::O_DIRECTORY, "O_DIRECTORY"),
    (OFlag::O_DSYNC, "O_DSYNC"),
    (OFlag::O_EXCL, "O_EXCL"),
    (OFlag::O_NOATIME, "O_NOATIME"),
    (OFlag::O_NOCTTY, "O_NOCTTY"),
    (OFlag::O_NOFOLLOW, "O_NOFOLLOW"),
    (OFlag::O_NONBLOCK, "O_NONBLOCK"),
    (OFlag::O_PATH, "O_PATH"),
    (OFlag::O_SYNC, "O_SYNC"),
    (OFlag::O_TMPFILE, "O_TMPFILE"),
    (OFlag::O_TRUNC, "O_TRUNC"),
];

impl OpenFlags {
    /// Return the access-mode portion as a string.
    pub fn access_mode_str(&self) -> &'static str {
        match self.0 & OFlag::O_ACCMODE {
            OFlag::O_RDONLY => "O_RDONLY",
            OFlag::O_WRONLY => "O_WRONLY",
            OFlag::O_RDWR => "O_RDWR",
            _ => "O_ACCMODE(?)",
        }
    }
}

impl fmt::Display for OpenFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.access_mode_str())?;
        for &(flag, desc) in FLAG_NAMES {
            if self.0.contains(flag) {
                write!(f, "|{}", desc)?;
            }
        }
        Ok(())
    }
}

/// Stat information for a file descriptor, gathered from `stat(2)` on
/// `/proc/[pid]/fd/<fd>`.
pub struct FdStat {
    pub mode: u32,
    pub dev_major: u64,
    pub dev_minor: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
    pub rdev_major: u64,
    pub rdev_minor: u64,
}

/// Socket metadata bundled for a file descriptor.
pub struct FdSocket {
    pub info: SocketInfo,
    pub details: Option<SocketDetails>,
}

/// Fully-populated file descriptor information gathered from the library.
///
/// Produced by [`ProcHandle::file_descriptors()`](super::ProcHandle::file_descriptors).
pub struct FileDescriptor {
    pub fd: u64,
    pub path: PathBuf,
    pub file_type: FileType,
    pub stat: Option<FdStat>,
    pub offset: u64,
    pub open_flags: OpenFlags,
    pub mnt_id: Option<u64>,
    pub extra_lines: Vec<String>,
    pub socket: Option<FdSocket>,
    pub sockprotoname: Option<String>,
}

/// Classify a file from its `stat(2)` mode bits and the symlink text from
/// `/proc/[pid]/fd/<fd>`.
///
/// When the mode bits identify a concrete POSIX type, that is returned.
/// When the mode bits are zero (as for anonymous inodes), the link text
/// is examined for `anon_inode:` patterns.
pub fn file_type_from_stat(mode: u32, link_text: &str) -> FileType {
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
pub fn file_type_from_link(link_text: &str) -> FileType {
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
pub fn parse_socket_inode(link_text: &str) -> Option<u64> {
    let inner = link_text.strip_prefix("socket:[")?;
    let inner = inner.strip_suffix(']')?;
    inner.parse::<u64>().ok()
}

/// Read `system.sockprotoname` xattr from `/proc/[pid]/fd/[fd]`.
pub(crate) fn get_sockprotoname(pid: u64, fd: u64) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let path = std::ffi::CString::new(format!("/proc/{}/fd/{}", pid, fd)).ok()?;
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

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, fd);
        None
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn handle_sockprotoname_xattr_error(pid: u64, fd: u64) {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(nix::libc::ENODATA)
        | Some(nix::libc::EOPNOTSUPP)
        | Some(nix::libc::ENOENT)
        | Some(nix::libc::EPERM)
        | Some(nix::libc::EACCES) => {}
        Some(errno) => eprintln!(
            "failed to read system.sockprotoname xattr for /proc/{}/fd/{}: errno {}",
            pid, fd, errno
        ),
        None => eprintln!(
            "failed to read system.sockprotoname xattr for /proc/{}/fd/{}",
            pid, fd
        ),
    }
}

/// Map a `system.sockprotoname` value to an `AddressFamily`.
pub fn address_family_from_sockprotoname(
    sockprotoname: &str,
) -> Option<nix::sys::socket::AddressFamily> {
    use nix::sys::socket::AddressFamily;
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

/// Call `stat(2)` on `/proc/[pid]/fd/[fd]` and wrap the result in an `FdStat`.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn stat_fd(pid: u64, fd: u64) -> Result<FdStat, std::io::Error> {
    use nix::sys::stat::{major, minor, stat};

    let path = format!("/proc/{}/fd/{}", pid, fd);
    let info = stat(path.as_str())?;
    Ok(FdStat {
        mode: info.st_mode,
        dev_major: major(info.st_dev),
        dev_minor: minor(info.st_dev),
        inode: info.st_ino as u64,
        uid: info.st_uid,
        gid: info.st_gid,
        size: info.st_size,
        rdev_major: major(info.st_rdev),
        rdev_minor: minor(info.st_rdev),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::stat::SFlag;

    #[test]
    fn test_file_type_from_stat_regular() {
        let ft = file_type_from_stat(SFlag::S_IFREG.bits(), "/dev/null");
        assert_eq!(ft, FileType::Posix(PosixFileType::Regular));
        assert_eq!(ft.to_string(), "S_IFREG");
    }

    #[test]
    fn test_file_type_from_stat_socket() {
        let ft = file_type_from_stat(SFlag::S_IFSOCK.bits(), "socket:[123]");
        assert_eq!(ft, FileType::Posix(PosixFileType::Socket));
        assert_eq!(ft.to_string(), "S_IFSOCK");
    }

    #[test]
    fn test_file_type_from_stat_block_device() {
        let ft = file_type_from_stat(SFlag::S_IFBLK.bits(), "/dev/sda");
        assert_eq!(ft, FileType::Posix(PosixFileType::BlockDevice));
        assert_eq!(ft.to_string(), "S_IFBLK");
    }

    #[test]
    fn test_file_type_from_stat_char_device() {
        let ft = file_type_from_stat(SFlag::S_IFCHR.bits(), "/dev/null");
        assert_eq!(ft, FileType::Posix(PosixFileType::CharDevice));
        assert_eq!(ft.to_string(), "S_IFCHR");
    }

    #[test]
    fn test_file_type_from_stat_directory() {
        let ft = file_type_from_stat(SFlag::S_IFDIR.bits(), "/tmp");
        assert_eq!(ft, FileType::Posix(PosixFileType::Directory));
        assert_eq!(ft.to_string(), "S_IFDIR");
    }

    #[test]
    fn test_file_type_from_stat_symlink() {
        let ft = file_type_from_stat(SFlag::S_IFLNK.bits(), "/some/link");
        assert_eq!(ft, FileType::Posix(PosixFileType::SymLink));
        assert_eq!(ft.to_string(), "S_IFLNK");
    }

    #[test]
    fn test_file_type_from_stat_fifo() {
        let ft = file_type_from_stat(SFlag::S_IFIFO.bits(), "/tmp/pipe");
        assert_eq!(ft, FileType::Posix(PosixFileType::Fifo));
        assert_eq!(ft.to_string(), "S_IFIFO");
    }

    #[test]
    fn test_file_type_from_stat_anon_inode_fallback() {
        let ft = file_type_from_stat(0, "anon_inode:[eventpoll]");
        assert_eq!(ft, FileType::Anon(AnonFileType::Epoll));
        assert_eq!(ft.to_string(), "anon_inode(epoll)");
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
        assert_eq!(ft.to_string(), "anon_inode(eventfd)");
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
        assert_eq!(ft.to_string(), "anon_inode(io_uring)");
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
    fn test_open_flags_display_rdonly() {
        let flags = OpenFlags(OFlag::O_RDONLY);
        assert_eq!(flags.to_string(), "O_RDONLY");
    }

    #[test]
    fn test_open_flags_display_rdonly_cloexec() {
        let flags = OpenFlags(OFlag::O_RDONLY | OFlag::O_CLOEXEC);
        assert_eq!(flags.to_string(), "O_RDONLY|O_CLOEXEC");
    }

    #[test]
    fn test_open_flags_display_rdwr_nonblock() {
        let flags = OpenFlags(OFlag::O_RDWR | OFlag::O_NONBLOCK);
        assert_eq!(flags.to_string(), "O_RDWR|O_NONBLOCK");
    }

    #[test]
    fn test_open_flags_display_wronly_append_sync() {
        // O_SYNC includes O_DSYNC bits on Linux, so both flags appear.
        let flags = OpenFlags(OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_SYNC);
        assert_eq!(flags.to_string(), "O_WRONLY|O_APPEND|O_DSYNC|O_SYNC");
    }

    #[test]
    fn test_file_type_unknown_display() {
        assert_eq!(FileType::Unknown.to_string(), "UNKNOWN_TYPE");
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
