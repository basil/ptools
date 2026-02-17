//
//   Copyright 2018 Delphix
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

use clap::{command, value_parser, Arg, ArgAction};
use nix::fcntl::OFlag;
use nix::sys::socket::{getsockopt, sockopt, AddressFamily};
use nix::sys::stat::{major, minor, stat, SFlag};
use ptools::ParseError;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::ParseIntError;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::exit;

#[derive(Clone)]
struct PeerProcess {
    pid: u64,
    comm: String,
}

// TODO Handle remaining anonymous inode types:
// - anon_inode:[io_uring]
// - anon_inode:[userfaultfd]
// - anon_inode:[fanotify]
// - anon_inode:[perf_event], BPF, etc.

// As defined by the file type bits of the st_mode field returned by stat
#[derive(PartialEq)]
enum PosixFileType {
    Regular,
    Directory,
    Socket,
    SymLink,
    BlockDevice,
    CharDevice,
    Fifo,
    Unknown(u32),
}

// For descriptors where stat(2) cannot identify a concrete POSIX file type, Linux may expose
// anonymous inode metadata via /proc/[pid]/fd/<fd> symlink text like "anon_inode:[eventpoll]".
#[derive(PartialEq)]
enum AnonFileType {
    Epoll,
    EventFd,
    SignalFd,
    TimerFd,
    Inotify,
    PidFd,
    Unknown(String),
}

#[derive(PartialEq)]
enum FileType {
    Posix(PosixFileType),
    Anon(AnonFileType),
    Unknown,
}

// We define our own enum rather than using the one from nix so that we can include additional
// types defined by the linux kernel but not by nix.
#[derive(Copy, Clone)]
enum SockType {
    Stream,
    Datagram,
    Raw,
    Rdm,
    SeqPacket,
    Dccp,
    Packet,
    Unknown(u16),
}

#[derive(Copy, Clone)]
enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynRecv,
    Unknown(u8),
}

// Some common types of files have their type described by the st_mode returned by stat. For certain
// types of files, though, st_mode is zero. In this case we can try to get more info from the text
// in /proc/[pid]/fd/[fd]
fn file_type(mode: u32, link_path: &Path) -> FileType {
    let mode = mode & SFlag::S_IFMT.bits();
    if mode != 0 {
        let posix_file_type = match SFlag::from_bits_truncate(mode) {
            SFlag::S_IFSOCK => PosixFileType::Socket,
            SFlag::S_IFLNK => PosixFileType::SymLink,
            SFlag::S_IFREG => PosixFileType::Regular,
            SFlag::S_IFBLK => PosixFileType::BlockDevice,
            SFlag::S_IFDIR => PosixFileType::Directory,
            SFlag::S_IFCHR => PosixFileType::CharDevice,
            SFlag::S_IFIFO => PosixFileType::Fifo,
            _ => PosixFileType::Unknown(mode),
        };
        FileType::Posix(posix_file_type)
    } else {
        // Symlinks normally contain name of another file, but the contents of /proc/[pid]/fd/[fd]
        // is in this case just text. fs::read_link converts this arbitrary text to a path, and then
        // we convert it back to a String here. We are assuming this conversion is lossless.
        let faux_path = match fs::read_link(link_path) {
            Ok(faux_path) => faux_path,
            Err(e) => {
                eprintln!("Failed to read {:?}: {}", link_path, e);
                return FileType::Unknown;
            }
        };
        let fd_info = match faux_path.to_str() {
            Some(fd_info) => fd_info,
            None => {
                eprintln!("Failed to convert path to string: {:?}", faux_path);
                return FileType::Unknown;
            }
        };
        // For anonymous inodes, this text has the format 'anon_inode:[<type>]' or
        // 'anon_inode:<type>'.
        if fd_info.starts_with("anon_inode:") {
            let fd_type_str = fd_info
                .trim_start_matches("anon_inode:")
                .trim_start_matches("[")
                .trim_end_matches("]");
            let anon_file_type = match fd_type_str {
                "eventpoll" => AnonFileType::Epoll,
                "eventfd" => AnonFileType::EventFd,
                "signalfd" => AnonFileType::SignalFd,
                "timerfd" => AnonFileType::TimerFd,
                "inotify" => AnonFileType::Inotify,
                "pidfd" => AnonFileType::PidFd,
                x => AnonFileType::Unknown(x.to_string()),
            };
            FileType::Anon(anon_file_type)
        } else {
            FileType::Unknown
        }
    }
}

fn print_file_type(file_type: &FileType) -> String {
    match file_type {
        // TODO For now we print the Posix file types using the somewhat cryptic macro identifiers used
        // by the st_mode field returned by stat to match what is printed on Solaris. However, given
        // that we already have more file types than we do on Solaris (because of Linux specific
        // things like epoll, for example), and given that these additional file types can't be
        // printed using S_ names (since they don't exist for these file types, since they aren't
        // understood by stat), we are printing names that are sort of inconsistent. Maybe we should
        // just be consistent, print better names, and just break compatibility with Solaris pfiles.
        FileType::Posix(PosixFileType::Regular) => "S_IFREG".into(),
        FileType::Posix(PosixFileType::Directory) => "S_IFDIR".into(),
        FileType::Posix(PosixFileType::Socket) => "S_IFSOCK".into(),
        FileType::Posix(PosixFileType::SymLink) => "S_IFLNK".into(),
        FileType::Posix(PosixFileType::BlockDevice) => "S_IFBLK".into(),
        FileType::Posix(PosixFileType::CharDevice) => "S_IFCHR".into(),
        FileType::Posix(PosixFileType::Fifo) => "S_IFIFO".into(),
        FileType::Posix(PosixFileType::Unknown(x)) => format!("UNKNOWN_TYPE(mode={})", x),
        FileType::Anon(AnonFileType::Epoll) => "anon_inode(epoll)".into(),
        FileType::Anon(AnonFileType::EventFd) => "anon_inode(eventfd)".into(),
        FileType::Anon(AnonFileType::SignalFd) => "anon_inode(signalfd)".into(),
        FileType::Anon(AnonFileType::TimerFd) => "anon_inode(timerfd)".into(),
        FileType::Anon(AnonFileType::Inotify) => "anon_inode(inotify)".into(),
        FileType::Anon(AnonFileType::PidFd) => "anon_inode(pidfd)".into(),
        FileType::Anon(AnonFileType::Unknown(s)) => format!("anon_inode({})", s),
        FileType::Unknown => "UNKNOWN_TYPE".into(),
    }
}

fn print_matching_fdinfo_lines(pid: u64, fd: u64, prefixes: &[&str]) {
    let fdinfo_path = format!("/proc/{}/fdinfo/{}", pid, fd);
    let fdinfo = match fs::read_to_string(&fdinfo_path) {
        Ok(fdinfo) => fdinfo,
        Err(e) => {
            eprintln!("failed to read {}: {}", &fdinfo_path, e);
            return;
        }
    };

    for line in fdinfo
        .lines()
        .filter(|line| prefixes.iter().any(|prefix| line.starts_with(prefix)))
    {
        println!("       {}", line);
    }
}

fn print_open_flags(flags: u64) {
    let open_flags = [
        (OFlag::O_APPEND, "O_APPEND"),
        (OFlag::O_ASYNC, "O_ASYNC"),
        (OFlag::O_CLOEXEC, "O_CLOEXEC"),
        (OFlag::O_CREAT, "O_CREAT"),
        (OFlag::O_DIRECT, "O_DIRECT"),
        (OFlag::O_DIRECTORY, "O_DIRECTORY"),
        (OFlag::O_DSYNC, "O_DSYNC"),
        (OFlag::O_EXCL, "O_EXCL"),
        (OFlag::O_LARGEFILE, "O_LARGEFILE"),
        (OFlag::O_NOATIME, "O_NOATIME"),
        (OFlag::O_NOCTTY, "O_NOCTTY"),
        (OFlag::O_NOFOLLOW, "O_NOFOLLOW"),
        (OFlag::O_NONBLOCK, "O_NONBLOCK"),
        (OFlag::O_PATH, "O_PATH"),
        (OFlag::O_SYNC, "O_SYNC"),
        (OFlag::O_TMPFILE, "O_TMPFILE"),
        (OFlag::O_TRUNC, "O_TRUNC"),
    ];

    print!(
        "{}",
        match OFlag::from_bits_truncate(flags as i32 & OFlag::O_ACCMODE.bits()) {
            OFlag::O_RDONLY => "O_RDONLY".to_string(),
            OFlag::O_WRONLY => "O_WRONLY".to_string(),
            OFlag::O_RDWR => "O_RDWR".to_string(),
            _ => format!("Unexpected mode {:o}", flags),
        }
    );

    // O_LARGEFILE == 0. Should that get printed everywhere?
    // probably yes, if we want to match illumos

    let raw_flags = flags as i32;
    for &(flag, desc) in open_flags.iter() {
        let bits = flag.bits();
        if bits != 0 && (raw_flags & bits) == bits {
            print!("|{}", desc);
        }
    }

    // illumos prints close-on-exec separately because it is a descriptor flag (FD_CLOEXEC via
    // fcntl(F_GETFD)), not an open-file status flag (F_GETFL). Linux exposes the CLOEXEC bit in
    // /proc/[pid]/fdinfo flags, so we keep it in this compact flag list.

    print!("\n");
}

fn get_fdinfo_field(pid: u64, fd: u64, field: &str) -> Result<String, Box<dyn Error>> {
    let mut contents = String::new();
    File::open(format!("/proc/{}/fdinfo/{}", pid, fd))?.read_to_string(&mut contents)?;
    let line = contents
        .lines()
        .filter(|line| line.starts_with(&format!("{}:", field)))
        .collect::<Vec<&str>>()
        .pop()
        .ok_or(ParseError::in_file(
            "fdinfo",
            &format!("no value '{}'", field),
        ))?;

    let (_, value) = line.split_once(':').ok_or(ParseError::in_file(
        "fdinfo",
        &format!("unexpected format for '{}': {}", field, line),
    ))?;

    Ok(value.trim().to_string())
}

fn get_flags(pid: u64, fd: u64) -> Result<u64, Box<dyn Error>> {
    let str_flags = get_fdinfo_field(pid, fd, "flags")?;
    Ok(u64::from_str_radix(str_flags.trim(), 8)?)
}

fn get_offset(pid: u64, fd: u64) -> Result<u64, Box<dyn Error>> {
    let str_offset = get_fdinfo_field(pid, fd, "pos")?;
    Ok(str_offset.parse::<u64>()?)
}

fn get_sockprotoname(pid: u64, fd: u64) -> Option<String> {
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

        return String::from_utf8(buf).ok();
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, fd);
        None
    }
}

fn address_family_from_sockprotoname(sockprotoname: &str) -> Option<AddressFamily> {
    let name = sockprotoname.strip_prefix("AF_").unwrap_or(sockprotoname);
    Some(match name {
        // Kernel proto names (sk_prot_creator->name), not AF_* family names.
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

fn sockname_from_sockprotoname(sockprotoname: &str) -> String {
    if let Some(addr_fam) = address_family_from_sockprotoname(sockprotoname) {
        address_family_str(addr_fam).to_string()
    } else {
        sockprotoname.to_string()
    }
}

#[cfg(target_os = "linux")]
fn handle_sockprotoname_xattr_error(pid: u64, fd: u64) {
    match std::io::Error::last_os_error().raw_os_error() {
        // Missing xattr or unsupported xattr for this procfs entry.
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

struct SockInfo {
    family: AddressFamily,
    sock_type: SockType,
    inode: u64,
    local_addr: Option<SocketAddr>, // Doesn't apply to unix sockets
    peer_addr: Option<SocketAddr>,  // Doesn't apply to unix sockets
    peer_pid: Option<u64>,          // If the peer is another process on this system
    tcp_state: Option<TcpState>,    // TCP only
}

fn print_sock_type(sock_type: &SockType) {
    println!(
        "         {}",
        match sock_type {
            SockType::Stream => "SOCK_STREAM".into(),
            SockType::Datagram => "SOCK_DGRAM".into(),
            SockType::Raw => "SOCK_RAW".into(),
            SockType::Rdm => "SOCK_RDM".into(),
            SockType::SeqPacket => "SOCK_SEQPACKET".into(),
            SockType::Dccp => "SOCK_DCCP".into(),
            SockType::Packet => "SOCK_PACKET".into(),
            SockType::Unknown(n) => format!("SOCK_TYPE_UNKNOWN_{}", n),
        }
    )
}

#[cfg(target_os = "linux")]
fn duplicate_target_fd(pid: u64, fd: u64) -> Option<OwnedFd> {
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

#[cfg(not(target_os = "linux"))]
fn duplicate_target_fd(_pid: u64, _fd: u64) -> Option<OwnedFd> {
    None
}

fn socket_options(pid: u64, fd: u64) -> Vec<String> {
    let Some(duplicated_fd) = duplicate_target_fd(pid, fd) else {
        return Vec::new();
    };

    let mut options = Vec::new();

    if matches!(getsockopt(&duplicated_fd, sockopt::AcceptConn), Ok(true)) {
        options.push("SO_ACCEPTCONN".to_string());
    }
    if matches!(getsockopt(&duplicated_fd, sockopt::Broadcast), Ok(true)) {
        options.push("SO_BROADCAST".to_string());
    }
    if matches!(getsockopt(&duplicated_fd, sockopt::KeepAlive), Ok(true)) {
        options.push("SO_KEEPALIVE".to_string());
    }
    if matches!(getsockopt(&duplicated_fd, sockopt::ReuseAddr), Ok(true)) {
        options.push("SO_REUSEADDR".to_string());
    }
    if matches!(getsockopt(&duplicated_fd, sockopt::OobInline), Ok(true)) {
        options.push("SO_OOBINLINE".to_string());
    }

    if let Ok(sndbuf) = getsockopt(&duplicated_fd, sockopt::SndBuf) {
        options.push(format!("SO_SNDBUF({})", sndbuf));
    }
    if let Ok(rcvbuf) = getsockopt(&duplicated_fd, sockopt::RcvBuf) {
        options.push(format!("SO_RCVBUF({})", rcvbuf));
    }

    options
}

fn print_socket_options(pid: u64, fd: u64) {
    let options = socket_options(pid, fd);
    if !options.is_empty() {
        println!("         {}", options.join(","));
    }
}

fn tcp_congestion_control(pid: u64, fd: u64) -> Option<String> {
    let duplicated_fd = duplicate_target_fd(pid, fd)?;
    let mut buf = [0u8; 64];
    let mut len = buf.len() as nix::libc::socklen_t;
    let rc = unsafe {
        nix::libc::getsockopt(
            duplicated_fd.as_raw_fd(),
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

fn address_family_str(addr_fam: AddressFamily) -> &'static str {
    match addr_fam {
        AddressFamily::Unix => "AF_UNIX",
        AddressFamily::Inet => "AF_INET",
        AddressFamily::Inet6 => "AF_INET6",
        AddressFamily::Netlink => "AF_NETLINK",
        AddressFamily::Packet => "AF_PACKET",
        AddressFamily::Ipx => "AF_IPX",
        AddressFamily::X25 => "AF_X25",
        AddressFamily::Ax25 => "AF_AX25",
        AddressFamily::AtmPvc => "AF_ATMPVC",
        AddressFamily::AppleTalk => "AF_APPLETALK",
        AddressFamily::Alg => "AF_ALG",
        AddressFamily::NetRom => "AF_NETROM",
        AddressFamily::Bridge => "AF_BRIDGE",
        AddressFamily::Rose => "AF_ROSE",
        AddressFamily::Decnet => "AF_DECNET",
        AddressFamily::NetBeui => "AF_NETBEUI",
        AddressFamily::Security => "AF_SECURITY",
        AddressFamily::Key => "AF_KEY",
        AddressFamily::Ash => "AF_ASH",
        AddressFamily::Econet => "AF_ECONET",
        AddressFamily::AtmSvc => "AF_ATMSVC",
        AddressFamily::Rds => "AF_RDS",
        AddressFamily::Sna => "AF_SNA",
        AddressFamily::Irda => "AF_IRDA",
        AddressFamily::Pppox => "AF_PPPOX",
        AddressFamily::Wanpipe => "AF_WANPIPE",
        AddressFamily::Llc => "AF_LLC",
        AddressFamily::Ib => "AF_IB",
        AddressFamily::Mpls => "AF_MPLS",
        AddressFamily::Can => "AF_CAN",
        AddressFamily::Tipc => "AF_TIPC",
        AddressFamily::Bluetooth => "AF_BLUETOOTH",
        AddressFamily::Iucv => "AF_IUCV",
        AddressFamily::RxRpc => "AF_RXRPC",
        AddressFamily::Isdn => "AF_ISDN",
        AddressFamily::Phonet => "AF_PHONET",
        AddressFamily::Ieee802154 => "AF_IEEE802154",
        AddressFamily::Caif => "AF_CAIF",
        AddressFamily::Nfc => "AF_NFC",
        AddressFamily::Vsock => "AF_VSOCK",
        AddressFamily::Unspec => "AF_UNSPEC",
        _ => unreachable!("New AddressFamily variant; update address_family_str to match it."),
    }
}

fn inet_address_str(addr_fam: AddressFamily, addr: Option<SocketAddr>) -> String {
    format!(
        "{} {}",
        address_family_str(addr_fam),
        if let Some(addr) = addr {
            format!("{}  port: {}", addr.ip(), addr.port())
        } else {
            "".to_string()
        }
    )
}

fn print_sockname(sock_info: &SockInfo) {
    println!(
        "         sockname: {}",
        match sock_info.family {
            AddressFamily::Inet => inet_address_str(sock_info.family, sock_info.local_addr),
            AddressFamily::Inet6 => inet_address_str(sock_info.family, sock_info.local_addr),
            addr_fam => address_family_str(addr_fam).to_string(),
        }
    );
}

fn print_sock_address(pid: u64, fd: u64, sock_info: &SockInfo, peer: Option<&PeerProcess>) {
    // If we have some additional info to print about the remote side of this socket, print it here
    if let Some(peer) = peer {
        println!("         peer: {}[{}]", peer.comm, peer.pid);
    } else if let Some(peer_pid) = sock_info.peer_pid {
        println!("         peerpid: {}", peer_pid);
    }

    if let Some(addr) = sock_info.peer_addr {
        println!(
            "         peername: {} ",
            inet_address_str(sock_info.family, Some(addr))
        );
    }

    if matches!(sock_info.tcp_state, Some(TcpState::Listen)) {
        if let Some(congestion_control) = tcp_congestion_control(pid, fd) {
            println!("         congestion control: {}", congestion_control);
        }
    }

    if let Some(state) = sock_info.tcp_state {
        println!("         state: {}", tcp_state_str(state));
    }

    // TODO Expand peer pid/comm resolution beyond current coverage (unix sockets and loopback TCP)
    // to additional local and namespace edge cases.
}

fn read_comm(pid: u64) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|comm| comm.trim_end().to_string())
}

fn read_socket_inode(path: &Path) -> Option<u64> {
    let link = fs::read_link(path).ok()?;
    let text = link.to_str()?;
    if !text.starts_with("socket:[") || !text.ends_with(']') {
        return None;
    }
    text.trim_start_matches("socket:[")
        .trim_end_matches(']')
        .parse::<u64>()
        .ok()
}

fn list_socket_owners() -> HashMap<u64, HashSet<u64>> {
    let mut owners = HashMap::<u64, HashSet<u64>>::new();
    let proc_entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("failed to read /proc for socket ownership lookup: {}", e);
            return owners;
        }
    };

    for entry in proc_entries.flatten() {
        let pid = match entry.file_name().to_string_lossy().parse::<u64>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{}/fd", pid);
        let Ok(fd_entries) = fs::read_dir(fd_dir) else {
            continue;
        };

        for fd_entry in fd_entries.flatten() {
            if let Some(inode) = read_socket_inode(&fd_entry.path()) {
                owners.entry(inode).or_default().insert(pid);
            }
        }
    }

    owners
}

fn local_tcp_peer_inodes(sockets: &HashMap<u64, SockInfo>) -> HashMap<u64, u64> {
    let mut by_tuple = HashMap::<(AddressFamily, SocketAddr, SocketAddr), Vec<u64>>::new();
    for sock in sockets.values() {
        if !matches!(sock.family, AddressFamily::Inet | AddressFamily::Inet6)
            || !matches!(sock.sock_type, SockType::Stream)
        {
            continue;
        }
        let (Some(local_addr), Some(peer_addr)) = (sock.local_addr, sock.peer_addr) else {
            continue;
        };
        by_tuple
            .entry((sock.family, local_addr, peer_addr))
            .or_default()
            .push(sock.inode);
    }

    let mut peers = HashMap::new();
    for sock in sockets.values() {
        if !matches!(sock.family, AddressFamily::Inet | AddressFamily::Inet6)
            || !matches!(sock.sock_type, SockType::Stream)
        {
            continue;
        }
        let (Some(local_addr), Some(peer_addr)) = (sock.local_addr, sock.peer_addr) else {
            continue;
        };
        if !(local_addr.ip().is_loopback() && peer_addr.ip().is_loopback()) {
            continue;
        }

        if let Some(candidates) = by_tuple.get(&(sock.family, peer_addr, local_addr)) {
            if let Some(peer_inode) = candidates
                .iter()
                .copied()
                .find(|inode| *inode != sock.inode)
            {
                peers.insert(sock.inode, peer_inode);
            }
        }
    }
    peers
}

fn derive_peer_processes(
    target_pid: u64,
    sockets: &HashMap<u64, SockInfo>,
) -> HashMap<u64, PeerProcess> {
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

        peers.insert(
            inode,
            PeerProcess {
                pid: chosen_pid,
                comm,
            },
        );
    }

    peers
}

fn unix_peer_process(pid: u64, fd: u64) -> Option<PeerProcess> {
    let fd_file = File::open(format!("/proc/{}/fd/{}", pid, fd)).ok()?;
    let creds = getsockopt(&fd_file, sockopt::PeerCredentials).ok()?;
    let peer_pid = creds.pid() as u64;
    let comm = read_comm(peer_pid)?;
    Some(PeerProcess {
        pid: peer_pid,
        comm,
    })
}

fn parse_tcp_state(state_hex: &str) -> Result<TcpState, ParseIntError> {
    Ok(match u8::from_str_radix(state_hex, 16)? {
        0x01 => TcpState::Established,
        0x02 => TcpState::SynSent,
        0x03 => TcpState::SynRecv,
        0x04 => TcpState::FinWait1,
        0x05 => TcpState::FinWait2,
        0x06 => TcpState::TimeWait,
        0x07 => TcpState::Close,
        0x08 => TcpState::CloseWait,
        0x09 => TcpState::LastAck,
        0x0A => TcpState::Listen,
        0x0B => TcpState::Closing,
        0x0C => TcpState::NewSynRecv,
        n => TcpState::Unknown(n),
    })
}

fn tcp_state_str(state: TcpState) -> String {
    match state {
        TcpState::Established => "TCP_ESTABLISHED".into(),
        TcpState::SynSent => "TCP_SYN_SENT".into(),
        TcpState::SynRecv => "TCP_SYN_RECV".into(),
        TcpState::FinWait1 => "TCP_FIN_WAIT1".into(),
        TcpState::FinWait2 => "TCP_FIN_WAIT2".into(),
        TcpState::TimeWait => "TCP_TIME_WAIT".into(),
        TcpState::Close => "TCP_CLOSE".into(),
        TcpState::CloseWait => "TCP_CLOSE_WAIT".into(),
        TcpState::LastAck => "TCP_LAST_ACK".into(),
        TcpState::Listen => "TCP_LISTEN".into(),
        TcpState::Closing => "TCP_CLOSING".into(),
        TcpState::NewSynRecv => "TCP_NEW_SYN_RECV".into(),
        TcpState::Unknown(n) => format!("TCP_UNKNOWN_{:02X}", n),
    }
}

fn parse_sock_type(type_code: &str) -> Result<SockType, ParseIntError> {
    Ok(match type_code.parse::<u16>()? {
        1 => SockType::Stream,
        2 => SockType::Datagram,
        3 => SockType::Raw,
        4 => SockType::Rdm,
        5 => SockType::SeqPacket,
        6 => SockType::Dccp,
        10 => SockType::Packet,
        n => SockType::Unknown(n),
    })
}

// Parse a socket address of the form "0100007F:1538" (i.e. 127.0.0.1:5432)
fn parse_ipv4_sock_addr(s: &str) -> Result<SocketAddr, ParseError> {
    let mk_err = || {
        ParseError::new(
            "IPv4 address",
            &format!("expected address in form '0100007F:1538', got {}", s),
        )
    };

    let fields = s.split(':').collect::<Vec<_>>();
    if fields.len() != 2 {
        return Err(mk_err());
    }

    // Port is always printed with most-significant byte first.
    let port = u16::from_str_radix(fields[1], 16).map_err(|_| mk_err())?;

    // Address is printed with most-significant byte first on big-endian systems and vice-versa on
    // little-endian systems.
    let addr_native_endian = u32::from_str_radix(fields[0], 16).map_err(|_| mk_err())?;
    let addr = Ipv4Addr::from(addr_native_endian.to_be());

    Ok(SocketAddr::new(IpAddr::V4(addr), port))
}

// Parse a socket address of the form "00000000000000000000000001000000:1538"
// (i.e. ::1:5432)
fn parse_ipv6_sock_addr(s: &str) -> Result<SocketAddr, ParseError> {
    let mk_err = || {
        ParseError::new(
            "IPv6 address",
            &format!(
                "expected address in form '00000000000000000000000001000000:1538', got {}",
                s
            ),
        )
    };

    let fields = s.split(':').collect::<Vec<_>>();
    if fields.len() != 2 || fields[0].len() != 32 {
        return Err(mk_err());
    }

    let port = u16::from_str_radix(fields[1], 16).map_err(|_| mk_err())?;

    let mut octets = [0u8; 16];
    for (i, chunk) in fields[0].as_bytes().chunks_exact(8).enumerate() {
        let chunk = std::str::from_utf8(chunk).map_err(|_| mk_err())?;
        let native = u32::from_str_radix(chunk, 16).map_err(|_| mk_err())?;
        octets[i * 4..(i + 1) * 4].copy_from_slice(&native.to_be().to_be_bytes());
    }

    Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
}

fn concrete_peer_addr(addr: SocketAddr) -> Option<SocketAddr> {
    if addr.ip().is_unspecified() {
        None
    } else {
        Some(addr)
    }
}

// Turn a Result into an Option, printing an error message indicating the error and the file where
// it occurred if the value is an Err.
fn ok_or_eprint<T>(r: Result<T, Box<dyn Error>>, filename: &str) -> Option<T> {
    if let Err(ref e) = r {
        eprintln!("Error parsing /proc/[pid]/net/{}: {}", filename, e)
    }
    r.ok()
}

// Parse the info for each socket in the system from /proc/[pid]/net, and return it as a map indexed
// by inode
fn fetch_sock_info(pid: u64) -> HashMap<u64, SockInfo> {
    let mut sockets = HashMap::new();
    // Socket table data is namespace-scoped in procfs. Always read from
    // /proc/<target-pid>/net/* so inode->socket metadata resolution is done in
    // the target process's network namespace instead of our own.
    let filename = format!("/proc/{}/net/unix", pid);
    if let Some(file) = ptools::open_or_warn(&filename) {
        let unix_sockets = BufReader::new(file)
            .lines()
            .skip(1) // Header
            .map(|line| {
                let line = line?;
                let fields = line.split_whitespace().collect::<Vec<&str>>();
                let inode = fields[6].parse()?;
                let sock_info = SockInfo {
                    family: AddressFamily::Unix,
                    sock_type: parse_sock_type(fields[4])?,
                    inode: inode,
                    local_addr: None,
                    peer_addr: None,
                    peer_pid: None,
                    tcp_state: None,
                };
                Ok((inode, sock_info))
            })
            .filter_map(|sock_info| ok_or_eprint(sock_info, "unix"));
        sockets.extend(unix_sockets);
    }

    if let Some(file) = ptools::open_or_warn(&format!("/proc/{}/net/netlink", pid)) {
        let netlink_sockets = BufReader::new(file)
            .lines()
            .skip(1) // Header
            .map(|line| {
                let line = line?;
                let fields = line.split_whitespace().collect::<Vec<&str>>();
                let inode = fields[9].parse()?;
                let sock_info = SockInfo {
                    family: AddressFamily::Netlink,
                    sock_type: SockType::Datagram,
                    inode: inode,
                    local_addr: None,
                    peer_addr: None,
                    peer_pid: None,
                    tcp_state: None,
                };
                Ok((inode, sock_info))
            })
            .filter_map(|sock_info| ok_or_eprint(sock_info, "netlink"));
        sockets.extend(netlink_sockets);
    }

    // procfs entries for tcp/udp/raw sockets (both IPv4 and IPv6) all use same format
    let mut parse_file =
        |filename, s_type, family, parse_addr: fn(&str) -> Result<SocketAddr, ParseError>| {
            if let Some(file) = ptools::open_or_warn(&format!("/proc/{}/net/{}", pid, filename)) {
                let is_tcp = filename == "tcp" || filename == "tcp6";
                let additional_sockets = BufReader::new(file)
                    .lines()
                    .skip(1) // Header
                    .map(move |line| {
                        let line = line?;
                        let fields = line.split_whitespace().collect::<Vec<&str>>();
                        let inode = fields[9].parse()?;
                        let peer_addr = parse_addr(fields[2])?;
                        let sock_info = SockInfo {
                            family,
                            sock_type: s_type,
                            local_addr: Some(parse_addr(fields[1])?),
                            peer_addr: concrete_peer_addr(peer_addr),
                            peer_pid: None,
                            tcp_state: if is_tcp {
                                Some(parse_tcp_state(fields[3])?)
                            } else {
                                None
                            },
                            inode: inode,
                        };
                        Ok((inode, sock_info))
                    })
                    .filter_map(|sock_info| ok_or_eprint(sock_info, filename));
                sockets.extend(additional_sockets);
            }
        };

    parse_file(
        "tcp",
        SockType::Stream,
        AddressFamily::Inet,
        parse_ipv4_sock_addr,
    );
    parse_file(
        "udp",
        SockType::Datagram,
        AddressFamily::Inet,
        parse_ipv4_sock_addr,
    );
    parse_file(
        "raw",
        SockType::Raw,
        AddressFamily::Inet,
        parse_ipv4_sock_addr,
    );
    parse_file(
        "tcp6",
        SockType::Stream,
        AddressFamily::Inet6,
        parse_ipv6_sock_addr,
    );
    parse_file(
        "udp6",
        SockType::Datagram,
        AddressFamily::Inet6,
        parse_ipv6_sock_addr,
    );
    parse_file(
        "raw6",
        SockType::Raw,
        AddressFamily::Inet6,
        parse_ipv6_sock_addr,
    );

    sockets
}

fn print_file(
    pid: u64,
    fd: u64,
    sockets: &HashMap<u64, SockInfo>,
    peers: &HashMap<u64, PeerProcess>,
    non_verbose: bool,
) {
    let link_path_str = format!("/proc/{}/fd/{}", pid, fd);
    let link_path = Path::new(&link_path_str);
    let stat_info = match stat(link_path) {
        Err(e) => {
            eprintln!("failed to stat {}: {}", &link_path_str, e);
            return;
        }
        Ok(stat_info) => stat_info,
    };

    let file_type = file_type(stat_info.st_mode, &link_path);

    print!(
        " {: >4}: {} mode:{:04o} dev:{},{} ino:{} uid:{} gid:{}",
        fd,
        print_file_type(&file_type),
        stat_info.st_mode & 0o7777,
        major(stat_info.st_dev),
        minor(stat_info.st_dev),
        stat_info.st_ino,
        stat_info.st_uid,
        stat_info.st_gid
    );

    let rdev_major = major(stat_info.st_rdev);
    let rdev_minor = minor(stat_info.st_rdev);
    if rdev_major == 0 && rdev_minor == 0 {
        print!(" size:{}\n", stat_info.st_size)
    } else {
        print!(" rdev:{},{}\n", rdev_major, rdev_minor);
    }

    if non_verbose {
        return;
    }

    print!("       ");
    match get_flags(pid, fd) {
        Ok(flags) => print_open_flags(flags),
        Err(e) => eprintln!("failed to read fd flags: {}", e),
    }

    match file_type {
        FileType::Posix(PosixFileType::Socket) => {
            // Socket metadata is resolved from /proc/<pid>/net/*, so inode lookups are
            // evaluated in the target process's network namespace.
            if let Some(sock_info) = sockets.get(&(stat_info.st_ino as u64)) {
                debug_assert_eq!(sock_info.inode, stat_info.st_ino as u64);
                print_sockname(sock_info);
                print_sock_type(&sock_info.sock_type);
                print_socket_options(pid, fd);
                let peer =
                    peers
                        .get(&sock_info.inode)
                        .cloned()
                        .or_else(|| match sock_info.family {
                            AddressFamily::Unix => unix_peer_process(pid, fd),
                            _ => None,
                        });
                print_sock_address(pid, fd, &sock_info, peer.as_ref());
            } else if let Some(sockprotoname) = get_sockprotoname(pid, fd) {
                println!(
                    "         sockname: {}",
                    sockname_from_sockprotoname(&sockprotoname)
                );
            } else {
                print!(
                    "       ERROR: failed to find info for socket with inode num {}\n",
                    stat_info.st_ino
                );
            }
        }
        _ => match fs::read_link(link_path) {
            Ok(path) => {
                println!("       {}", path.to_string_lossy());
                match get_offset(pid, fd) {
                    Ok(offset) => println!("       offset: {}", offset),
                    Err(e) => eprintln!("failed to read fd offset: {}", e),
                }
                match path.as_os_str().to_string_lossy().as_ref() {
                    "anon_inode:[eventpoll]" => print_epoll_fdinfo(pid, fd),
                    "anon_inode:[eventfd]" => {
                        print_matching_fdinfo_lines(pid, fd, &["eventfd-count:"])
                    }
                    "anon_inode:[signalfd]" => print_matching_fdinfo_lines(pid, fd, &["sigmask:"]),
                    "anon_inode:[timerfd]" => print_matching_fdinfo_lines(
                        pid,
                        fd,
                        &[
                            "clockid:",
                            "ticks:",
                            "settime flags:",
                            "it_value:",
                            "it_interval:",
                        ],
                    ),
                    "anon_inode:inotify" | "anon_inode:[inotify]" => {
                        print_matching_fdinfo_lines(pid, fd, &["inotify "])
                    }
                    _ => {}
                }
            }
            Err(e) => eprintln!("failed to readlink {}: {}", &link_path_str, e),
        },
    }
}

fn print_epoll_fdinfo(pid: u64, fd: u64) {
    let fdinfo_path = format!("/proc/{}/fdinfo/{}", pid, fd);
    let fdinfo = match fs::read_to_string(&fdinfo_path) {
        Ok(fdinfo) => fdinfo,
        Err(e) => {
            eprintln!("failed to read {}: {}", &fdinfo_path, e);
            return;
        }
    };

    for line in fdinfo.lines().filter(|line| line.starts_with("tfd:")) {
        let mut parts = line.split_whitespace().peekable();
        let mut tfd = None;
        let mut events = None;
        let mut data = None;
        let mut ino = None;

        while let Some(part) = parts.next() {
            if let Some((key, value)) = part.split_once(':') {
                if !value.is_empty() {
                    match key {
                        "pos" => {}
                        "ino" => ino = Some(value),
                        _ => {}
                    }
                    continue;
                }

                if let Some(value) = parts.next() {
                    match key {
                        "tfd" => tfd = Some(value),
                        "events" => events = Some(value),
                        "data" => data = Some(value),
                        _ => {}
                    }
                }
            }
        }

        print!("       epoll");
        if let Some(tfd) = tfd {
            print!(" tfd: {}", tfd);
        }
        if let Some(events) = events {
            print!(" events: {}", events);
        }
        if let Some(data) = data {
            print!(" data: {}", data);
        }
        if let Some(ino) = ino {
            print!(" ino: {}", ino);
        }
        println!();
    }
}

fn read_nofile_rlimit(pid: u64) -> Result<(String, String), Box<dyn Error>> {
    let limits = fs::read_to_string(format!("/proc/{}/limits", pid))?;

    for line in limits.lines() {
        if line.starts_with("Max open files") {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return Err(Box::new(ParseError::new(
                    "Max open files",
                    "line has fewer fields than expected",
                )));
            }

            return Ok((fields[3].to_string(), fields[4].to_string()));
        }
    }

    Err(Box::new(ParseError::new(
        "/proc/[pid]/limits",
        "Max open files line not found",
    )))
}

fn read_umask(pid: u64) -> Result<String, Box<dyn Error>> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid))?;
    for line in status.lines() {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };

        if field == "Umask" {
            let parsed = u16::from_str_radix(value.trim(), 8)?;
            return Ok(format!("{:03o}", parsed));
        }
    }

    Err(Box::new(ParseError::new(
        "/proc/[pid]/status",
        "Umask line not found",
    )))
}

fn print_files(pid: u64, non_verbose: bool) -> bool {
    let proc_dir = format!("/proc/{}/", pid);
    if !Path::new(&proc_dir).exists() {
        eprintln!("No such directory {}", &proc_dir);
        return false;
    }

    ptools::print_proc_summary(pid);
    match read_nofile_rlimit(pid) {
        Ok((soft, hard)) => {
            println!("  Current soft rlimit: {} file descriptors", soft);
            println!("  Current hard rlimit: {} file descriptors", hard);
        }
        Err(e) => eprintln!("Failed to read RLIMIT_NOFILE for {}: {}", pid, e),
    }
    match read_umask(pid) {
        Ok(umask) => println!("  Current umask: {}", umask),
        Err(e) => eprintln!("Failed to read umask for {}: {}", pid, e),
    }

    let sockets = fetch_sock_info(pid);
    let peers = derive_peer_processes(pid, &sockets);

    let fd_dir = format!("/proc/{}/fd/", pid);
    let readdir_res = fs::read_dir(&fd_dir).and_then(|entries| {
        for entry in entries {
            let entry = entry?;
            let filename = entry.file_name();
            let filename = filename.to_string_lossy();
            if let Ok(fd) = (&filename).parse::<u64>() {
                print_file(pid, fd, &sockets, &peers, non_verbose);
            } else {
                eprint!("Unexpected file /proc/[pid]/fd/{} found", &filename);
            }
        }
        Ok(())
    });

    if let Err(e) = readdir_res {
        eprintln!("Unable to read {}: {}", &fd_dir, e);
        return false;
    }

    return true;
}

fn main() {
    let matches = command!()
        .about("Print information for all open files in each process")
        .trailing_var_arg(true)
        .arg(
            Arg::new("non-verbose")
                .short('n')
                .action(ArgAction::SetTrue)
                .help("Set non-verbose mode"),
        )
        .arg(
            Arg::new("pid")
                .value_name("PID")
                .help("Process ID (PID)")
                .num_args(1..)
                .required(true)
                .value_parser(value_parser!(u64).range(1..)),
        )
        .get_matches();

    let non_verbose = matches.get_flag("non-verbose");
    let error = matches
        .get_many::<u64>("pid")
        .unwrap()
        .copied()
        .any(|pid| !print_files(pid, non_verbose));

    if error {
        exit(1);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nix::sys::socket::AddressFamily;
    use std::net::SocketAddr;

    #[test]
    fn test_parse_ipv4_sock_addr() {
        assert_eq!(
            parse_ipv4_sock_addr("0100007F:1538").unwrap(),
            "127.0.0.1:5432".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_ipv4_sock_addr("00000000:0000").unwrap(),
            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
        );

        assert!(parse_ipv4_sock_addr("0100007F 1538").is_err());
        assert!(parse_ipv4_sock_addr("0100007F:1538:00").is_err());
        assert!(parse_ipv4_sock_addr("010000YY:1538").is_err());
        assert!(parse_ipv4_sock_addr("0100007F:15YY").is_err());
        assert!(parse_ipv4_sock_addr(":1538").is_err());
    }

    #[test]
    fn test_parse_sock_type() {
        assert!(matches!(parse_sock_type("1").unwrap(), SockType::Stream));
        assert!(matches!(parse_sock_type("2").unwrap(), SockType::Datagram));
        assert!(matches!(parse_sock_type("3").unwrap(), SockType::Raw));
        assert!(matches!(parse_sock_type("4").unwrap(), SockType::Rdm));
        assert!(matches!(parse_sock_type("5").unwrap(), SockType::SeqPacket));
        assert!(matches!(parse_sock_type("6").unwrap(), SockType::Dccp));
        assert!(matches!(parse_sock_type("10").unwrap(), SockType::Packet));

        assert!(matches!(
            parse_sock_type("999").unwrap(),
            SockType::Unknown(999)
        ));
        assert!(parse_sock_type("abc").is_err());
    }

    #[test]
    fn test_address_family_str() {
        assert_eq!(address_family_str(AddressFamily::Unix), "AF_UNIX");
        assert_eq!(address_family_str(AddressFamily::Inet), "AF_INET");
        assert_eq!(address_family_str(AddressFamily::Inet6), "AF_INET6");
        assert_eq!(address_family_str(AddressFamily::Netlink), "AF_NETLINK");
        assert_eq!(address_family_str(AddressFamily::Packet), "AF_PACKET");
        assert_eq!(address_family_str(AddressFamily::Bluetooth), "AF_BLUETOOTH");
        assert_eq!(address_family_str(AddressFamily::Vsock), "AF_VSOCK");
        assert_eq!(address_family_str(AddressFamily::Alg), "AF_ALG");
        assert_eq!(address_family_str(AddressFamily::Can), "AF_CAN");
        assert_eq!(address_family_str(AddressFamily::Pppox), "AF_PPPOX");
        assert_eq!(address_family_str(AddressFamily::Ib), "AF_IB");

        assert_eq!(address_family_str(AddressFamily::Ipx), "AF_IPX");
        assert_eq!(address_family_str(AddressFamily::X25), "AF_X25");
        assert_eq!(address_family_str(AddressFamily::Ax25), "AF_AX25");
        assert_eq!(address_family_str(AddressFamily::AppleTalk), "AF_APPLETALK");
        assert_eq!(address_family_str(AddressFamily::Tipc), "AF_TIPC");
        assert_eq!(address_family_str(AddressFamily::Nfc), "AF_NFC");
        assert_eq!(address_family_str(AddressFamily::Unspec), "AF_UNSPEC");
    }

    #[test]
    fn test_sockname_from_sockprotoname() {
        assert_eq!(sockname_from_sockprotoname("ALG"), "AF_ALG");
        assert_eq!(sockname_from_sockprotoname("AF_ALG"), "AF_ALG");
        assert_eq!(
            sockname_from_sockprotoname("SOMETHING_UNKNOWN"),
            "SOMETHING_UNKNOWN"
        );
    }

    #[test]
    fn test_posix_file_type_symlink_and_block_device() {
        let dummy = Path::new("/proc/self/fd/0");

        let symlink_type = file_type(SFlag::S_IFLNK.bits(), dummy);
        assert!(matches!(
            symlink_type,
            FileType::Posix(PosixFileType::SymLink)
        ));
        assert_eq!(print_file_type(&symlink_type), "S_IFLNK");

        let block_device_type = file_type(SFlag::S_IFBLK.bits(), dummy);
        assert!(matches!(
            block_device_type,
            FileType::Posix(PosixFileType::BlockDevice)
        ));
        assert_eq!(print_file_type(&block_device_type), "S_IFBLK");
    }
}
