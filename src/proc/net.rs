use nix::sys::socket::{getsockopt, sockopt, AddressFamily};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::ParseIntError;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(target_os = "linux")]
use super::fd::parse_socket_inode;
use super::{Error, ProcSource};

/// Socket type as reported in `/proc/[pid]/net/*`.
///
/// We define our own enum rather than using the one from nix so that we can
/// include additional types defined by the Linux kernel but not by nix.
#[derive(Debug, Clone, Copy)]
pub enum SockType {
    Stream,
    Datagram,
    Raw,
    Rdm,
    SeqPacket,
    Dccp,
    Packet,
    Unknown(u16),
}

impl std::fmt::Display for SockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SockType::Stream => write!(f, "SOCK_STREAM"),
            SockType::Datagram => write!(f, "SOCK_DGRAM"),
            SockType::Raw => write!(f, "SOCK_RAW"),
            SockType::Rdm => write!(f, "SOCK_RDM"),
            SockType::SeqPacket => write!(f, "SOCK_SEQPACKET"),
            SockType::Dccp => write!(f, "SOCK_DCCP"),
            SockType::Packet => write!(f, "SOCK_PACKET"),
            SockType::Unknown(n) => write!(f, "SOCK_TYPE_UNKNOWN_{}", n),
        }
    }
}

/// TCP connection state from `/proc/[pid]/net/tcp*`.
#[derive(Debug, Clone, Copy)]
pub enum TcpState {
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

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Established => write!(f, "TCP_ESTABLISHED"),
            TcpState::SynSent => write!(f, "TCP_SYN_SENT"),
            TcpState::SynRecv => write!(f, "TCP_SYN_RECV"),
            TcpState::FinWait1 => write!(f, "TCP_FIN_WAIT1"),
            TcpState::FinWait2 => write!(f, "TCP_FIN_WAIT2"),
            TcpState::TimeWait => write!(f, "TCP_TIME_WAIT"),
            TcpState::Close => write!(f, "TCP_CLOSE"),
            TcpState::CloseWait => write!(f, "TCP_CLOSE_WAIT"),
            TcpState::LastAck => write!(f, "TCP_LAST_ACK"),
            TcpState::Listen => write!(f, "TCP_LISTEN"),
            TcpState::Closing => write!(f, "TCP_CLOSING"),
            TcpState::NewSynRecv => write!(f, "TCP_NEW_SYN_RECV"),
            TcpState::Unknown(n) => write!(f, "TCP_UNKNOWN_{:02X}", n),
        }
    }
}

/// Parsed socket metadata from `/proc/[pid]/net/*`.
#[derive(Clone)]
pub(crate) struct SocketInfo {
    pub family: AddressFamily,
    pub sock_type: SockType,
    pub inode: u64,
    pub local_addr: Option<SocketAddr>,
    pub peer_addr: Option<SocketAddr>,
    pub tcp_state: Option<TcpState>,
    pub tx_queue: Option<u32>,
    pub rx_queue: Option<u32>,
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

// Parse a socket address of the form "0100007F:1538" (i.e. 127.0.0.1:5432)
fn parse_ipv4_sock_addr(s: &str) -> Result<SocketAddr, Error> {
    let mk_err = || {
        Error::parse(
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
fn parse_ipv6_sock_addr(s: &str) -> Result<SocketAddr, Error> {
    let mk_err = || {
        Error::parse(
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

// Parse "HHHHHHHH:HHHHHHHH" tx_queue:rx_queue from /proc/net/tcp fields[4]
fn parse_queue_sizes(s: &str) -> (u32, u32) {
    if let Some((tx, rx)) = s.split_once(':') {
        let tx = u32::from_str_radix(tx, 16).unwrap_or(0);
        let rx = u32::from_str_radix(rx, 16).unwrap_or(0);
        (tx, rx)
    } else {
        (0, 0)
    }
}

/// Parse socket metadata from all `/proc/[pid]/net/*` files, returning a map
/// keyed by inode number.
pub(crate) fn parse_socket_info(source: &dyn ProcSource) -> HashMap<u64, SocketInfo> {
    let mut sockets = HashMap::new();

    // Socket table data is namespace-scoped in procfs. Always read from
    // /proc/<target-pid>/net/* so inode->socket metadata resolution is done in
    // the target process's network namespace instead of our own.
    if let Ok(content) = source.read_net_file("unix") {
        let unix_sockets = content
            .lines()
            .skip(1) // Header
            .filter_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<&str>>();
                let inode = fields[6].parse().ok()?;
                let sock_type = parse_sock_type(fields[4]).ok()?;
                Some((
                    inode,
                    SocketInfo {
                        family: AddressFamily::Unix,
                        sock_type,
                        inode,
                        local_addr: None,
                        peer_addr: None,
                        tcp_state: None,
                        tx_queue: None,
                        rx_queue: None,
                    },
                ))
            });
        sockets.extend(unix_sockets);
    }

    if let Ok(content) = source.read_net_file("netlink") {
        let netlink_sockets = content
            .lines()
            .skip(1) // Header
            .filter_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<&str>>();
                let inode = fields[9].parse().ok()?;
                Some((
                    inode,
                    SocketInfo {
                        family: AddressFamily::Netlink,
                        sock_type: SockType::Datagram,
                        inode,
                        local_addr: None,
                        peer_addr: None,
                        tcp_state: None,
                        tx_queue: None,
                        rx_queue: None,
                    },
                ))
            });
        sockets.extend(netlink_sockets);
    }

    // procfs entries for tcp/udp/raw sockets (both IPv4 and IPv6) all use same format
    let mut parse_net_file =
        |filename: &str, s_type, family, parse_addr: fn(&str) -> Result<SocketAddr, Error>| {
            if let Ok(content) = source.read_net_file(filename) {
                let is_tcp = filename == "tcp" || filename == "tcp6";
                let additional_sockets = content
                    .lines()
                    .skip(1) // Header
                    .filter_map(move |line| {
                        let fields = line.split_whitespace().collect::<Vec<&str>>();
                        let inode = fields[9].parse().ok()?;
                        let peer_addr = parse_addr(fields[2]).ok()?;
                        let (tx_queue, rx_queue) = parse_queue_sizes(fields[4]);
                        Some((
                            inode,
                            SocketInfo {
                                family,
                                sock_type: s_type,
                                local_addr: Some(parse_addr(fields[1]).ok()?),
                                peer_addr: concrete_peer_addr(peer_addr),
                                tcp_state: if is_tcp {
                                    Some(parse_tcp_state(fields[3]).ok()?)
                                } else {
                                    None
                                },
                                inode,
                                tx_queue: Some(tx_queue),
                                rx_queue: Some(rx_queue),
                            },
                        ))
                    });
                sockets.extend(additional_sockets);
            }
        };

    parse_net_file(
        "tcp",
        SockType::Stream,
        AddressFamily::Inet,
        parse_ipv4_sock_addr,
    );
    parse_net_file(
        "udp",
        SockType::Datagram,
        AddressFamily::Inet,
        parse_ipv4_sock_addr,
    );
    parse_net_file(
        "raw",
        SockType::Raw,
        AddressFamily::Inet,
        parse_ipv4_sock_addr,
    );
    parse_net_file(
        "tcp6",
        SockType::Stream,
        AddressFamily::Inet6,
        parse_ipv6_sock_addr,
    );
    parse_net_file(
        "udp6",
        SockType::Datagram,
        AddressFamily::Inet6,
        parse_ipv6_sock_addr,
    );
    parse_net_file(
        "raw6",
        SockType::Raw,
        AddressFamily::Inet6,
        parse_ipv6_sock_addr,
    );

    sockets
}

/// Socket details queried via `getsockopt` on a duplicated file descriptor.
#[derive(Clone)]
pub(crate) struct SocketDetails {
    pub options: Vec<String>,
    pub tcp_info: Option<nix::libc::tcp_info>,
    pub congestion_control: Option<String>,
}

/// Structured TCP connection metrics extracted from `libc::tcp_info`.
pub struct TcpInfo {
    pub snd_cwnd: u32,
    pub snd_ssthresh: u32,
    pub snd_wscale: u8,
    pub rcv_wscale: u8,
    pub rtt: u32,
    pub rttvar: u32,
    pub snd_mss: u32,
    pub rcv_mss: u32,
    pub advmss: u32,
    pub pmtu: u32,
    pub unacked: u32,
    pub retrans: u32,
    pub total_retrans: u32,
    pub lost: u32,
    pub rcv_space: u32,
}

impl TcpInfo {
    fn from_raw(raw: &nix::libc::tcp_info) -> Self {
        TcpInfo {
            snd_cwnd: raw.tcpi_snd_cwnd,
            snd_ssthresh: raw.tcpi_snd_ssthresh,
            snd_wscale: raw.tcpi_snd_rcv_wscale & 0x0f,
            rcv_wscale: (raw.tcpi_snd_rcv_wscale >> 4) & 0x0f,
            rtt: raw.tcpi_rtt,
            rttvar: raw.tcpi_rttvar,
            snd_mss: raw.tcpi_snd_mss,
            rcv_mss: raw.tcpi_rcv_mss,
            advmss: raw.tcpi_advmss,
            pmtu: raw.tcpi_pmtu,
            unacked: raw.tcpi_unacked,
            retrans: raw.tcpi_retrans,
            total_retrans: raw.tcpi_total_retrans,
            lost: raw.tcpi_lost,
            rcv_space: raw.tcpi_rcv_space,
        }
    }
}

/// Peer process for a socket connection.
#[derive(Clone)]
pub struct PeerProcess {
    pub pid: u64,
    pub comm: String,
}

/// Unified socket metadata combining `/proc/net/*` info, `getsockopt` details,
/// and peer process resolution.
pub struct Socket {
    pub family: AddressFamily,
    pub sock_type: SockType,
    pub inode: u64,
    pub local_addr: Option<SocketAddr>,
    pub peer_addr: Option<SocketAddr>,
    pub tcp_state: Option<TcpState>,
    pub tx_queue: Option<u32>,
    pub rx_queue: Option<u32>,
    pub options: Vec<String>,
    pub tcp_info: Option<TcpInfo>,
    pub congestion_control: Option<String>,
    pub peer_process: Option<PeerProcess>,
}

impl Socket {
    pub(crate) fn from_parts(
        info: SocketInfo,
        details: Option<SocketDetails>,
        peer: Option<PeerProcess>,
    ) -> Self {
        let (tcp_info, congestion_control, options) = if let Some(d) = details {
            (
                d.tcp_info.map(|raw| TcpInfo::from_raw(&raw)),
                d.congestion_control,
                d.options,
            )
        } else {
            (None, None, Vec::new())
        };
        Socket {
            family: info.family,
            sock_type: info.sock_type,
            inode: info.inode,
            local_addr: info.local_addr,
            peer_addr: info.peer_addr,
            tcp_state: info.tcp_state,
            tx_queue: info.tx_queue,
            rx_queue: info.rx_queue,
            options,
            tcp_info,
            congestion_control,
            peer_process: peer,
        }
    }
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

fn query_socket_options(sock_fd: &OwnedFd) -> Vec<String> {
    let mut options = Vec::new();

    if matches!(getsockopt(sock_fd, sockopt::ReuseAddr), Ok(true)) {
        options.push("SO_REUSEADDR".to_string());
    }
    if matches!(getsockopt(sock_fd, sockopt::KeepAlive), Ok(true)) {
        options.push("SO_KEEPALIVE".to_string());
    }
    if matches!(getsockopt(sock_fd, sockopt::Broadcast), Ok(true)) {
        options.push("SO_BROADCAST".to_string());
    }
    if matches!(getsockopt(sock_fd, sockopt::AcceptConn), Ok(true)) {
        options.push("SO_ACCEPTCONN".to_string());
    }
    if matches!(getsockopt(sock_fd, sockopt::OobInline), Ok(true)) {
        options.push("SO_OOBINLINE".to_string());
    }

    if let Ok(sndbuf) = getsockopt(sock_fd, sockopt::SndBuf) {
        options.push(format!("SO_SNDBUF({})", sndbuf));
    }
    if let Ok(rcvbuf) = getsockopt(sock_fd, sockopt::RcvBuf) {
        options.push(format!("SO_RCVBUF({})", rcvbuf));
    }

    options
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
pub(crate) fn query_socket_details(pid: u64, fd: u64) -> Option<SocketDetails> {
    let sock_fd = duplicate_target_fd(pid, fd)?;
    Some(SocketDetails {
        options: query_socket_options(&sock_fd),
        tcp_info: query_tcp_info(&sock_fd),
        congestion_control: query_tcp_congestion_control(&sock_fd),
    })
}

// -- Peer process resolution --------------------------------------------------

#[cfg(target_os = "linux")]
pub(crate) fn read_comm(pid: u64) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|comm| comm.trim_end().to_string())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_comm(_pid: u64) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn list_socket_owners() -> HashMap<u64, std::collections::HashSet<u64>> {
    let mut owners = HashMap::<u64, std::collections::HashSet<u64>>::new();
    let proc_entries = match std::fs::read_dir("/proc") {
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

#[cfg(target_os = "linux")]
fn local_tcp_peer_inodes(sockets: &HashMap<u64, SocketInfo>) -> HashMap<u64, u64> {
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

pub(crate) fn has_loopback_tcp_peers(sockets: &HashMap<u64, SocketInfo>) -> bool {
    sockets.values().any(|sock| {
        matches!(sock.family, AddressFamily::Inet | AddressFamily::Inet6)
            && matches!(sock.sock_type, SockType::Stream)
            && sock.local_addr.is_some_and(|a| a.ip().is_loopback())
            && sock.peer_addr.is_some_and(|a| a.ip().is_loopback())
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn derive_peer_processes(
    target_pid: u64,
    sockets: &HashMap<u64, SocketInfo>,
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

#[cfg(not(target_os = "linux"))]
pub(crate) fn derive_peer_processes(
    _target_pid: u64,
    _sockets: &HashMap<u64, SocketInfo>,
) -> HashMap<u64, PeerProcess> {
    HashMap::new()
}

#[cfg(target_os = "linux")]
pub(crate) fn unix_peer_process(pid: u64, fd: u64) -> Option<PeerProcess> {
    let sock_fd = duplicate_target_fd(pid, fd)?;
    let creds = getsockopt(&sock_fd, sockopt::PeerCredentials).ok()?;
    let peer_pid = creds.pid() as u64;
    let comm = read_comm(peer_pid)?;
    Some(PeerProcess {
        pid: peer_pid,
        comm,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn unix_peer_process(_pid: u64, _fd: u64) -> Option<PeerProcess> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_sock_addr() {
        // The address format in /proc/net/tcp is native-endian, so the hex
        // representation differs between little-endian and big-endian systems.
        #[cfg(target_endian = "little")]
        const LOCALHOST: &str = "0100007F:1538";
        #[cfg(target_endian = "big")]
        const LOCALHOST: &str = "7F000001:1538";

        assert_eq!(
            parse_ipv4_sock_addr(LOCALHOST).unwrap(),
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
}
