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

use std::io::{self, BufRead};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::path::PathBuf;

use nix::sys::socket::AddressFamily;

use super::FromBufRead;

/// Parse a `system.sockprotoname` value (e.g. `"TCP"`, `"AF_UNIX"`, `"UDPv6"`)
/// into an [`AddressFamily`].
pub fn parse_sock_proto_family(s: &str) -> Option<AddressFamily> {
    let name = s.strip_prefix("AF_").unwrap_or(s);
    match name {
        "UNIX" | "UNIX-STREAM" => Some(AddressFamily::Unix),
        "TCP" | "UDP" | "RAW" | "PING" | "MPTCP" | "L2TP/IP" => Some(AddressFamily::Inet),
        "TCPv6" | "UDPv6" | "RAWv6" | "SCTPv6" | "SMC6" | "L2TP/IPv6" => Some(AddressFamily::Inet6),
        "SCTP" | "SMC" => Some(AddressFamily::Inet),
        "NETLINK" => Some(AddressFamily::Netlink),
        "PACKET" => Some(AddressFamily::Packet),
        "ALG" => Some(AddressFamily::Alg),
        "XDP" => Some(AddressFamily::Packet),
        "ROSE" => Some(AddressFamily::Rose),
        _ => None,
    }
}

/// Create an `io::Error` for a `/proc/[pid]/<file>` parse failure.
fn file_parse_error(file: &str, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Error parsing /proc/[pid]/{file}: {reason}"),
    )
}

/// Socket type as reported in `/proc/[pid]/net/*`.
///
/// We define our own enum rather than using the one from nix so that we can
/// include additional types defined by the Linux kernel but not by nix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl From<u16> for SockType {
    #[allow(deprecated)]
    fn from(n: u16) -> Self {
        match i32::from(n) {
            libc::SOCK_STREAM => Self::Stream,
            libc::SOCK_DGRAM => Self::Datagram,
            libc::SOCK_RAW => Self::Raw,
            libc::SOCK_RDM => Self::Rdm,
            libc::SOCK_SEQPACKET => Self::SeqPacket,
            libc::SOCK_DCCP => Self::Dccp,
            libc::SOCK_PACKET => Self::Packet,
            _ => Self::Unknown(n),
        }
    }
}

#[allow(deprecated)]
impl From<SockType> for u16 {
    fn from(st: SockType) -> Self {
        match st {
            SockType::Stream => libc::SOCK_STREAM as u16,
            SockType::Datagram => libc::SOCK_DGRAM as u16,
            SockType::Raw => libc::SOCK_RAW as u16,
            SockType::Rdm => libc::SOCK_RDM as u16,
            SockType::SeqPacket => libc::SOCK_SEQPACKET as u16,
            SockType::Dccp => libc::SOCK_DCCP as u16,
            SockType::Packet => libc::SOCK_PACKET as u16,
            SockType::Unknown(n) => n,
        }
    }
}

/// TCP connection state from `/proc/[pid]/net/tcp*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl From<u8> for TcpState {
    fn from(num: u8) -> Self {
        match num {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            12 => Self::NewSynRecv,
            n => Self::Unknown(n),
        }
    }
}

impl From<TcpState> for u8 {
    fn from(state: TcpState) -> Self {
        match state {
            TcpState::Established => 1,
            TcpState::SynSent => 2,
            TcpState::SynRecv => 3,
            TcpState::FinWait1 => 4,
            TcpState::FinWait2 => 5,
            TcpState::TimeWait => 6,
            TcpState::Close => 7,
            TcpState::CloseWait => 8,
            TcpState::LastAck => 9,
            TcpState::Listen => 10,
            TcpState::Closing => 11,
            TcpState::NewSynRecv => 12,
            TcpState::Unknown(n) => n,
        }
    }
}

/// UDP connection state from `/proc/[pid]/net/udp*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpState {
    Established,
    Close,
    Unknown(u8),
}

impl From<u8> for UdpState {
    fn from(num: u8) -> Self {
        match num {
            1 => Self::Established,
            7 => Self::Close,
            n => Self::Unknown(n),
        }
    }
}

impl From<UdpState> for u8 {
    fn from(state: UdpState) -> Self {
        match state {
            UdpState::Established => 1,
            UdpState::Close => 7,
            UdpState::Unknown(n) => n,
        }
    }
}

/// Unix socket state from `/proc/[pid]/net/unix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixState {
    Unconnected,
    Connecting,
    Connected,
    Disconnecting,
    Unknown(u8),
}

impl From<u8> for UnixState {
    fn from(num: u8) -> Self {
        match num {
            1 => Self::Unconnected,
            2 => Self::Connecting,
            3 => Self::Connected,
            4 => Self::Disconnecting,
            n => Self::Unknown(n),
        }
    }
}

impl From<UnixState> for u8 {
    fn from(state: UnixState) -> Self {
        match state {
            UnixState::Unconnected => 1,
            UnixState::Connecting => 2,
            UnixState::Connected => 3,
            UnixState::Disconnecting => 4,
            UnixState::Unknown(n) => n,
        }
    }
}

// -- Protocol-specific entry types -------------------------------------------

/// Parsed TCP socket entry from `/proc/[pid]/net/tcp{,6}`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TcpNetEntry {
    pub local_address: SocketAddr,
    pub remote_address: SocketAddr,
    pub state: TcpState,
    pub rx_queue: u32,
    pub tx_queue: u32,
    pub uid: u32,
    pub inode: u64,
}

/// Parsed UDP socket entry from `/proc/[pid]/net/udp{,6}`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UdpNetEntry {
    pub local_address: SocketAddr,
    pub remote_address: SocketAddr,
    pub state: UdpState,
    pub rx_queue: u32,
    pub tx_queue: u32,
    pub uid: u32,
    pub inode: u64,
}

/// Parsed Unix socket entry from `/proc/[pid]/net/unix`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UnixNetEntry {
    pub ref_count: u32,
    pub socket_type: SockType,
    pub state: UnixState,
    pub inode: u64,
    pub path: Option<PathBuf>,
}

/// Parsed raw socket entry from `/proc/[pid]/net/raw{,6}`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RawNetEntry {
    pub local_address: SocketAddr,
    pub remote_address: Option<SocketAddr>,
    pub tx_queue: u32,
    pub rx_queue: u32,
    pub uid: u32,
    pub inode: u64,
}

/// Parsed netlink socket entry from `/proc/[pid]/net/netlink`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NetlinkNetEntry {
    pub inode: u64,
    pub protocol: u32,
    pub pid: u32,
    pub groups: u32,
}

#[derive(Debug)]
pub struct TcpNetEntries(pub Vec<TcpNetEntry>);
#[derive(Debug)]
pub struct UdpNetEntries(pub Vec<UdpNetEntry>);
#[derive(Debug)]
pub struct UnixNetEntries(pub Vec<UnixNetEntry>);
#[derive(Debug)]
pub struct RawNetEntries(pub Vec<RawNetEntry>);
#[derive(Debug)]
pub struct NetlinkNetEntries(pub Vec<NetlinkNetEntry>);

/// Protocol-specific socket entry, used as the value in the inode-to-socket map.
#[derive(Debug, Clone)]
pub enum NetEntry {
    Tcp(TcpNetEntry),
    Udp(UdpNetEntry),
    Unix(UnixNetEntry),
    Raw(RawNetEntry),
    Netlink(NetlinkNetEntry),
}

// -- Socket-level types ------------------------------------------------------

/// Socket-level options queried via `getsockopt`.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SocketOptions {
    pub reuse_addr: bool,
    pub keep_alive: bool,
    pub broadcast: bool,
    pub accept_conn: bool,
    pub oob_inline: bool,
    pub snd_buf: Option<usize>,
    pub rcv_buf: Option<usize>,
}

/// Socket details queried via `getsockopt` on a duplicated file descriptor.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SocketDetails {
    pub options: SocketOptions,
    pub tcp_info: Option<nix::libc::tcp_info>,
    pub congestion_control: Option<String>,
}

// -- Helpers -----------------------------------------------------------------

/// Parse an IPv4 socket address from the hex format used in `/proc/net/*`.
///
/// `is_little_endian` indicates the byte order of the source that produced the
/// data (the kernel prints addresses in native-endian order).
fn parse_ipv4_sock_addr(s: &str, is_little_endian: bool) -> io::Result<SocketAddr> {
    let mk_err = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Error parsing IPv4 address: expected form '0100007F:1538', got {s}"),
        )
    };

    let fields = s.split(':').collect::<Vec<_>>();
    if fields.len() != 2 {
        return Err(mk_err());
    }

    // Port is always printed with most-significant byte first.
    let port = u16::from_str_radix(fields[1], 16).map_err(|_| mk_err())?;

    // Address is printed in the source's native byte order.
    let raw = u32::from_str_radix(fields[0], 16).map_err(|_| mk_err())?;
    let canonical = if is_little_endian {
        raw.swap_bytes()
    } else {
        raw
    };
    let addr = Ipv4Addr::from(canonical);

    Ok(SocketAddr::new(IpAddr::V4(addr), port))
}

/// Parse an IPv6 socket address from the hex format used in `/proc/net/*`.
///
/// `is_little_endian` indicates the byte order of the source that produced the
/// data (the kernel prints each 32-bit word in native-endian order).
fn parse_ipv6_sock_addr(s: &str, is_little_endian: bool) -> io::Result<SocketAddr> {
    let mk_err = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Error parsing IPv6 address: expected form '00000000000000000000000001000000:1538', got {s}"),
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
        let raw = u32::from_str_radix(chunk, 16).map_err(|_| mk_err())?;
        let canonical = if is_little_endian {
            raw.swap_bytes()
        } else {
            raw
        };
        octets[i * 4..(i + 1) * 4].copy_from_slice(&canonical.to_be_bytes());
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
fn parse_queue_sizes(s: &str) -> io::Result<(u32, u32)> {
    let (tx, rx) = s.split_once(':').ok_or_else(|| {
        file_parse_error(
            "tx_queue:rx_queue",
            &format!("expected form 'HHHH:HHHH', got '{s}'"),
        )
    })?;
    let tx = u32::from_str_radix(tx, 16)
        .map_err(|e| file_parse_error("tx_queue", &format!("invalid value '{tx}': {e}")))?;
    let rx = u32::from_str_radix(rx, 16)
        .map_err(|e| file_parse_error("rx_queue", &format!("invalid value '{rx}': {e}")))?;
    Ok((tx, rx))
}

// -- FromBufRead / inherent from_buf_read implementations --------------------

impl FromBufRead for UnixNetEntries {
    fn from_buf_read(reader: impl BufRead) -> io::Result<Self> {
        let mut lines = reader.lines();
        if let Some(header) = lines.next() {
            header?;
        }
        let mut entries = Vec::new();
        for line_result in lines {
            let line = line_result?;
            let parse_row = || -> io::Result<UnixNetEntry> {
                let fields = line.split_whitespace().collect::<Vec<&str>>();
                if fields.len() < 7 {
                    return Err(file_parse_error("unix", &format!("too few fields: {line}")));
                }
                let ref_count = u32::from_str_radix(fields[1], 16).map_err(|e| {
                    file_parse_error("unix", &format!("invalid ref_count '{}': {e}", fields[1]))
                })?;
                let socket_type = SockType::from(fields[4].parse::<u16>().map_err(|e| {
                    file_parse_error("unix", &format!("invalid socket_type '{}': {e}", fields[4]))
                })?);
                let state = UnixState::from(u8::from_str_radix(fields[5], 16).map_err(|e| {
                    file_parse_error("unix", &format!("invalid state '{}': {e}", fields[5]))
                })?);
                let inode = fields[6].parse().map_err(|e| {
                    file_parse_error("unix", &format!("invalid inode '{}': {e}", fields[6]))
                })?;
                let path = fields.get(7).map(|&s| PathBuf::from(s));
                Ok(UnixNetEntry {
                    ref_count,
                    socket_type,
                    state,
                    inode,
                    path,
                })
            };
            match parse_row() {
                Ok(entry) => entries.push(entry),
                Err(e) => eprintln!("warning: skipping malformed unix row: {e}"),
            }
        }
        Ok(UnixNetEntries(entries))
    }
}

impl FromBufRead for NetlinkNetEntries {
    fn from_buf_read(reader: impl BufRead) -> io::Result<Self> {
        let mut lines = reader.lines();
        if let Some(header) = lines.next() {
            header?;
        }
        let mut entries = Vec::new();
        for line_result in lines {
            let line = line_result?;
            let parse_row = || -> io::Result<NetlinkNetEntry> {
                let fields = line.split_whitespace().collect::<Vec<&str>>();
                if fields.len() < 10 {
                    return Err(file_parse_error(
                        "netlink",
                        &format!("too few fields: {line}"),
                    ));
                }
                let protocol = fields[1].parse().map_err(|e| {
                    file_parse_error("netlink", &format!("invalid protocol '{}': {e}", fields[1]))
                })?;
                let pid = fields[2].parse().map_err(|e| {
                    file_parse_error("netlink", &format!("invalid pid '{}': {e}", fields[2]))
                })?;
                let groups = u32::from_str_radix(fields[3], 16).map_err(|e| {
                    file_parse_error("netlink", &format!("invalid groups '{}': {e}", fields[3]))
                })?;
                let inode = fields[9].parse().map_err(|e| {
                    file_parse_error("netlink", &format!("invalid inode '{}': {e}", fields[9]))
                })?;
                Ok(NetlinkNetEntry {
                    inode,
                    protocol,
                    pid,
                    groups,
                })
            };
            match parse_row() {
                Ok(entry) => entries.push(entry),
                Err(e) => eprintln!("warning: skipping malformed netlink row: {e}"),
            }
        }
        Ok(NetlinkNetEntries(entries))
    }
}

/// Common fields parsed from a `/proc/[pid]/net/{tcp,udp,raw}{,6}` row.
struct InetRow {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    tx_queue: u32,
    rx_queue: u32,
    uid: u32,
    inode: u64,
}

/// Shared parser for inet-family `/proc/[pid]/net/*` files (tcp, udp, raw).
///
/// Handles header skipping, line iteration, field splitting, minimum field
/// count, address/queue/uid/inode parsing, and per-row error logging.
/// The `build` closure receives the common fields plus the raw field slice
/// for any protocol-specific extraction (e.g. state).
fn parse_inet_entries<T>(
    reader: impl BufRead,
    family: AddressFamily,
    is_little_endian: bool,
    proto: &str,
    build: impl Fn(InetRow, &[&str]) -> io::Result<T>,
) -> io::Result<Vec<T>> {
    let parse_addr: fn(&str, bool) -> io::Result<SocketAddr> = match family {
        AddressFamily::Inet6 => parse_ipv6_sock_addr,
        _ => parse_ipv4_sock_addr,
    };

    let mut lines = reader.lines();
    if let Some(header) = lines.next() {
        header?;
    }
    let mut entries = Vec::new();
    for line_result in lines {
        let line = line_result?;
        let parse_row = || -> io::Result<T> {
            let fields = line.split_whitespace().collect::<Vec<&str>>();
            if fields.len() < 10 {
                return Err(file_parse_error(proto, &format!("too few fields: {line}")));
            }
            let local_addr = parse_addr(fields[1], is_little_endian)?;
            let peer_addr = parse_addr(fields[2], is_little_endian)?;
            let (tx_queue, rx_queue) = parse_queue_sizes(fields[4])?;
            let uid = fields[7].parse().map_err(|e| {
                file_parse_error(proto, &format!("invalid uid '{}': {e}", fields[7]))
            })?;
            let inode = fields[9].parse().map_err(|e| {
                file_parse_error(proto, &format!("invalid inode '{}': {e}", fields[9]))
            })?;
            build(
                InetRow {
                    local_addr,
                    peer_addr,
                    tx_queue,
                    rx_queue,
                    uid,
                    inode,
                },
                &fields,
            )
        };
        match parse_row() {
            Ok(entry) => entries.push(entry),
            Err(e) => eprintln!("warning: skipping malformed {proto} row: {e}"),
        }
    }
    Ok(entries)
}

impl TcpNetEntries {
    pub fn from_buf_read(
        reader: impl BufRead,
        family: AddressFamily,
        is_little_endian: bool,
    ) -> io::Result<Self> {
        let entries =
            parse_inet_entries(reader, family, is_little_endian, "tcp", |row, fields| {
                let state = TcpState::from(u8::from_str_radix(fields[3], 16).map_err(|e| {
                    file_parse_error("tcp", &format!("invalid state '{}': {e}", fields[3]))
                })?);
                Ok(TcpNetEntry {
                    local_address: row.local_addr,
                    remote_address: row.peer_addr,
                    state,
                    rx_queue: row.rx_queue,
                    tx_queue: row.tx_queue,
                    uid: row.uid,
                    inode: row.inode,
                })
            })?;
        Ok(TcpNetEntries(entries))
    }
}

impl UdpNetEntries {
    pub fn from_buf_read(
        reader: impl BufRead,
        family: AddressFamily,
        is_little_endian: bool,
    ) -> io::Result<Self> {
        let entries =
            parse_inet_entries(reader, family, is_little_endian, "udp", |row, fields| {
                let state = UdpState::from(u8::from_str_radix(fields[3], 16).map_err(|e| {
                    file_parse_error("udp", &format!("invalid state '{}': {e}", fields[3]))
                })?);
                Ok(UdpNetEntry {
                    local_address: row.local_addr,
                    remote_address: row.peer_addr,
                    state,
                    rx_queue: row.rx_queue,
                    tx_queue: row.tx_queue,
                    uid: row.uid,
                    inode: row.inode,
                })
            })?;
        Ok(UdpNetEntries(entries))
    }
}

impl RawNetEntries {
    pub fn from_buf_read(
        reader: impl BufRead,
        family: AddressFamily,
        is_little_endian: bool,
    ) -> io::Result<Self> {
        let entries = parse_inet_entries(reader, family, is_little_endian, "raw", |row, _| {
            Ok(RawNetEntry {
                local_address: row.local_addr,
                remote_address: concrete_peer_addr(row.peer_addr),
                tx_queue: row.tx_queue,
                rx_queue: row.rx_queue,
                uid: row.uid,
                inode: row.inode,
            })
        })?;
        Ok(RawNetEntries(entries))
    }
}
