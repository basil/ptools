use nix::sys::socket::AddressFamily;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::ParseIntError;

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
pub struct SocketInfo {
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
