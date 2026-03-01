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

use std::borrow::Cow;
use std::net::SocketAddr;
use std::process::exit;

use nix::fcntl::OFlag;
use nix::sys::socket::AddressFamily;
use nix::sys::stat::major;
use nix::sys::stat::minor;
use ptools::model::fd::FDTarget;
use ptools::model::net::parse_sock_proto_family;
use ptools::model::net::NetEntry;
use ptools::model::net::SockType;
use ptools::model::net::SocketOptions;
use ptools::model::net::TcpState;
use ptools::model::net::UdpState;
use ptools::model::net::UnixState;
use ptools::proc::fd::FileDescriptor;
use ptools::proc::net::Socket;
use ptools::proc::ProcHandle;

fn print_matching_fdinfo_lines(extra_lines: &[String], prefixes: &[&str]) {
    for line in extra_lines
        .iter()
        .filter(|line| prefixes.iter().any(|prefix| line.starts_with(prefix)))
    {
        // Normalize whitespace in key:value lines (kernel pads with many spaces)
        let normalized = if let Some((key, val)) = line.split_once(':') {
            format!("{}: {}", key, val.trim())
        } else {
            line.to_string()
        };
        println!("      {normalized}");
    }
}

fn sockname_from_sockprotoname(sockprotoname: &str) -> String {
    if let Some(addr_fam) = parse_sock_proto_family(sockprotoname) {
        address_family_str(addr_fam).to_string()
    } else {
        sockprotoname.to_string()
    }
}

fn file_type_str(ft: &FDTarget) -> Cow<'static, str> {
    match ft {
        FDTarget::Regular(_) => "S_IFREG".into(),
        FDTarget::Directory(_) => "S_IFDIR".into(),
        FDTarget::SymLink(_) => "S_IFLNK".into(),
        FDTarget::BlockDevice(_) => "S_IFBLK".into(),
        FDTarget::CharDevice(_) => "S_IFCHR".into(),
        FDTarget::Fifo(_) | FDTarget::Pipe(_) => "S_IFIFO".into(),
        FDTarget::Socket(_) => "S_IFSOCK".into(),
        FDTarget::Net(_) => "net".into(),
        FDTarget::Epoll => "anon_inode(epoll)".into(),
        FDTarget::EventFd => "anon_inode(eventfd)".into(),
        FDTarget::SignalFd => "anon_inode(signalfd)".into(),
        FDTarget::TimerFd => "anon_inode(timerfd)".into(),
        FDTarget::Inotify => "anon_inode(inotify)".into(),
        FDTarget::PidFd => "anon_inode(pidfd)".into(),
        FDTarget::Memfd(ref name) => format!("memfd({name})").into(),
        FDTarget::UnknownAnon(ref s) => format!("anon_inode({s})").into(),
        FDTarget::Other(ref type_name, _) => type_name.clone().into(),
        FDTarget::Unknown => "UNKNOWN_TYPE".into(),
    }
}

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

fn open_flags_str(flags: &OFlag) -> String {
    let mut s = match *flags & OFlag::O_ACCMODE {
        OFlag::O_RDONLY => "O_RDONLY",
        OFlag::O_WRONLY => "O_WRONLY",
        OFlag::O_RDWR => "O_RDWR",
        _ => "O_ACCMODE(?)",
    }
    .to_string();
    for &(flag, desc) in FLAG_NAMES {
        if flags.contains(flag) {
            s.push('|');
            s.push_str(desc);
        }
    }
    s
}

fn sock_type_str(st: &SockType) -> Cow<'static, str> {
    match st {
        SockType::Stream => "SOCK_STREAM".into(),
        SockType::Datagram => "SOCK_DGRAM".into(),
        SockType::Raw => "SOCK_RAW".into(),
        SockType::Rdm => "SOCK_RDM".into(),
        SockType::SeqPacket => "SOCK_SEQPACKET".into(),
        SockType::Dccp => "SOCK_DCCP".into(),
        SockType::Packet => "SOCK_PACKET".into(),
        SockType::Unknown(n) => format!("SOCK_TYPE_UNKNOWN_{n}").into(),
    }
}

fn tcp_state_str(state: &TcpState) -> Cow<'static, str> {
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
        TcpState::Unknown(n) => format!("TCP_UNKNOWN_{n:02X}").into(),
    }
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

fn print_sockname(sock: &Socket) {
    let sockname = match &sock.entry {
        NetEntry::Tcp(e) => inet_address_str(sock.family, Some(e.local_address)),
        NetEntry::Udp(e) => inet_address_str(sock.family, Some(e.local_address)),
        NetEntry::Raw(e) => inet_address_str(sock.family, Some(e.local_address)),
        NetEntry::Unix(e) => {
            if let Some(ref path) = e.path {
                format!("AF_UNIX {}", path.display())
            } else {
                "AF_UNIX".to_string()
            }
        }
        NetEntry::Netlink(_) => address_family_str(sock.family).to_string(),
    };
    println!("        sockname: {sockname}");
}

fn print_tcp_info(info: &libc::tcp_info) {
    println!(
        "        cwnd: {}  ssthresh: {}",
        info.tcpi_snd_cwnd, info.tcpi_snd_ssthresh,
    );
    let snd_wscale = if cfg!(target_endian = "little") {
        info.tcpi_snd_rcv_wscale & 0x0f
    } else {
        (info.tcpi_snd_rcv_wscale >> 4) & 0x0f
    };
    let rcv_wscale = if cfg!(target_endian = "little") {
        (info.tcpi_snd_rcv_wscale >> 4) & 0x0f
    } else {
        info.tcpi_snd_rcv_wscale & 0x0f
    };
    println!("        snd_wscale: {snd_wscale}  rcv_wscale: {rcv_wscale}",);

    let rtt_ms = info.tcpi_rtt as f64 / 1000.0;
    let rttvar_ms = info.tcpi_rttvar as f64 / 1000.0;
    println!("        rtt: {rtt_ms:.3}ms  rttvar: {rttvar_ms:.3}ms",);

    println!(
        "        snd_mss: {}  rcv_mss: {}  advmss: {}  pmtu: {}",
        info.tcpi_snd_mss, info.tcpi_rcv_mss, info.tcpi_advmss, info.tcpi_pmtu,
    );
    println!(
        "        unacked: {}  retrans: {}/{}  lost: {}",
        info.tcpi_unacked, info.tcpi_retrans, info.tcpi_total_retrans, info.tcpi_lost,
    );
    println!("        rcv_space: {}", info.tcpi_rcv_space);
}

fn format_socket_options(opts: &SocketOptions) -> String {
    let mut parts = Vec::new();
    if opts.reuse_addr {
        parts.push("SO_REUSEADDR".to_string());
    }
    if opts.keep_alive {
        parts.push("SO_KEEPALIVE".to_string());
    }
    if opts.broadcast {
        parts.push("SO_BROADCAST".to_string());
    }
    if opts.accept_conn {
        parts.push("SO_ACCEPTCONN".to_string());
    }
    if opts.oob_inline {
        parts.push("SO_OOBINLINE".to_string());
    }
    if let Some(sndbuf) = opts.snd_buf {
        parts.push(format!("SO_SNDBUF({sndbuf})"));
    }
    if let Some(rcvbuf) = opts.rcv_buf {
        parts.push(format!("SO_RCVBUF({rcvbuf})"));
    }
    parts.join(",")
}

fn print_peername(sock: &Socket) {
    if let (Some(pid), Some(ref comm)) = (sock.peer_pid, &sock.peer_comm) {
        println!("        peer: {comm}[{pid}]");
    }

    let peer_addr = match &sock.entry {
        NetEntry::Tcp(e) => (!e.remote_address.ip().is_unspecified()).then_some(e.remote_address),
        NetEntry::Udp(e) => (!e.remote_address.ip().is_unspecified()).then_some(e.remote_address),
        NetEntry::Raw(e) => e.remote_address,
        _ => None,
    };

    if let Some(addr) = peer_addr {
        println!(
            "        peername: {}",
            inet_address_str(sock.family, Some(addr))
        );
    }
}

fn print_tcp_details(sock: &Socket) {
    let NetEntry::Tcp(e) = &sock.entry else {
        return;
    };

    if let Some(ref cc) = sock.congestion_control {
        println!("        congestion control: {cc}");
    }

    println!("        state: {}", tcp_state_str(&e.state));

    if e.tx_queue > 0 || e.rx_queue > 0 {
        println!("        tx_queue: {}  rx_queue: {}", e.tx_queue, e.rx_queue);
    }

    if !matches!(e.state, TcpState::Listen) {
        if let Some(ref info) = sock.tcp_info {
            print_tcp_info(info);
        }
    }
}

fn udp_state_str(state: &UdpState) -> Cow<'static, str> {
    match state {
        UdpState::Established => "UDP_ESTABLISHED".into(),
        UdpState::Close => "UDP_CLOSE".into(),
        UdpState::Unknown(n) => format!("UDP_UNKNOWN_{n:02X}").into(),
    }
}

fn unix_state_str(state: &UnixState) -> Cow<'static, str> {
    match state {
        UnixState::Unconnected => "SS_UNCONNECTED".into(),
        UnixState::Connecting => "SS_CONNECTING".into(),
        UnixState::Connected => "SS_CONNECTED".into(),
        UnixState::Disconnecting => "SS_DISCONNECTING".into(),
        UnixState::Unknown(n) => format!("SS_UNKNOWN_{n:02X}").into(),
    }
}

fn print_udp_details(sock: &Socket) {
    let NetEntry::Udp(e) = &sock.entry else {
        return;
    };

    println!("        state: {}", udp_state_str(&e.state));

    if e.tx_queue > 0 || e.rx_queue > 0 {
        println!("        tx_queue: {}  rx_queue: {}", e.tx_queue, e.rx_queue);
    }
}

fn print_raw_details(sock: &Socket) {
    let NetEntry::Raw(e) = &sock.entry else {
        return;
    };

    if e.tx_queue > 0 || e.rx_queue > 0 {
        println!("        tx_queue: {}  rx_queue: {}", e.tx_queue, e.rx_queue);
    }
}

fn print_unix_details(sock: &Socket) {
    let NetEntry::Unix(e) = &sock.entry else {
        return;
    };

    println!("        state: {}", unix_state_str(&e.state));
}

fn netlink_protocol_name(protocol: u32) -> Cow<'static, str> {
    match protocol {
        0 => "NETLINK_ROUTE".into(),
        1 => "NETLINK_UNUSED".into(),
        2 => "NETLINK_USERSOCK".into(),
        3 => "NETLINK_FIREWALL".into(),
        4 => "NETLINK_SOCK_DIAG".into(),
        5 => "NETLINK_NFLOG".into(),
        6 => "NETLINK_XFRM".into(),
        7 => "NETLINK_SELINUX".into(),
        8 => "NETLINK_ISCSI".into(),
        9 => "NETLINK_AUDIT".into(),
        10 => "NETLINK_FIB_LOOKUP".into(),
        11 => "NETLINK_CONNECTOR".into(),
        12 => "NETLINK_NETFILTER".into(),
        13 => "NETLINK_IP6_FW".into(),
        14 => "NETLINK_DNRTMSG".into(),
        15 => "NETLINK_KOBJECT_UEVENT".into(),
        16 => "NETLINK_GENERIC".into(),
        18 => "NETLINK_SCSITRANSPORT".into(),
        19 => "NETLINK_ECRYPTFS".into(),
        20 => "NETLINK_RDMA".into(),
        21 => "NETLINK_CRYPTO".into(),
        22 => "NETLINK_SMC".into(),
        n => format!("NETLINK_UNKNOWN({n})").into(),
    }
}

fn print_netlink_details(sock: &Socket) {
    let NetEntry::Netlink(e) = &sock.entry else {
        return;
    };

    println!("        protocol: {}", netlink_protocol_name(e.protocol));
    println!("        port-id: {}", e.pid);
    println!("        groups: 0x{:08x}", e.groups);
}

fn offset_is_meaningful(target: &FDTarget) -> bool {
    !matches!(
        target,
        FDTarget::Epoll
            | FDTarget::EventFd
            | FDTarget::SignalFd
            | FDTarget::TimerFd
            | FDTarget::Inotify
            | FDTarget::PidFd
            | FDTarget::UnknownAnon(_)
            | FDTarget::Pipe(_)
            | FDTarget::Fifo(_)
            | FDTarget::Net(_)
    )
}

fn print_fd_details(fd: &FileDescriptor) {
    if offset_is_meaningful(&fd.target) {
        println!("      offset: {}", fd.fdinfo.pos);
    }
    match &fd.target {
        FDTarget::Epoll => print_epoll_fdinfo(&fd.fdinfo.extra_lines),
        FDTarget::EventFd => {
            print_matching_fdinfo_lines(&fd.fdinfo.extra_lines, &["eventfd-count:"])
        }
        FDTarget::SignalFd => print_matching_fdinfo_lines(&fd.fdinfo.extra_lines, &["sigmask:"]),
        FDTarget::TimerFd => print_matching_fdinfo_lines(
            &fd.fdinfo.extra_lines,
            &[
                "clockid:",
                "ticks:",
                "settime flags:",
                "it_value:",
                "it_interval:",
            ],
        ),
        FDTarget::Inotify => print_matching_fdinfo_lines(&fd.fdinfo.extra_lines, &["inotify "]),
        FDTarget::PidFd => {
            for line in fd
                .fdinfo
                .extra_lines
                .iter()
                .filter(|l| l.starts_with("Pid:"))
            {
                if let Some((_, val)) = line.split_once(':') {
                    println!("      pid: {}", val.trim());
                }
            }
        }
        _ => {}
    }
}

fn print_file(fd: &FileDescriptor, non_verbose: bool) {
    if let Some(ref st) = fd.stat {
        // Full output -- stat succeeded (live process).
        print!(
            "{: >4}: {} mode:0{:03o} dev:{},{} ino:{} uid:{} gid:{}",
            fd.fd,
            file_type_str(&fd.target),
            st.st_mode & 0o7777,
            major(st.st_dev),
            minor(st.st_dev),
            st.st_ino,
            st.st_uid,
            st.st_gid
        );

        if major(st.st_rdev) == 0 && minor(st.st_rdev) == 0 {
            println!(" size:{}", st.st_size)
        } else {
            println!(" rdev:{},{}", major(st.st_rdev), minor(st.st_rdev));
        }

        if non_verbose {
            return;
        }

        println!("      {}", open_flags_str(&fd.fdinfo.flags));

        match fd.target {
            FDTarget::Socket(_) => {
                if let Some(ref sock) = fd.socket {
                    println!("        {}", sock_type_str(&sock.sock_type));
                    let opts = format_socket_options(&sock.options);
                    if !opts.is_empty() {
                        println!("        {opts}");
                    }
                    print_sockname(sock);
                    print_peername(sock);
                    print_tcp_details(sock);
                    print_udp_details(sock);
                    print_raw_details(sock);
                    print_unix_details(sock);
                    print_netlink_details(sock);
                } else if let Some(ref sockprotoname) = fd.sockprotoname {
                    println!(
                        "        sockname: {}",
                        sockname_from_sockprotoname(sockprotoname)
                    );
                } else {
                    println!(
                        "      ERROR: failed to find info for socket with inode num {}",
                        st.st_ino
                    );
                }
            }
            _ => {
                println!("      {}", fd.target);
                print_fd_details(fd);
            }
        }
    } else {
        // Fallback -- stat failed (coredump or inaccessible fd).
        println!("{: >4}: {}", fd.fd, fd.target);

        if non_verbose {
            return;
        }

        println!("      {}", open_flags_str(&fd.fdinfo.flags));

        if matches!(fd.target, FDTarget::Socket(_)) {
            println!("        (socket details not available)");
        }

        print_fd_details(fd);
    }
}

fn print_epoll_fdinfo(extra_lines: &[String]) {
    for line in extra_lines.iter().filter(|line| line.starts_with("tfd:")) {
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

        print!("      epoll");
        if let Some(tfd) = tfd {
            print!(" tfd: {tfd}");
        }
        if let Some(events) = events {
            print!(" events: {events}");
        }
        if let Some(data) = data {
            print!(" data: {data}");
        }
        if let Some(ino) = ino {
            print!(" ino: {ino}");
        }
        println!();
    }
}

fn print_files(handle: &ProcHandle, non_verbose: bool) -> std::io::Result<()> {
    let pid = handle.pid();

    ptools::display::print_proc_summary_from(handle);
    match handle.nofile_limit() {
        Ok(limit) => {
            println!("  Current rlimit: {} file descriptors", limit.soft);
        }
        Err(e) => eprintln!("pfiles: failed to read RLIMIT_NOFILE for {pid}: {e}"),
    }
    match handle.umask() {
        Ok(umask) => println!("  Current umask: {umask:03o}"),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            eprintln!("pfiles: failed to read umask for {pid}: {e}")
        }
        Err(_) => {}
    }

    let file_descs = handle.file_descriptors()?;

    for fd in &file_descs {
        print_file(fd, non_verbose);
    }

    Ok(())
}

struct Args {
    non_verbose: bool,
    operands: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: pfiles [-n] [pid | core]...");
    eprintln!("Print information for all open files in each process.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -n               Set non-verbose mode");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        non_verbose: false,
        operands: Vec::new(),
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("pfiles: {e}");
        exit(2);
    }) {
        match arg {
            Short('h') | Long("help") => {
                print_usage();
                exit(0);
            }
            Short('V') | Long("version") => {
                println!("pfiles {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            Short('n') => args.non_verbose = true,
            Value(val) => {
                args.operands.push(val.to_string_lossy().into_owned());
            }
            _ => {
                eprintln!("pfiles: unexpected argument: {arg:?}");
                exit(2);
            }
        }
    }

    if args.operands.is_empty() {
        eprintln!("pfiles: at least one PID or core required");
        exit(2);
    }
    args
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();

    let mut error = false;
    let mut first = true;
    for operand in &args.operands {
        if !first {
            println!();
        }
        first = false;
        let handle = match ptools::proc::resolve_operand(operand) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("pfiles: {e}");
                error = true;
                continue;
            }
        };
        if let Err(e) = print_files(&handle, args.non_verbose) {
            eprintln!("pfiles: {}: {e}", handle.pid());
            error = true;
        }
    }

    if error {
        exit(1);
    }
}

#[cfg(test)]
mod test {
    use nix::sys::socket::AddressFamily;

    use super::*;

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
    fn test_file_type_str() {
        use std::path::PathBuf;

        assert_eq!(
            file_type_str(&FDTarget::Regular(PathBuf::from("/tmp/f"))).as_ref(),
            "S_IFREG"
        );
        assert_eq!(file_type_str(&FDTarget::Socket(1)).as_ref(), "S_IFSOCK");
        assert_eq!(
            file_type_str(&FDTarget::BlockDevice(PathBuf::from("/dev/sda"))).as_ref(),
            "S_IFBLK"
        );
        assert_eq!(
            file_type_str(&FDTarget::CharDevice(PathBuf::from("/dev/null"))).as_ref(),
            "S_IFCHR"
        );
        assert_eq!(
            file_type_str(&FDTarget::Directory(PathBuf::from("/tmp"))).as_ref(),
            "S_IFDIR"
        );
        assert_eq!(
            file_type_str(&FDTarget::SymLink(PathBuf::from("/tmp/l"))).as_ref(),
            "S_IFLNK"
        );
        assert_eq!(
            file_type_str(&FDTarget::Fifo(PathBuf::from("/tmp/p"))).as_ref(),
            "S_IFIFO"
        );
        assert_eq!(
            file_type_str(&FDTarget::Epoll).as_ref(),
            "anon_inode(epoll)"
        );
        assert_eq!(
            file_type_str(&FDTarget::EventFd).as_ref(),
            "anon_inode(eventfd)"
        );
        assert_eq!(
            file_type_str(&FDTarget::UnknownAnon("io_uring".to_string())).as_ref(),
            "anon_inode(io_uring)"
        );
        assert_eq!(file_type_str(&FDTarget::Pipe(1)).as_ref(), "S_IFIFO");
        assert_eq!(file_type_str(&FDTarget::Net(1)).as_ref(), "net");
        assert_eq!(
            file_type_str(&FDTarget::Memfd("shm".to_string())).as_ref(),
            "memfd(shm)"
        );
        assert_eq!(
            file_type_str(&FDTarget::Other("fuse".to_string(), 1)).as_ref(),
            "fuse"
        );
        assert_eq!(file_type_str(&FDTarget::Unknown).as_ref(), "UNKNOWN_TYPE");
    }

    #[test]
    fn test_open_flags_str() {
        assert_eq!(open_flags_str(&OFlag::O_RDONLY), "O_RDONLY");
        assert_eq!(
            open_flags_str(&(OFlag::O_RDONLY | OFlag::O_CLOEXEC)),
            "O_RDONLY|O_CLOEXEC"
        );
        assert_eq!(
            open_flags_str(&(OFlag::O_RDWR | OFlag::O_NONBLOCK)),
            "O_RDWR|O_NONBLOCK"
        );
        // O_SYNC includes O_DSYNC bits on Linux, so both flags appear.
        assert_eq!(
            open_flags_str(&(OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_SYNC)),
            "O_WRONLY|O_APPEND|O_DSYNC|O_SYNC"
        );
    }

    #[test]
    fn test_sock_type_str() {
        assert_eq!(sock_type_str(&SockType::Stream).as_ref(), "SOCK_STREAM");
        assert_eq!(sock_type_str(&SockType::Datagram).as_ref(), "SOCK_DGRAM");
        assert_eq!(sock_type_str(&SockType::Raw).as_ref(), "SOCK_RAW");
        assert_eq!(
            sock_type_str(&SockType::Unknown(99)).as_ref(),
            "SOCK_TYPE_UNKNOWN_99"
        );
    }

    #[test]
    fn test_tcp_state_str() {
        assert_eq!(
            tcp_state_str(&TcpState::Established).as_ref(),
            "TCP_ESTABLISHED"
        );
        assert_eq!(tcp_state_str(&TcpState::Listen).as_ref(), "TCP_LISTEN");
        assert_eq!(
            tcp_state_str(&TcpState::Unknown(0xFF)).as_ref(),
            "TCP_UNKNOWN_FF"
        );
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
}
