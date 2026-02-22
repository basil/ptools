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

use nix::sys::socket::{getsockopt, sockopt, AddressFamily};
use ptools::{
    Error, FileDescriptor, FileType, PosixFileType, ProcHandle, SockType, SocketDetails,
    SocketInfo, TcpState,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::net::SocketAddr;
use std::path::Path;
use std::process::exit;

#[derive(Clone)]
struct PeerProcess {
    pid: u64,
    comm: String,
}

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
        println!("      {}", normalized);
    }
}

fn sockname_from_sockprotoname(sockprotoname: &str) -> String {
    if let Some(addr_fam) = ptools::address_family_from_sockprotoname(sockprotoname) {
        address_family_str(addr_fam).to_string()
    } else {
        sockprotoname.to_string()
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

fn print_sockname(sock_info: &SocketInfo) {
    println!(
        "        sockname: {}",
        match sock_info.family {
            AddressFamily::Inet => inet_address_str(sock_info.family, sock_info.local_addr),
            AddressFamily::Inet6 => inet_address_str(sock_info.family, sock_info.local_addr),
            addr_fam => address_family_str(addr_fam).to_string(),
        }
    );
}

fn print_tcp_info(info: &nix::libc::tcp_info) {
    let snd_wscale = info.tcpi_snd_rcv_wscale & 0x0f;
    let rcv_wscale = (info.tcpi_snd_rcv_wscale >> 4) & 0x0f;
    println!(
        "        cwnd: {}  ssthresh: {}",
        info.tcpi_snd_cwnd, info.tcpi_snd_ssthresh,
    );
    println!(
        "        snd_wscale: {}  rcv_wscale: {}",
        snd_wscale, rcv_wscale,
    );

    let rtt_ms = info.tcpi_rtt as f64 / 1000.0;
    let rttvar_ms = info.tcpi_rttvar as f64 / 1000.0;
    println!("        rtt: {:.3}ms  rttvar: {:.3}ms", rtt_ms, rttvar_ms,);

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

fn print_peername(sock_info: &SocketInfo, peer: Option<&PeerProcess>) {
    if let Some(peer) = peer {
        println!("        peer: {}[{}]", peer.comm, peer.pid);
    }

    if let Some(addr) = sock_info.peer_addr {
        println!(
            "        peername: {}",
            inet_address_str(sock_info.family, Some(addr))
        );
    }
}

fn print_tcp_details(details: Option<&SocketDetails>, sock_info: &SocketInfo) {
    if let Some(details) = details {
        if let Some(ref cc) = details.congestion_control {
            println!("        congestion control: {}", cc);
        }
    }

    if let Some(state) = sock_info.tcp_state {
        println!("        state: {}", state);
    }

    if let (Some(tx), Some(rx)) = (sock_info.tx_queue, sock_info.rx_queue) {
        if tx > 0 || rx > 0 {
            println!("        tx_queue: {}  rx_queue: {}", tx, rx);
        }
    }

    if let Some(details) = details {
        if sock_info.tcp_state.is_some() && !matches!(sock_info.tcp_state, Some(TcpState::Listen)) {
            if let Some(ref info) = details.tcp_info {
                print_tcp_info(info);
            }
        }
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

fn derive_peer_processes(
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

fn print_fd_details(fd: &FileDescriptor) {
    println!("      offset: {}", fd.offset);
    match fd.path.as_os_str().to_string_lossy().as_ref() {
        "anon_inode:[eventpoll]" => print_epoll_fdinfo(&fd.extra_lines),
        "anon_inode:[eventfd]" => print_matching_fdinfo_lines(&fd.extra_lines, &["eventfd-count:"]),
        "anon_inode:[signalfd]" => print_matching_fdinfo_lines(&fd.extra_lines, &["sigmask:"]),
        "anon_inode:[timerfd]" => print_matching_fdinfo_lines(
            &fd.extra_lines,
            &[
                "clockid:",
                "ticks:",
                "settime flags:",
                "it_value:",
                "it_interval:",
            ],
        ),
        "anon_inode:inotify" | "anon_inode:[inotify]" => {
            print_matching_fdinfo_lines(&fd.extra_lines, &["inotify "])
        }
        _ => {}
    }
}

fn print_file(fd: &FileDescriptor, pid: u64, peers: &HashMap<u64, PeerProcess>, non_verbose: bool) {
    if let Some(ref st) = fd.stat {
        // Full output -- stat succeeded (live process).
        print!(
            "{: >4}: {} mode:{:04o} dev:{},{} ino:{} uid:{} gid:{}",
            fd.fd,
            fd.file_type,
            st.mode & 0o7777,
            st.dev_major,
            st.dev_minor,
            st.inode,
            st.uid,
            st.gid
        );

        if st.rdev_major == 0 && st.rdev_minor == 0 {
            println!(" size:{}", st.size)
        } else {
            println!(" rdev:{},{}", st.rdev_major, st.rdev_minor);
        }

        if non_verbose {
            return;
        }

        println!("      {}", fd.open_flags);

        match fd.file_type {
            FileType::Posix(PosixFileType::Socket) => {
                if let Some(ref sock) = fd.socket {
                    let sock_info = &sock.info;
                    print_sockname(sock_info);
                    let peer =
                        peers
                            .get(&sock_info.inode)
                            .cloned()
                            .or_else(|| match sock_info.family {
                                // SO_PEERCRED on duplicated fd -- live-only.
                                AddressFamily::Unix => unix_peer_process(pid, fd.fd),
                                _ => None,
                            });
                    print_peername(sock_info, peer.as_ref());
                    println!("        {}", sock_info.sock_type);
                    if let Some(ref details) = sock.details {
                        if !details.options.is_empty() {
                            println!("        {}", details.options.join(","));
                        }
                    }
                    print_tcp_details(sock.details.as_ref(), sock_info);
                } else if let Some(ref sockprotoname) = fd.sockprotoname {
                    println!(
                        "        sockname: {}",
                        sockname_from_sockprotoname(sockprotoname)
                    );
                } else {
                    println!(
                        "      ERROR: failed to find info for socket with inode num {}",
                        st.inode
                    );
                }
            }
            _ => {
                println!("      {}", fd.path.to_string_lossy());
                print_fd_details(fd);
            }
        }
    } else {
        // Fallback -- stat failed (coredump or inaccessible fd).
        println!("{: >4}: {}", fd.fd, fd.path.to_string_lossy());

        if non_verbose {
            return;
        }

        println!("      {}", fd.open_flags);

        if fd.path.to_string_lossy().starts_with("socket:[") {
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

fn print_files(handle: &ProcHandle, non_verbose: bool) -> Result<(), Error> {
    let pid = handle.pid();

    ptools::print_proc_summary_from(handle);
    match handle.nofile_limit() {
        Ok(limit) => {
            let fmt = |v: ptools::RlimitVal| match v {
                Some(n) => n.to_string(),
                None => "unlimited".into(),
            };
            println!(
                "  Current soft rlimit: {} file descriptors",
                fmt(limit.soft)
            );
            println!(
                "  Current hard rlimit: {} file descriptors",
                fmt(limit.hard)
            );
        }
        Err(e) => eprintln!("Failed to read RLIMIT_NOFILE for {}: {}", pid, e),
    }
    match handle.umask() {
        Ok(umask) => println!("  Current umask: {:03o}", umask),
        Err(e) => eprintln!("Failed to read umask for {}: {}", pid, e),
    }

    let file_descs = handle.file_descriptors().map_err(|e| {
        eprintln!("Unable to read /proc/{}/fd/: {}", pid, e);
        e
    })?;

    // derive_peer_processes does system-wide /proc scan; skip when there are
    // no sockets to match (always the case for coredump sources).
    let has_sockets = file_descs.iter().any(|f| f.socket.is_some());
    let peers = if has_sockets {
        let sockets = handle.socket_info();
        derive_peer_processes(pid, &sockets)
    } else {
        HashMap::new()
    };

    for fd in &file_descs {
        print_file(fd, pid, &peers, non_verbose);
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
        let handle = match ptools::resolve_operand(operand) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("pfiles: {e}");
                error = true;
                continue;
            }
        };
        for w in handle.warnings() {
            eprintln!("{w}");
        }
        if print_files(&handle, args.non_verbose).is_err() {
            error = true;
        }
    }

    if error {
        exit(1);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nix::sys::socket::AddressFamily;

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
}
