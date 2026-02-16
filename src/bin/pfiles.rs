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

use clap::{command, value_parser, Arg};
use nix::fcntl::OFlag;
use nix::sys::socket::AddressFamily;
use nix::sys::stat::{major, minor, stat, SFlag};
use ptools::ParseError;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::ParseIntError;
use std::path::Path;
use std::process::exit;

// TODO Test pfiles against processes with IPv6 sockets
// TODO llumos pfiles prints socket options for sockets. Is there any way to read those on Linux?
// TODO Offset into file for pfiles
// TODO Finish pfiles (handle remaining file types)

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

// As defined by contents of the symlink for the file descriptor in /proc/[pid]/fd/, which has the
// form 'anon_inode:[eventpoll]' TODO better comment
#[derive(PartialEq)]
enum AnonFileType {
    Epoll,
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
        FileType::Anon(AnonFileType::Unknown(s)) => format!("anon_inode({})", s),
        FileType::Unknown => "UNKNOWN_TYPE".into(),
    }
}

fn print_open_flags(flags: u64) {
    let open_flags = vec![
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

    for &(flag, _desc) in open_flags.iter() {
        if (flags as i32 & flag.bits()) != 0 {
            print!("|{:?}", flag); // TODO don't use debug
        }
    }

    // TODO why does illumos print close on exec separately?

    print!("\n");
}

fn get_flags(pid: u64, fd: u64) -> Result<u64, Box<dyn Error>> {
    let mut contents = String::new();
    File::open(format!("/proc/{}/fdinfo/{}", pid, fd))?.read_to_string(&mut contents)?;
    let line = contents
        .lines()
        .filter(|line| line.starts_with("flags:"))
        .collect::<Vec<&str>>()
        .pop()
        .ok_or(ParseError::in_file("fdinfo", "no value 'flags'"))?;
    let str_flags = line.replace("flags:", "");
    Ok(u64::from_str_radix(str_flags.trim(), 8)?)
}

struct SockInfo {
    family: AddressFamily,
    sock_type: SockType,
    inode: u64,
    local_addr: Option<SocketAddr>, // Doesn't apply to unix sockets
    peer_addr: Option<SocketAddr>,  // Doesn't apply to unix sockets
    peer_pid: Option<u64>,          // If the peer is another process on this system
                                    // TODO state: Option<SockState>, // TCP only
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

fn print_sock_address(sock_info: &SockInfo) {
    if let Some(peer_pid) = sock_info.peer_pid {
        println!("         peerpid: {}", peer_pid);
    }

    println!(
        "         sockname: {}",
        match sock_info.family {
            AddressFamily::Inet => inet_address_str(sock_info.family, sock_info.local_addr),
            AddressFamily::Inet6 => inet_address_str(sock_info.family, sock_info.local_addr),
            addr_fam => address_family_str(addr_fam).to_string(),
        }
    );

    // If we have some additional info to print about the remote side of this socket, print it here

    // TODO check that addr is not 0.0.0.0 or :: (Actually, should we make it such that sockaddrs
    // are none in these cases)?
    if let Some(addr) = sock_info.peer_addr {
        if addr.ip() != IpAddr::from([0, 0, 0, 0])
            && addr.ip() != IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0])
        {
            println!(
                "         peername: {} ",
                inet_address_str(sock_info.family, Some(addr))
            );
        }
    }
    // TODO for unix sockets, or for tcp connections connected to another process on this machine,
    // see if we can find and print the pid/comm of the other process
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
                };
                Ok((inode, sock_info))
            })
            .filter_map(|sock_info| ok_or_eprint(sock_info, "netlink"));
        sockets.extend(netlink_sockets);
    }

    // procfs entries for tcp, udp, and raw sockets all use same format
    let mut parse_file = |filename, s_type| {
        if let Some(file) = ptools::open_or_warn(&format!("/proc/{}/net/{}", pid, filename)) {
            let additional_sockets = BufReader::new(file)
                .lines()
                .skip(1) // Header
                .map(move |line| {
                    let line = line?;
                    let fields = line.split_whitespace().collect::<Vec<&str>>();
                    let inode = fields[9].parse()?;
                    let sock_info = SockInfo {
                        family: AddressFamily::Inet,
                        sock_type: s_type,
                        local_addr: Some(parse_ipv4_sock_addr(fields[1])?),
                        peer_addr: Some(parse_ipv4_sock_addr(fields[2])?),
                        peer_pid: None,
                        inode: inode,
                    };
                    Ok((inode, sock_info))
                })
                .filter_map(|sock_info| ok_or_eprint(sock_info, filename));
            sockets.extend(additional_sockets);
        }
    };

    parse_file("tcp", SockType::Stream);
    parse_file("udp", SockType::Datagram);
    parse_file("raw", SockType::Raw);

    sockets
}

// TODO Some things about illumos pfiles output seem less than ideal. For instance, would
// printing 'TCP' be preferrable to 'SOCK_STREAM'? Could we add somewhere in output the
// psuedo file for the socket? That could be very useful for manually inspecting or
// draining the output.
//
//    435: S_IFSOCK mode:0666 dev:556,0 ino:38252 uid:0 gid:0 rdev:0,0
//         O_RDWR
//           SOCK_STREAM
//           SO_SNDBUF(16384),SO_RCVBUF(5120)
//           sockname: AF_UNIX
//           peer: java[1053] zone: global[0]
//
// Another example: we can guess by the way that there is no peer address that this socket
// is listening. Could we make this more explicit? Even for sockets that aren't listening, it
// might be really useful to know the state of the connection
//
//    436: S_IFSOCK mode:0666 dev:556,0 ino:37604 uid:0 gid:0 rdev:0,0
//         O_RDWR|O_NONBLOCK
//           SOCK_STREAM
//           SO_REUSEADDR,SO_SNDBUF(16777216),SO_RCVBUF(4194304)
//           sockname: AF_INET6 ::  port: 8341

fn print_file(pid: u64, fd: u64, sockets: &HashMap<u64, SockInfo>) {
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
        " {: >4}: {} mode:{:o} dev:{},{} ino:{} uid:{} gid:{}",
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

    print!("       ");
    match get_flags(pid, fd) {
        Ok(flags) => print_open_flags(flags),
        Err(e) => eprintln!("failed to read fd flags: {}", e),
    }

    // TODO we can print more specific information for epoll fds by looking at /proc/[pid]/fdinfo/[fd]
    match file_type {
        FileType::Posix(PosixFileType::Socket) => {
            // TODO We should read the 'system.sockprotoname' xattr for /proc/[pid]/fd/[fd] for
            // sockets. That way we can at least print the protocol even if we weren't able to find
            // any info for the socket in procfs.
            // TODO make sure we are displaying information that is for the correct namespace
            // TODO handle IPv6
            if let Some(sock_info) = sockets.get(&(stat_info.st_ino as u64)) {
                debug_assert_eq!(sock_info.inode, stat_info.st_ino as u64);
                print_sock_type(&sock_info.sock_type);
                print_sock_address(&sock_info);
            } else {
                print!(
                    "       ERROR: failed to find info for socket with inode num {}\n",
                    stat_info.st_ino
                );
            }
        }
        _ => match fs::read_link(link_path) {
            Ok(path) => println!("       {}", path.to_string_lossy()),
            Err(e) => eprintln!("failed to readlink {}: {}", &link_path_str, e),
        },
    }
}

fn print_files(pid: u64) -> bool {
    let proc_dir = format!("/proc/{}/", pid);
    if !Path::new(&proc_dir).exists() {
        eprintln!("No such directory {}", &proc_dir);
        return false;
    }

    ptools::print_proc_summary(pid);

    // TODO print current rlimit

    let sockets = fetch_sock_info(pid);

    let fd_dir = format!("/proc/{}/fd/", pid);
    let readdir_res = fs::read_dir(&fd_dir).and_then(|entries| {
        for entry in entries {
            let entry = entry?;
            let filename = entry.file_name();
            let filename = filename.to_string_lossy();
            if let Ok(fd) = (&filename).parse::<u64>() {
                print_file(pid, fd, &sockets);
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
            Arg::new("pid")
                .value_name("PID")
                .help("Process ID (PID)")
                .num_args(1..)
                .required(true)
                .value_parser(value_parser!(u64).range(1..)),
        )
        .get_matches();

    let error = matches
        .get_many::<u64>("pid")
        .unwrap()
        .copied()
        .any(|pid| !print_files(pid));

    if error {
        exit(1);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_parse_ipv4_sock_addr() {
        assert_eq!(
            parse_ipv4_sock_addr("0100007F:1538").unwrap(),
            "127.0.0.1:5432".parse::<SocketAddr>().unwrap()
        );

        assert!(parse_ipv4_sock_addr("0100007F 1538").is_err());
        assert!(parse_ipv4_sock_addr("010000YY:1538").is_err());
        assert!(parse_ipv4_sock_addr("0100007F:15YY").is_err());
    }
}
