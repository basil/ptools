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

// Remove jemalloc and use the system allocator instead. Jemalloc accounts for ~300K in a stripped
// binary, and isn't useful here because we will be doing minimal allocation.
use std::alloc::System;
#[global_allocator]
static ALLOCATOR: System = System;

extern crate getopts;
extern crate nix;

use getopts::{Options, ParsingStyle};

use nix::fcntl::OFlag;
use nix::sys::socket::AddressFamily;
use nix::sys::stat::{major, minor, stat, SFlag};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::ParseIntError;
use std::path::Path;
use std::process::exit;

// Issues blocking 0.1 release
//  - Everything marked with BLOCKER
//  - Offset into file for pfiles
//  - Finish pfiles (handle remaining file types)
//  - Update README with current build instructions
//  - Add relevant package metadata
//  - Format code using rustfmt

// Issues for post 0.1 release
// - May want to save space by removing regex crate
// - Add a type alias for Result<Foo, Box<Error>>
// - Add support for handling core dumps
// - Handle unprintable characters in anything we need to print and non-UTF8 in any input
// - Allow a user to be specified in ptree
// - Replace top-level .unwrap()s with a nicer error message
// - Read current environ in penv
// - Test against 32-bit processes
// - Test pfiles against processes with IPv6 sockets
// - illumos pfiles prints socket options for sockets. Is there any way to read those on Linux?
//

//
// Error handling philosophy: in general these tools should try to recover from errors and continue
// to produce useful output. Debugging tools, much more so than other tools, are expected to be run
// on systems which are in unusual and bad states. Indeed, this is when they are most useful. Note
// that this mainly refers to situations where info on the system doesn't match our expectations.
// For instance, if we expect a particular field in /proc/[pid]/status to have a particular value,
// and it doesn't, we shouldn't panic. On the other hand, we should feel free to assert that some
// purely internal invariant holds, and panic if it doesn't.
//

fn usage(program: &str, opts: Options) -> ! {
    usage_impl(program, opts, false);
}

fn usage_err(program: &str, opts: Options) -> ! {
    usage_impl(program, opts, true);
}

fn usage_impl(program: &str, opts: Options, error: bool) -> ! {
    print!("{}\n", opts.short_usage(program));
    std::process::exit(if error { 1 } else { 0 });
}

fn open_or_warn(filename: &str) -> Option<File> {
    match File::open(filename) {
        Ok(file) => Some(file),
        Err(e) => {
            eprintln!("Error opening {}: {}", filename, e);
            None
        }
    }
}

fn print_args(pid: u64) {
    if let Some(file) = open_or_warn(&format!("/proc/{}/cmdline", pid)) {
        print_proc_summary(pid);

        for (i, bytes) in BufReader::new(file).split('\0' as u8).enumerate() {
            match &bytes {
                Ok(bytes) => {
                    let arg = String::from_utf8_lossy(bytes);
                    println!("argv[{}]: {}", i, arg);
                }
                Err(e) => {
                    eprint!("Error reading args: {}", e)
                }
            }
        }
    }
}

fn print_env(pid: u64) {
    // This contains the environ as it was when the proc was started. To get the current
    // environment, we need to inspect its memory to find out how it has change. POSIX defines a
    // char **__environ symbol that we will need to find. Unfortunately, inspecting the memory of
    // another process is not typically permitted, even if the process owned by the same user. See
    // /etc/sysctl.d/10-ptrace.conf for details.
    //
    // Long term, we might want to print the current environment if we can, and print a warning
    // + the contents of /proc/[pid]/environ if we can't
    if let Some(file) = open_or_warn(&format!("/proc/{}/environ", pid)) {
        print_proc_summary(pid);

        for (i, bytes) in BufReader::new(file).split('\0' as u8).enumerate() {
            match &bytes {
                Ok(bytes) => {
                    let arg = String::from_utf8_lossy(bytes);
                    println!("envp[{}]: {}", i, arg);
                }
                Err(e) => {
                    eprint!("Error reading environment: {}", e)
                }
            }
        }
    }
}

// Print the pid and a summary of command line arguments on a single line.
fn print_proc_summary(pid: u64) {
    print!("{:8}", format!("{}:", pid));
    print_cmd_summary(pid);
}

#[derive(Debug)]
struct ParseError {
    reason: String,
}

impl ParseError {
    fn new(item: &str, reason: &str) -> Self {
        ParseError {
            reason: format!("Error parsing {}: {}", item, reason),
        }
    }
    fn in_file(file: &str, reason: &str) -> Self {
        ParseError {
            reason: format!("Error parsing /proc/[pid]/{}: {}", file, reason),
        }
    }
}

impl Error for ParseError {
    fn description(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

// Info parsed from /proc/[pid]/status
struct ProcStat {
    pid: u64,
    fields: HashMap<String, String>,
}

impl ProcStat {
    // What is the stability of 'status' vs 'stat'? Is parsing this more likely to break? Overall,
    // 'stat' seems better designed for parsing, _except_ ...
    //
    // The fields in /proc/[pid]/stat are separated by spaces. Unfortunately, the second field is
    // the command, which can contain spaces. Without knowing what the command is beforehand, we
    // can't parse this file reliably. We can read the command from /proc/[pid]/comm,
    // so we know exactly what to expect, but that would be a pain.
    //
    fn read(pid: u64) -> Result<Self, Box<dyn Error>> {
        // /proc/[pid]/status contains lines of the form
        //
        //    Name:   bash
        //    Umask:  0022
        //    State:  S (sleeping)
        //    ...

        let status_file = ProcStat::status_file(pid);
        let fields = BufReader::new(File::open(&status_file)?)
            .lines()
            .map(|s| {
                let s: String = s?;
                let substrs = s.splitn(2, ":").collect::<Vec<&str>>();
                if substrs.len() < 2 {
                    Err(ParseError::in_file(
                        "status",
                        &format!(
                            "Fewer fields than expected in line '{}' of file {}",
                            s, status_file
                        ),
                    ))?;
                }
                let key = substrs[0].to_string();
                let value = substrs[1].trim().to_string();
                Ok((key, value))
            })
            .collect::<Result<HashMap<String, String>, Box<dyn Error>>>()?;

        Ok(ProcStat {
            pid: pid,
            fields: fields,
        })
    }

    fn status_file(pid: u64) -> String {
        format!("/proc/{}/status", pid)
    }

    fn get_field(&self, field: &str) -> Result<&str, Box<dyn Error>> {
        match self.fields.get(field) {
            Some(val) => Ok(val),
            None => Err(From::from(ParseError::in_file(
                "status",
                &format!(
                    "Missing expected field '{}' in file {}",
                    field,
                    ProcStat::status_file(self.pid)
                ),
            ))),
        }
    }

    fn ppid(&self) -> Result<u64, Box<dyn Error>> {
        Ok(self.get_field("PPid")?.parse()?)
    }
}

// Loop over all the processes listed in /proc/, find the parent of each one, and build a map from
// child to parent and a map from parent to children. There doesn't seem to be a more efficient way
// of doing this reliably.
fn build_proc_maps() -> Result<(HashMap<u64, u64>, HashMap<u64, Vec<u64>>), Box<dyn Error>> {
    let mut child_map = HashMap::new(); // Map of pid to pids of children
    let mut parent_map = HashMap::new(); // Map of pid to pid of parent

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let filename = entry.file_name();
        if let Some(pid) = filename.to_str().and_then(|s| s.parse::<u64>().ok()) {
            let ppid = match ProcStat::read(pid) {
                Ok(proc_stat) => match proc_stat.ppid() {
                    Ok(ppid) => ppid,
                    Err(e) => {
                        eprintln!("{}", e.to_string());
                        continue;
                    }
                },
                // Proc probably exited before we could read its status
                Err(_) => continue,
            };
            child_map.entry(ppid).or_insert(vec![]).push(pid);
            parent_map.insert(pid, ppid);
        }
    }

    Ok((parent_map, child_map))
}

fn print_tree(pid: u64, parent_map: &HashMap<u64, u64>, child_map: &HashMap<u64, Vec<u64>>) {
    let indent_level = if pid == 1 {
        0
    } else {
        if !parent_map.contains_key(&pid) {
            eprintln!("No such pid {}", pid);
            return;
        }
        print_parents(&parent_map, pid)
    };
    print_children(&child_map, pid, indent_level);
}

// Print a summary of command line arguments on a single line.
fn print_cmd_summary(pid: u64) {
    match File::open(format!("/proc/{}/cmdline", pid)) {
        Ok(file) => {
            for arg in BufReader::new(file).take(80).split('\0' as u8) {
                match arg {
                    Ok(arg) => print!("{} ", String::from_utf8_lossy(&arg)),
                    Err(e) => {
                        println!("<error reading cmdline>");
                        eprintln!("{}", e.to_string());
                        break;
                    }
                }
            }
            print!("\n");
        }
        Err(ref e) if e.kind() == ErrorKind::NotFound => {
            println!("<exited>");
        }
        Err(e) => {
            println!("<error reading cmdline>");
            eprintln!("{}", e.to_string());
        }
    }
}

// Returns the current indentation level
fn print_parents(parent_map: &HashMap<u64, u64>, pid: u64) -> u64 {
    let ppid = match parent_map.get(&pid) {
        Some(ppid) => *ppid,
        // Some child process listed 'pid' as its parent, but 'pid' exited before we could read its
        // parent. The child of 'pid' will have been re-parented, and the new parent will be 'init'.
        // It's actually a bit more complicated (see find_new_reaper() in the kernel), and there is
        // one case we might want to handle better: when a child is re-parented to another thread in
        // the thread group.
        None => 1,
    };

    // We've reached the top of the process tree. Don't bother printing the parent if the parent
    // is pid 1. Typically pid 1 didn't really start the process in question.
    if ppid == 1 {
        return 0;
    }

    let indent_level = print_parents(parent_map, ppid);
    print_ptree_line(ppid, indent_level);
    return indent_level + 1;
}

fn print_children(child_map: &HashMap<u64, Vec<u64>>, pid: u64, indent_level: u64) {
    print_ptree_line(pid, indent_level);
    if let Some(children) = child_map.get(&pid) {
        for child in children.iter() {
            print_children(child_map, *child, indent_level + 1);
        }
    }
}

fn print_ptree_line(pid: u64, indent_level: u64) {
    for _ in 0..indent_level {
        print!("  ");
    }
    print!("{}  ", pid);
    print_cmd_summary(pid);
}

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
        // For now we print the Posix file types using the somewhat cryptic macro identifiers used
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
    if let Some(file) = open_or_warn(&filename) {
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

    if let Some(file) = open_or_warn(&format!("/proc/{}/net/netlink", pid)) {
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
        if let Some(file) = open_or_warn(&format!("/proc/{}/net/{}", pid, filename)) {
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

/*
 * Some things about illumos pfiles output seem less than ideal. For instance, would
 * printing 'TCP' be preferrable to 'SOCK_STREAM'? Could we add somewhere in output the
 * psuedo file for the socket? That could be very useful for manually inspecting or
 * draining the output.
 *
 *    435: S_IFSOCK mode:0666 dev:556,0 ino:38252 uid:0 gid:0 rdev:0,0
 *         O_RDWR
 *           SOCK_STREAM
 *           SO_SNDBUF(16384),SO_RCVBUF(5120)
 *           sockname: AF_UNIX
 *           peer: java[1053] zone: global[0]
 *
 * Another example: we can guess by the way that there is no peer address that this socket
 * is listening. Could we make this more explicit? Even for sockets that aren't listening, it
 * might be really useful to know the state of the connection
 *
 *    436: S_IFSOCK mode:0666 dev:556,0 ino:37604 uid:0 gid:0 rdev:0,0
 *         O_RDWR|O_NONBLOCK
 *           SOCK_STREAM
 *           SO_REUSEADDR,SO_SNDBUF(16777216),SO_RCVBUF(4194304)
 *           sockname: AF_INET6 ::  port: 8341
 */

fn print_files(pid: u64) -> bool {
    let proc_dir = format!("/proc/{}/", pid);
    if !Path::new(&proc_dir).exists() {
        eprintln!("No such directory {}", &proc_dir);
        return false;
    }

    print_proc_summary(pid);

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

fn parse_pid(arg: &str) -> Option<u64> {
    match arg.parse::<u64>() {
        Ok(pid) => Some(pid),
        Err(_e) => {
            eprintln!("'{}' is not a valid PID", arg);
            None
        }
    }
}

pub fn pargs_main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];

    let opts = {
        let mut opts = Options::new();
        opts.optflag("a", "", "Print command line args to process");
        // We have a separate penv command, but keep this option for compatibility with Solaris
        opts.optflag("e", "", "Print environement variables of process");
        opts.optflag("h", "help", "print this help message");
        opts.parsing_style(ParsingStyle::StopAtFirstFree);
        opts
    };

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprint!("{}\n", e.to_string());
            usage_err(program, opts);
        }
    };

    if matches.opt_present("h") {
        usage(program, opts);
    }

    if matches.free.len() == 0 {
        usage_err(program, opts);
    }

    let do_print_args = matches.opt_present("a");
    let do_print_env = matches.opt_present("e");

    for arg in &matches.free {
        if let Some(pid) = parse_pid(arg) {
            if do_print_args || !do_print_env {
                print_args(pid);
            }

            if do_print_env {
                print_env(pid);
            }
        }
    }
}

pub fn penv_main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];

    let opts = {
        let mut opts = Options::new();
        opts.optflag("h", "help", "print this help message");
        opts.parsing_style(ParsingStyle::StopAtFirstFree);
        opts
    };

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprint!("{}\n", e.to_string());
            usage_err(program, opts);
        }
    };

    if matches.opt_present("h") {
        usage(program, opts);
    }

    if matches.free.len() == 0 {
        usage_err(program, opts);
    }

    for arg in &matches.free {
        if let Some(pid) = parse_pid(arg) {
            print_env(pid);
        }
    }
}

pub fn pfiles_main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];

    let opts = {
        let mut opts = Options::new();
        opts.optflag("h", "help", "print this help message");
        opts.parsing_style(ParsingStyle::StopAtFirstFree);
        opts
    };

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprint!("{}\n", e.to_string());
            usage_err(program, opts);
        }
    };

    if matches.opt_present("h") {
        usage(program, opts);
    }

    if matches.free.len() == 0 {
        usage_err(program, opts);
    }

    let mut error = false;
    for arg in &matches.free {
        if let Some(pid) = parse_pid(arg) {
            error = error || !print_files(pid);
        }
    }

    if error {
        exit(1);
    }
}

pub fn ptree_main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];

    let opts = {
        let mut opts = Options::new();
        opts.optflag("h", "help", "print this help message");
        opts.parsing_style(ParsingStyle::StopAtFirstFree);
        opts
    };

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprint!("{}\n", e.to_string());
            usage_err(program, opts);
        }
    };

    if matches.opt_present("h") {
        usage(program, opts);
    }

    let (parent_map, child_map) = match build_proc_maps() {
        Ok(maps) => maps,
        Err(e) => {
            eprintln!("Error building parent/child maps: {}", e);
            exit(1);
        }
    };

    if matches.free.len() == 0 {
        // Should we print all processes here, including kernel threads? Is there any way this
        // could miss userspace processes?
        print_tree(1, &parent_map, &child_map);
    } else {
        for arg in &matches.free {
            if let Some(pid) = parse_pid(arg) {
                print_tree(pid, &parent_map, &child_map);
            }
        }
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
