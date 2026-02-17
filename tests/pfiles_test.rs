mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn assert_contains(output: &str, needle: &str) {
    assert!(
        output.contains(needle),
        "Expected to find {:?} in output:\n{}",
        needle,
        output
    );
}

fn parse_fd_map(output: &str) -> BTreeMap<u32, String> {
    let mut fd_map: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let mut current_fd: Option<u32> = None;

    for line in output.lines() {
        let trimmed = line.trim_start();
        let Some((fd_prefix, rest)) = trimmed.split_once(':') else {
            if let Some(fd) = current_fd {
                fd_map.entry(fd).or_default().push(line.to_string());
            }
            continue;
        };

        if fd_prefix.chars().all(|c| c.is_ascii_digit()) {
            let fd = fd_prefix.parse::<u32>().expect("fd should parse as u32");
            current_fd = Some(fd);
            fd_map
                .entry(fd)
                .or_default()
                .push(rest.trim_start().to_string());
        } else if let Some(fd) = current_fd {
            fd_map.entry(fd).or_default().push(line.to_string());
        }
    }

    fd_map
        .into_iter()
        .map(|(fd, lines)| (fd, lines.join("\n")))
        .collect()
}

fn normalize_dynamic_fields(block: &str) -> String {
    block
        .lines()
        .map(normalize_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_line(line: &str) -> String {
    let mut normalized = line.to_string();

    normalized = replace_token(&normalized, "dev:", "<dynamic>");
    normalized = replace_token(&normalized, "ino:", "<dynamic>");
    normalized = replace_token(&normalized, "uid:", "<dynamic>");
    normalized = replace_token(&normalized, "gid:", "<dynamic>");
    normalized = replace_token(&normalized, "size:", "<dynamic>");
    normalized = replace_pipe_inode(&normalized);
    normalized = replace_port(&normalized);
    normalized = replace_after_marker(&normalized, "epoll tfd: ", "<dynamic>");
    normalized = replace_peer_pid(&normalized);

    normalized
}

fn replace_token(line: &str, marker: &str, replacement: &str) -> String {
    let Some(start) = line.find(marker) else {
        return line.to_string();
    };

    let value_start = start + marker.len();
    let mut ws_end = value_start;
    for c in line[value_start..].chars() {
        if c == ' ' {
            ws_end += c.len_utf8();
        } else {
            break;
        }
    }

    let mut value_end = ws_end;
    for c in line[ws_end..].chars() {
        if c.is_ascii_hexdigit() || c == ',' {
            value_end += c.len_utf8();
        } else {
            break;
        }
    }

    if value_end == ws_end {
        return line.to_string();
    }

    let mut out = String::new();
    out.push_str(&line[..ws_end]);
    out.push_str(replacement);
    out.push_str(&line[value_end..]);
    out
}

fn replace_pipe_inode(line: &str) -> String {
    let Some(start) = line.find("pipe:[") else {
        return line.to_string();
    };
    let value_start = start + "pipe:[".len();
    let Some(end_rel) = line[value_start..].find(']') else {
        return line.to_string();
    };
    let value_end = value_start + end_rel;

    if !line[value_start..value_end]
        .chars()
        .all(|c| c.is_ascii_digit())
    {
        return line.to_string();
    }

    format!(
        "{}pipe:[<dynamic>]{}",
        &line[..start],
        &line[value_end + 1..]
    )
}

fn replace_port(line: &str) -> String {
    let Some(start) = line.find("port: ") else {
        return line.to_string();
    };
    let value_start = start + "port: ".len();
    let mut value_end = value_start;
    for c in line[value_start..].chars() {
        if c.is_ascii_digit() {
            value_end += c.len_utf8();
        } else {
            break;
        }
    }

    if value_end == value_start {
        return line.to_string();
    }

    format!("{}port: <dynamic>{}", &line[..start], &line[value_end..])
}

fn replace_peer_pid(line: &str) -> String {
    let Some(start) = line.find("peer: ") else {
        return line.to_string();
    };
    let Some(open_rel) = line[start..].find('[') else {
        return line.to_string();
    };
    let open = start + open_rel;
    let Some(close_rel) = line[open + 1..].find(']') else {
        return line.to_string();
    };
    let close = open + 1 + close_rel;
    if !line[open + 1..close].chars().all(|c| c.is_ascii_digit()) {
        return line.to_string();
    }

    format!("{}[<dynamic>]{}", &line[..open], &line[close + 1..])
}

fn replace_after_marker(line: &str, marker: &str, replacement: &str) -> String {
    let Some(start) = line.find(marker) else {
        return line.to_string();
    };
    let value_start = start + marker.len();
    let mut value_end = value_start;
    for c in line[value_start..].chars() {
        if c.is_ascii_digit() {
            value_end += c.len_utf8();
        } else {
            break;
        }
    }

    if value_end == value_start {
        return line.to_string();
    }

    format!(
        "{}{}{}",
        &line[..value_start],
        replacement,
        &line[value_end..]
    )
}

fn assert_offset_for_path(output: &str, path: &str, expected_offset: u64) {
    let lines: Vec<&str> = output.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if line.contains(path) {
            assert!(
                idx > 0,
                "Found path line without preceding output: {}",
                line
            );
            let expected = format!("offset: {}", expected_offset);
            assert!(
                lines[idx - 1].contains(&expected),
                "Expected line before {:?} to contain {:?}, got {:?}. Full output:\n{}",
                path,
                expected,
                lines[idx - 1],
                output
            );
            return;
        }
    }

    panic!("Path {:?} not found in output:\n{}", path, output);
}

fn find_block_device_path() -> Option<String> {
    std::fs::read_dir("/dev").ok()?.flatten().find_map(|entry| {
        let path = entry.path();
        let metadata = std::fs::metadata(&path).ok()?;
        if metadata.file_type().is_block_device() {
            Some(path.to_string_lossy().to_string())
        } else {
            None
        }
    })
}

fn find_fd_by_path(fd_map: &BTreeMap<u32, String>, path: &str) -> u32 {
    let matches: Vec<u32> = fd_map
        .iter()
        .filter_map(|(fd, block)| {
            block
                .lines()
                .last()
                .map(|line| line.trim() == path)
                .unwrap_or(false)
                .then_some(*fd)
        })
        .collect();

    assert_eq!(
        matches.len(),
        1,
        "Expected exactly one fd block ending with path {:?}, got {}",
        path,
        matches.len()
    );

    matches[0]
}

fn find_fd_containing(fd_map: &BTreeMap<u32, String>, needle: &str) -> u32 {
    let matches: Vec<u32> = fd_map
        .iter()
        .filter_map(|(fd, block)| {
            if block.contains(needle) {
                Some(*fd)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        matches.len(),
        1,
        "Expected exactly one fd containing {:?}, got {}",
        needle,
        matches.len()
    );

    matches[0]
}

fn find_first_fd_matching<F>(fd_map: &BTreeMap<u32, String>, mut predicate: F, context: &str) -> u32
where
    F: FnMut(&str) -> bool,
{
    fd_map
        .iter()
        .find_map(|(fd, block)| predicate(block).then_some(*fd))
        .unwrap_or_else(|| panic!("Expected at least one fd matching {}", context))
}

fn unique_matrix_prefix() -> String {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    format!(
        "/tmp/ptools-pfiles-matrix-{}-{}",
        std::process::id(),
        unique
    )
}

#[test]
fn pfiles_rejects_missing_pid() {
    let output = Command::new(common::find_exec("pfiles"))
        .output()
        .expect("failed to run pfiles");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_contains(&stderr, "Usage:");
    assert_contains(&stderr, "PID");
}

#[test]
fn pfiles_rejects_pid_zero() {
    let output = Command::new(common::find_exec("pfiles"))
        .arg("0")
        .output()
        .expect("failed to run pfiles");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_contains(&stderr, "invalid value");
}

#[test]
fn pfiles_prints_current_nofile_rlimit() {
    const EXPECTED_SOFT: u64 = 123;
    const EXPECTED_HARD: u64 = 456;

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let signal_path = format!("/tmp/ptools-test-ready-{}-{}", std::process::id(), unique);
    let signal_file = Path::new(&signal_path);
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut examined_proc = Command::new(common::find_exec("examples/args_env"));
    examined_proc
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .env("PTOOLS_TEST_READY_FILE", &signal_path);

    unsafe {
        examined_proc.pre_exec(|| {
            let lim = nix::libc::rlimit {
                rlim_cur: EXPECTED_SOFT,
                rlim_max: EXPECTED_HARD,
            };

            if nix::libc::setrlimit(nix::libc::RLIMIT_NOFILE, &lim) != 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        });
    }

    let mut examined_proc = examined_proc.spawn().expect("failed to spawn args_env");

    while !signal_file.exists() {
        if let Some(status) = examined_proc.try_wait().expect("failed to wait on child") {
            panic!("Child exited too soon with status {}", status)
        }
    }

    let output = Command::new(common::find_exec("pfiles"))
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pfiles");

    examined_proc.kill().expect("failed to kill child process");
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let rlimit_line = stdout
        .lines()
        .find(|line| line.contains("RLIMIT_NOFILE soft:"))
        .expect("missing RLIMIT_NOFILE line");

    let parts: Vec<&str> = rlimit_line.split_whitespace().collect();
    assert!(
        parts.len() >= 5,
        "unexpected RLIMIT_NOFILE line format: {}",
        rlimit_line
    );

    assert_eq!(parts[2], EXPECTED_SOFT.to_string());
    assert_eq!(parts[4], EXPECTED_HARD.to_string());
}

#[test]
fn pfiles_reports_epoll_anon_inode() {
    let stdout = common::run_ptool("pfiles", "examples/epoll");
    let fd_map = parse_fd_map(&stdout);

    let null_fd = find_fd_by_path(&fd_map, "/dev/null");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&null_fd).expect("expected /dev/null fd")),
        "S_IFCHR mode:666 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> rdev:1,3\n       O_RDONLY\n         offset: 0\n       /dev/null"
    );
    let epoll_fd = find_fd_containing(&fd_map, "anon_inode:[eventpoll]");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&epoll_fd).expect("expected eventpoll fd")),
        "anon_inode(epoll) mode:600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR\n         offset: 0\n       anon_inode:[eventpoll]\n       epoll tfd: <dynamic> events: 19 data: 0 ino: <dynamic>"
    );
}

#[test]
fn pfiles_resolves_socket_metadata_for_target_net_namespace() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let signal_path = format!("/tmp/ptools-test-ready-{}-{}", std::process::id(), unique);
    let signal_file = Path::new(&signal_path);
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let example = common::find_exec("examples/netlink");
    let mut unshare_cmd = Command::new("unshare");
    unshare_cmd
        .arg("--net")
        .arg(example)
        .env("PTOOLS_TEST_READY_FILE", &signal_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut examined_proc = match unshare_cmd.spawn() {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("Skipping net namespace e2e test: unshare not installed");
            return;
        }
        Err(e) => panic!("failed to launch unshare for pfiles_matrix: {}", e),
    };

    while !signal_file.exists() {
        if let Some(status) = examined_proc
            .try_wait()
            .expect("failed waiting for unshare child")
        {
            let stderr = examined_proc
                .wait_with_output()
                .expect("failed to collect unshare output")
                .stderr;
            let stderr = String::from_utf8_lossy(&stderr);
            if status.code() == Some(1)
                && (stderr.contains("Operation not permitted")
                    || stderr.contains("unshare failed")
                    || stderr.contains("Invalid argument"))
            {
                eprintln!(
                    "Skipping net namespace e2e test: unshare unavailable in this environment: {}",
                    stderr.trim()
                );
                return;
            }
            panic!(
                "unshare child exited before readiness signal, status: {}, stderr: {}",
                status, stderr
            );
        }
    }

    let output = Command::new(common::find_exec("pfiles"))
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pfiles");

    examined_proc.kill().expect("failed to kill unshare child");
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    assert!(output.status.success(), "pfiles failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !stdout.contains("ERROR: failed to find info for socket with inode num"),
        "socket metadata lookup failed unexpectedly in target net namespace:
{}",
        stdout
    );
    assert_contains(&stdout, "sockname: AF_NETLINK");
}

#[test]
fn pfiles_reports_netlink_socket() {
    let stdout = common::run_ptool("pfiles", "examples/netlink");
    let fd_map = parse_fd_map(&stdout);

    let null_fd = find_fd_by_path(&fd_map, "/dev/null");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&null_fd).expect("expected /dev/null fd")),
        "S_IFCHR mode:666 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> rdev:1,3\n       O_RDONLY\n         offset: 0\n       /dev/null"
    );
    let netlink_fd = find_fd_containing(&fd_map, "sockname: AF_NETLINK");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&netlink_fd).expect("expected netlink fd")),
        "S_IFSOCK mode:777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR\n         offset: 0\n         SOCK_DGRAM\n         sockname: AF_NETLINK"
    );
}

#[test]
fn pfiles_falls_back_to_sockprotoname_xattr_for_unknown_socket_family() {
    use nix::errno::Errno;
    use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};

    let alg_socket = match socket(
        AddressFamily::Alg,
        SockType::SeqPacket,
        SockFlag::empty(),
        None,
    ) {
        Ok(fd) => fd,
        Err(Errno::EAFNOSUPPORT | Errno::EPROTONOSUPPORT) => {
            eprintln!("skipping test: AF_ALG sockets are not supported by this kernel");
            return;
        }
        Err(e) => panic!("failed to create AF_ALG socket: {}", e),
    };

    let output = Command::new(common::find_exec("pfiles"))
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pfiles");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let fd_map = parse_fd_map(&stdout);
    let fd = alg_socket.as_raw_fd() as u32;
    assert_eq!(
        normalize_dynamic_fields(
            fd_map
                .get(&fd)
                .unwrap_or_else(|| panic!("missing fd block for AF_ALG socket fd {}", fd)),
        ),
        "S_IFSOCK mode:777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR\n         offset: 0\n         sockname: AF_ALG"
    );
}

#[test]
fn pfiles_matrix_covers_file_types_and_socket_families() {
    let matrix_prefix = unique_matrix_prefix();
    let matrix_file_path = format!("{}-file", matrix_prefix);
    let matrix_link_path = format!("{}-link", matrix_prefix);
    let stdout = common::run_ptool_with_options(
        "pfiles",
        &[],
        "examples/pfiles_matrix",
        &[],
        &[("PTOOLS_MATRIX_PREFIX", matrix_prefix.as_str())],
    );
    let fd_map = parse_fd_map(&stdout);
    let cwd = std::env::current_dir()
        .expect("failed to get cwd")
        .to_string_lossy()
        .to_string();

    let null_fd = find_fd_by_path(&fd_map, "/dev/null");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&null_fd).expect("expected /dev/null fd")),
        "S_IFCHR mode:666 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> rdev:1,3\n       O_RDONLY\n         offset: 0\n       /dev/null"
    );

    let reg_fd = find_fd_by_path(&fd_map, &matrix_file_path);
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&reg_fd).expect("expected regular-file fd")),
        format!(
            "S_IFREG mode:644 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_WRONLY|O_CLOEXEC\n         offset: 3\n       {}",
            matrix_file_path
        )
    );
    let symlink_fd = find_fd_by_path(&fd_map, &matrix_link_path);
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&symlink_fd).expect("expected symlink fd")),
        format!(
            "S_IFLNK mode:777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_PATH\n         offset: 0\n       {}",
            matrix_link_path
        )
    );
    let dir_fd = find_fd_by_path(&fd_map, &cwd);
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&dir_fd).expect("expected cwd directory fd")),
        format!(
            "S_IFDIR mode:755 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDONLY|O_DIRECTORY\n         offset: 0\n       {}",
            cwd
        )
    );

    if find_block_device_path().is_some() {
        let block_devices: Vec<&str> = fd_map
            .values()
            .map(|s| s.as_str())
            .filter(|block| block.starts_with("S_IFBLK "))
            .collect();
        assert!(
            !block_devices.is_empty(),
            "expected at least one S_IFBLK fd block, output:\n{}",
            stdout
        );

        let block_device = normalize_dynamic_fields(block_devices[0]);
        let lines: Vec<&str> = block_device.lines().collect();
        assert!(
            lines.len() >= 4,
            "Unexpected S_IFBLK block: {}",
            block_device
        );
        assert_eq!(lines[1], "       O_RDONLY|O_CLOEXEC|O_PATH");
        assert_eq!(lines[2], "         offset: 0");
        assert!(lines[3].trim_start().starts_with("/dev/"));
    }

    let rd_pipe_fd = find_fd_containing(
        &fd_map,
        "O_RDONLY|O_CLOEXEC\n         offset: 0\n       pipe:[",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&rd_pipe_fd).expect("expected read pipe fd")),
        "S_IFIFO mode:600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDONLY|O_CLOEXEC\n         offset: 0\n       pipe:[<dynamic>]"
    );
    let wr_pipe_fd = find_fd_containing(
        &fd_map,
        "O_WRONLY|O_CLOEXEC\n         offset: 0\n       pipe:[",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&wr_pipe_fd).expect("expected write pipe fd")),
        "S_IFIFO mode:600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_WRONLY|O_CLOEXEC\n         offset: 0\n       pipe:[<dynamic>]"
    );

    let epoll_fd = find_fd_containing(&fd_map, "anon_inode:[eventpoll]");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&epoll_fd).expect("expected eventpoll fd")),
        "anon_inode(epoll) mode:600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR\n         offset: 0\n       anon_inode:[eventpoll]\n       epoll tfd: <dynamic> events: 19 data: 0 ino: <dynamic>"
    );
    let eventfd_fd = find_fd_containing(&fd_map, "anon_inode:[eventfd]");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&eventfd_fd).expect("expected eventfd fd")),
        "anon_inode(eventfd) mode:600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_NONBLOCK\n         offset: 0\n       anon_inode:[eventfd]"
    );

    let unix_stream_fd = find_first_fd_matching(
        &fd_map,
        |block| block.contains("SOCK_STREAM") && block.contains("sockname: AF_UNIX"),
        "SOCK_STREAM + sockname: AF_UNIX",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&unix_stream_fd).expect("expected unix stream fd")),
        "S_IFSOCK mode:777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         offset: 0\n         SOCK_STREAM\n         sockname: AF_UNIX"
    );

    let inet_listen_fd = find_first_fd_matching(
        &fd_map,
        |block| {
            block.contains("SOCK_STREAM")
                && block.contains("sockname: AF_INET")
                && !block.contains("peername: AF_INET")
        },
        "SOCK_STREAM + sockname: AF_INET without peername",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&inet_listen_fd).expect("expected inet listen fd")),
        "S_IFSOCK mode:777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         offset: 0\n         SOCK_STREAM\n         sockname: AF_INET 127.0.0.1  port: <dynamic>\n         state: TCP_LISTEN"
    );

    let inet_peer_fd = find_first_fd_matching(
        &fd_map,
        |block| block.contains("SOCK_STREAM") && block.contains("peername: AF_INET"),
        "SOCK_STREAM + peername: AF_INET",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&inet_peer_fd).expect("expected fd with peername")),
        "S_IFSOCK mode:777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         offset: 0\n         SOCK_STREAM\n         peer: pfiles_matrix[<dynamic>]\n         sockname: AF_INET 127.0.0.1  port: <dynamic>\n         peername: AF_INET 127.0.0.1  port: <dynamic> \n         state: TCP_ESTABLISHED"
    );

    let inet6_listen_fd = find_first_fd_matching(
        &fd_map,
        |block| {
            block.contains("SOCK_STREAM")
                && block.contains("sockname: AF_INET6")
                && !block.contains("peername: AF_INET6")
        },
        "SOCK_STREAM + sockname: AF_INET6 without peername",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&inet6_listen_fd).expect("expected inet6 listen fd")),
        "S_IFSOCK mode:777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         offset: 0\n         SOCK_STREAM\n         sockname: AF_INET6 ::1  port: <dynamic>\n         state: TCP_LISTEN"
    );

    let inet6_peer_fd = find_first_fd_matching(
        &fd_map,
        |block| block.contains("SOCK_STREAM") && block.contains("peername: AF_INET6"),
        "SOCK_STREAM + peername: AF_INET6",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&inet6_peer_fd).expect("expected fd with inet6 peername")),
        "S_IFSOCK mode:777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         offset: 0\n         SOCK_STREAM\n         peer: pfiles_matrix[<dynamic>]\n         sockname: AF_INET6 ::1  port: <dynamic>\n         peername: AF_INET6 ::1  port: <dynamic> \n         state: TCP_ESTABLISHED"
    );

    let inet_dgram_fd = find_first_fd_matching(
        &fd_map,
        |block| block.contains("SOCK_DGRAM") && block.contains("sockname: AF_INET "),
        "SOCK_DGRAM + sockname: AF_INET",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&inet_dgram_fd).expect("expected inet dgram fd")),
        "S_IFSOCK mode:777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         offset: 0\n         SOCK_DGRAM\n         sockname: AF_INET 127.0.0.1  port: <dynamic>"
    );

    let inet6_dgram_fd = find_first_fd_matching(
        &fd_map,
        |block| block.contains("SOCK_DGRAM") && block.contains("sockname: AF_INET6"),
        "SOCK_DGRAM + sockname: AF_INET6",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&inet6_dgram_fd).expect("expected inet6 dgram fd")),
        "S_IFSOCK mode:777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         offset: 0\n         SOCK_DGRAM\n         sockname: AF_INET6 ::1  port: <dynamic>"
    );

    assert_offset_for_path(&stdout, &matrix_file_path, 3);
}

#[test]
fn pfiles_exits_nonzero_when_any_pid_fails() {
    let output = common::run_ptool_with_options_and_capture(
        "pfiles",
        &["999999999"],
        "examples/args_env",
        &[],
        &[],
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_contains(&stderr, "No such directory /proc/999999999/");
}
