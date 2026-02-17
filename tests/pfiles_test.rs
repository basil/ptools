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
        let is_fd_header_candidate = line
            .chars()
            .next()
            .map(|c| c.is_ascii_whitespace())
            .unwrap_or(false);
        let trimmed = line.trim_start();
        let Some((fd_prefix, rest)) = trimmed.split_once(':') else {
            if let Some(fd) = current_fd {
                fd_map.entry(fd).or_default().push(line.to_string());
            }
            continue;
        };

        if is_fd_header_candidate && fd_prefix.chars().all(|c| c.is_ascii_digit()) {
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

fn drop_sockopts_line(block: &str) -> String {
    block
        .lines()
        .filter(|line| !line.trim_start().starts_with("SO_"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_line(line: &str) -> String {
    if line.trim_start().starts_with("SO_") {
        let normalized = replace_sockopt_value(line, "SO_SNDBUF(");
        return replace_sockopt_value(&normalized, "SO_RCVBUF(");
    }

    if line.trim_start().starts_with("sigmask:") {
        return replace_after_marker(line, "sigmask:", " <dynamic>");
    }
    if line.trim_start().starts_with("clockid:") {
        return replace_after_marker(line, "clockid:", " <dynamic>");
    }
    if line.trim_start().starts_with("ticks:") {
        return replace_after_marker(line, "ticks:", " <dynamic>");
    }
    if line.trim_start().starts_with("settime flags:") {
        return replace_after_marker(line, "settime flags:", " <dynamic>");
    }
    if line.trim_start().starts_with("it_value:") {
        return replace_tuple_value(line, "it_value:", "<dynamic>");
    }
    if line.trim_start().starts_with("it_interval:") {
        return replace_tuple_value(line, "it_interval:", "<dynamic>");
    }
    if line.trim_start().starts_with("inotify ") {
        return format!(
            "{}inotify <dynamic>",
            line.chars()
                .take_while(|c| c.is_ascii_whitespace())
                .collect::<String>()
        );
    }

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

fn replace_sockopt_value(line: &str, marker: &str) -> String {
    let Some(start) = line.find(marker) else {
        return line.to_string();
    };
    let value_start = start + marker.len();
    let Some(end_rel) = line[value_start..].find(')') else {
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
        "{}{}<dynamic>{}",
        &line[..start],
        marker,
        &line[value_end..]
    )
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
        if c.is_ascii_whitespace() {
            value_end += c.len_utf8();
        } else {
            break;
        }
    }
    let mut token_end = value_end;
    for c in line[value_end..].chars() {
        if c.is_ascii_hexdigit() {
            token_end += c.len_utf8();
        } else {
            break;
        }
    }

    if token_end == value_end {
        return line.to_string();
    }

    format!(
        "{}{}{}",
        &line[..value_start],
        replacement,
        &line[token_end..]
    )
}

fn replace_tuple_value(line: &str, marker: &str, replacement: &str) -> String {
    let Some(start) = line.find(marker) else {
        return line.to_string();
    };
    let value_start = start + marker.len();
    let value = line[value_start..].trim_start();
    if !value.starts_with('(') || !value.ends_with(')') {
        return line.to_string();
    }

    let prefix = &line[..value_start];
    let leading_ws = line[value_start..]
        .chars()
        .take_while(|c| c.is_ascii_whitespace())
        .collect::<String>();
    format!("{}{}{}", prefix, leading_ws, replacement)
}

fn assert_offset_for_path(output: &str, path: &str, expected_offset: u64) {
    let lines: Vec<&str> = output.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if line.contains(path) {
            assert!(
                idx + 1 < lines.len(),
                "Found path line without following output: {}",
                line
            );
            let expected = format!("offset: {}", expected_offset);
            assert!(
                lines[idx + 1].contains(&expected),
                "Expected line after {:?} to contain {:?}, got {:?}. Full output:\n{}",
                path,
                expected,
                lines[idx + 1],
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
        .filter_map(|(fd, block)| block.lines().any(|line| line.trim() == path).then_some(*fd))
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

fn count_normalized_exact_blocks(fd_map: &BTreeMap<u32, String>, expected: &str) -> usize {
    fd_map
        .values()
        .map(|block| normalize_dynamic_fields(block))
        .filter(|block| block == expected)
        .count()
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
fn pfiles_prints_header_lines() {
    const EXPECTED_SOFT: u64 = 123;
    const EXPECTED_HARD: u64 = 456;
    const EXPECTED_UMASK: u32 = 0o022;

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
            nix::libc::umask(EXPECTED_UMASK);

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
    let soft_rlimit_line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("Current soft rlimit:"))
        .expect("missing Current soft rlimit line");
    assert_eq!(
        soft_rlimit_line.trim(),
        format!("Current soft rlimit: {} file descriptors", EXPECTED_SOFT)
    );

    let hard_rlimit_line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("Current hard rlimit:"))
        .expect("missing Current hard rlimit line");
    assert_eq!(
        hard_rlimit_line.trim(),
        format!("Current hard rlimit: {} file descriptors", EXPECTED_HARD)
    );

    let umask_line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("Current umask:"))
        .expect("missing Current umask line");
    assert_eq!(
        umask_line.trim(),
        format!("Current umask: {:03o}", EXPECTED_UMASK)
    );
}

#[test]
fn pfiles_reports_epoll_anon_inode() {
    let stdout = common::run_ptool("pfiles", "examples/epoll");
    let fd_map = parse_fd_map(&stdout);

    let null_fd = find_fd_by_path(&fd_map, "/dev/null");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&null_fd).expect("expected /dev/null fd")),
        "S_IFCHR mode:0666 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> rdev:1,3\n       O_RDONLY\n       /dev/null\n       offset: 0"
    );
    let epoll_fd = find_fd_containing(&fd_map, "anon_inode:[eventpoll]");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&epoll_fd).expect("expected eventpoll fd")),
        "anon_inode(epoll) mode:0600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR\n       anon_inode:[eventpoll]\n       offset: 0\n       epoll tfd: <dynamic> events: 19 data: 0 ino: <dynamic>"
    );
}

#[test]
fn pfiles_non_verbose_mode_prints_fstat_only_descriptor_lines() {
    let stdout = common::run_ptool_with_options("pfiles", &["-n"], "examples/epoll", &[], &[]);
    let fd_map = parse_fd_map(&stdout);
    assert!(!fd_map.is_empty(), "expected at least one fd block");
    assert_contains(&stdout, "Current soft rlimit:");
    assert_contains(&stdout, "Current hard rlimit:");
    assert_contains(&stdout, "Current umask:");

    for block in fd_map.values() {
        assert!(
            !block.contains('\n'),
            "expected single-line fd block in -n mode, got:\n{}",
            block
        );
        assert!(
            !block.contains("offset:"),
            "unexpected verbose offset in -n mode:\n{}",
            block
        );
        assert!(
            !block.contains("sockname:"),
            "unexpected socket details in -n mode:\n{}",
            block
        );
        assert!(
            !block.contains("anon_inode:["),
            "unexpected path/details in -n mode:\n{}",
            block
        );
    }
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
        "S_IFCHR mode:0666 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> rdev:1,3\n       O_RDONLY\n       /dev/null\n       offset: 0"
    );
    let netlink_fd = find_fd_containing(&fd_map, "sockname: AF_NETLINK");
    let normalized =
        normalize_dynamic_fields(fd_map.get(&netlink_fd).expect("expected netlink fd"));
    let expected_with_sockopts = "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR\n         sockname: AF_NETLINK\n         SOCK_DGRAM\n         SO_SNDBUF(<dynamic>),SO_RCVBUF(<dynamic>)";
    let expected_without_sockopts = drop_sockopts_line(expected_with_sockopts);
    assert!(
        normalized == expected_with_sockopts || normalized == expected_without_sockopts,
        "netlink fd did not match expected with/without sockopts:\n{}",
        normalized
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
        "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR\n         sockname: AF_ALG"
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
        "S_IFCHR mode:0666 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> rdev:1,3\n       O_RDONLY\n       /dev/null\n       offset: 0"
    );

    let reg_fd = find_fd_by_path(&fd_map, &matrix_file_path);
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&reg_fd).expect("expected regular-file fd")),
        format!(
            "S_IFREG mode:0644 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_WRONLY|O_CLOEXEC\n       {}\n       offset: 3",
            matrix_file_path
        )
    );
    let symlink_fd = find_fd_by_path(&fd_map, &matrix_link_path);
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&symlink_fd).expect("expected symlink fd")),
        format!(
            "S_IFLNK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_PATH\n       {}\n       offset: 0",
            matrix_link_path
        )
    );
    let dir_fd = find_fd_by_path(&fd_map, &cwd);
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&dir_fd).expect("expected cwd directory fd")),
        format!(
            "S_IFDIR mode:0755 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDONLY|O_DIRECTORY\n       {}\n       offset: 0",
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
        assert!(lines[2].trim_start().starts_with("/dev/"));
        assert_eq!(lines[3], "       offset: 0");
    }

    let rd_pipe_fd = find_first_fd_matching(
        &fd_map,
        |block| {
            block.contains("O_RDONLY|O_CLOEXEC")
                && block.contains("\n       pipe:[")
                && block.contains("\n       offset: 0")
        },
        "read pipe block",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&rd_pipe_fd).expect("expected read pipe fd")),
        "S_IFIFO mode:0600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDONLY|O_CLOEXEC\n       pipe:[<dynamic>]\n       offset: 0"
    );
    let wr_pipe_fd = find_first_fd_matching(
        &fd_map,
        |block| {
            block.contains("O_WRONLY|O_CLOEXEC")
                && block.contains("\n       pipe:[")
                && block.contains("\n       offset: 0")
        },
        "write pipe block",
    );
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&wr_pipe_fd).expect("expected write pipe fd")),
        "S_IFIFO mode:0600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_WRONLY|O_CLOEXEC\n       pipe:[<dynamic>]\n       offset: 0"
    );

    let epoll_fd = find_fd_containing(&fd_map, "anon_inode:[eventpoll]");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&epoll_fd).expect("expected eventpoll fd")),
        "anon_inode(epoll) mode:0600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR\n       anon_inode:[eventpoll]\n       offset: 0\n       epoll tfd: <dynamic> events: 19 data: 0 ino: <dynamic>"
    );
    let eventfd_fd = find_fd_containing(&fd_map, "anon_inode:[eventfd]");
    assert_eq!(
        normalize_dynamic_fields(fd_map.get(&eventfd_fd).expect("expected eventfd fd")),
        "anon_inode(eventfd) mode:0600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_NONBLOCK\n       anon_inode:[eventfd]\n       offset: 0\n       eventfd-count:                0"
    );

    let signalfd_expected =
        "anon_inode(signalfd) mode:0600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC|O_NONBLOCK\n       anon_inode:[signalfd]\n       offset: 0\n       sigmask: <dynamic>";
    assert_eq!(
        count_normalized_exact_blocks(&fd_map, signalfd_expected),
        1,
        "expected exactly one normalized signalfd block"
    );

    let timerfd_expected =
        "anon_inode(timerfd) mode:0600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC|O_NONBLOCK\n       anon_inode:[timerfd]\n       offset: 0\n       clockid: <dynamic>\n       ticks: <dynamic>\n       settime flags: <dynamic>\n       it_value: <dynamic>\n       it_interval: <dynamic>";
    assert_eq!(
        count_normalized_exact_blocks(&fd_map, timerfd_expected),
        1,
        "expected exactly one normalized timerfd block"
    );

    let inotify_fd = fd_map
        .iter()
        .find_map(|(fd, block)| {
            normalize_dynamic_fields(block)
                .starts_with("anon_inode(inotify) mode:")
                .then_some(*fd)
        })
        .expect("expected inotify anon inode fd");
    let inotify_block = normalize_dynamic_fields(
        fd_map
            .get(&inotify_fd)
            .expect("expected inotify anon inode fd"),
    );
    let inotify_lines: Vec<&str> = inotify_block.lines().collect();
    assert!(
        inotify_lines.len() >= 5,
        "unexpected inotify block:\n{}",
        inotify_block
    );
    assert_eq!(
        inotify_lines[0],
        "anon_inode(inotify) mode:0600 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>"
    );
    assert_eq!(inotify_lines[1], "       O_RDONLY|O_CLOEXEC|O_NONBLOCK");
    assert!(
        inotify_lines[2] == "       anon_inode:inotify"
            || inotify_lines[2] == "       anon_inode:[inotify]",
        "unexpected inotify path line: {}",
        inotify_lines[2]
    );
    assert_eq!(inotify_lines[3], "       offset: 0");
    assert!(
        inotify_lines[4] == "       inotify <dynamic>",
        "unexpected inotify fdinfo line: {}",
        inotify_lines[4]
    );

    let unix_stream_expected = "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         sockname: AF_UNIX\n         SOCK_STREAM\n         SO_ACCEPTCONN,SO_SNDBUF(<dynamic>),SO_RCVBUF(<dynamic>)";
    assert_eq!(
        count_normalized_exact_blocks(&fd_map, unix_stream_expected),
        1,
        "expected exactly one unix listener socket block"
    );

    let inet_listen_expected = "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         sockname: AF_INET 127.0.0.1  port: <dynamic>\n         SOCK_STREAM\n         SO_ACCEPTCONN,SO_REUSEADDR,SO_SNDBUF(<dynamic>),SO_RCVBUF(<dynamic>)\n         state: TCP_LISTEN";
    assert_eq!(
        count_normalized_exact_blocks(&fd_map, inet_listen_expected),
        1,
        "expected exactly one IPv4 listening socket block"
    );

    let inet_peer_expected = "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         sockname: AF_INET 127.0.0.1  port: <dynamic>\n         SOCK_STREAM\n         SO_SNDBUF(<dynamic>),SO_RCVBUF(<dynamic>)\n         peer: pfiles_matrix[<dynamic>]\n         peername: AF_INET 127.0.0.1  port: <dynamic> \n         state: TCP_ESTABLISHED";
    assert!(
        count_normalized_exact_blocks(&fd_map, inet_peer_expected) >= 1,
        "expected at least one IPv4 established socket block"
    );

    let inet6_listen_expected = "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         sockname: AF_INET6 ::1  port: <dynamic>\n         SOCK_STREAM\n         SO_ACCEPTCONN,SO_REUSEADDR,SO_SNDBUF(<dynamic>),SO_RCVBUF(<dynamic>)\n         state: TCP_LISTEN";
    assert_eq!(
        count_normalized_exact_blocks(&fd_map, inet6_listen_expected),
        1,
        "expected exactly one IPv6 listening socket block"
    );

    let inet6_peer_expected = "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         sockname: AF_INET6 ::1  port: <dynamic>\n         SOCK_STREAM\n         SO_SNDBUF(<dynamic>),SO_RCVBUF(<dynamic>)\n         peer: pfiles_matrix[<dynamic>]\n         peername: AF_INET6 ::1  port: <dynamic> \n         state: TCP_ESTABLISHED";
    assert!(
        count_normalized_exact_blocks(&fd_map, inet6_peer_expected) >= 1,
        "expected at least one IPv6 established socket block"
    );

    let inet_dgram_expected = "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         sockname: AF_INET 127.0.0.1  port: <dynamic>\n         SOCK_DGRAM\n         SO_SNDBUF(<dynamic>),SO_RCVBUF(<dynamic>)";
    assert_eq!(
        count_normalized_exact_blocks(&fd_map, inet_dgram_expected),
        1,
        "expected exactly one IPv4 datagram socket block"
    );

    let inet6_dgram_expected = "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         sockname: AF_INET6 ::1  port: <dynamic>\n         SOCK_DGRAM\n         SO_SNDBUF(<dynamic>),SO_RCVBUF(<dynamic>)";
    assert_eq!(
        count_normalized_exact_blocks(&fd_map, inet6_dgram_expected),
        1,
        "expected exactly one IPv6 datagram socket block"
    );

    assert_offset_for_path(&stdout, &matrix_file_path, 3);
}

#[test]
fn pfiles_reports_socket_options_when_target_is_child_of_inspector() {
    let output = Command::new(common::find_exec("examples/pfiles_sockopts_parent"))
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pfiles_sockopts_parent");

    assert!(
        output.status.success(),
        "socket options harness failed: {:?}",
        output
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let fd_map = parse_fd_map(&stdout);

    let listen_fd = find_first_fd_matching(
        &fd_map,
        |block| block.contains("SOCK_STREAM") && block.contains("state: TCP_LISTEN"),
        "SOCK_STREAM + TCP_LISTEN",
    );
    let listen_normalized = normalize_dynamic_fields(
        fd_map
            .get(&listen_fd)
            .expect("expected listening socket fd"),
    );
    let listen_with_sockopts = "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         sockname: AF_INET 127.0.0.1  port: <dynamic>\n         SOCK_STREAM\n         SO_ACCEPTCONN,SO_REUSEADDR,SO_SNDBUF(<dynamic>),SO_RCVBUF(<dynamic>)\n         state: TCP_LISTEN";
    let listen_without_sockopts = drop_sockopts_line(listen_with_sockopts);
    assert!(
        listen_normalized == listen_with_sockopts || listen_normalized == listen_without_sockopts,
        "listen socket did not match expected with/without sockopts:\n{}",
        listen_normalized
    );

    let dgram_fd = find_first_fd_matching(
        &fd_map,
        |block| block.contains("SOCK_DGRAM") && block.contains("sockname: AF_INET "),
        "SOCK_DGRAM + sockname: AF_INET",
    );
    let dgram_normalized =
        normalize_dynamic_fields(fd_map.get(&dgram_fd).expect("expected udp socket fd"));
    let dgram_with_sockopts = "S_IFSOCK mode:0777 dev:<dynamic> ino:<dynamic> uid:<dynamic> gid:<dynamic> size:<dynamic>\n       O_RDWR|O_CLOEXEC\n         sockname: AF_INET 127.0.0.1  port: <dynamic>\n         SOCK_DGRAM\n         SO_SNDBUF(<dynamic>),SO_RCVBUF(<dynamic>)";
    let dgram_without_sockopts = drop_sockopts_line(dgram_with_sockopts);
    assert!(
        dgram_normalized == dgram_with_sockopts || dgram_normalized == dgram_without_sockopts,
        "dgram socket did not match expected with/without sockopts:\n{}",
        dgram_normalized
    );
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
