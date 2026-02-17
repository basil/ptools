mod common;

use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

fn assert_contains(output: &str, needle: &str) {
    assert!(
        output.contains(needle),
        "Expected to find {:?} in output:\n{}",
        needle,
        output
    );
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

    let signal_file = Path::new("/tmp/ptools-test-ready");
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut examined_proc = Command::new(common::find_exec("examples/args_env"));
    examined_proc
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit());

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

    assert_contains(&stdout, "anon_inode(epoll)");
    assert_contains(&stdout, "anon_inode:[eventpoll]");
    assert_contains(&stdout, "epoll tfd: 3");
}

#[test]
fn pfiles_reports_netlink_socket() {
    let stdout = common::run_ptool("pfiles", "examples/netlink");

    assert_contains(&stdout, "S_IFSOCK");
    assert_contains(&stdout, "SOCK_DGRAM");
    assert_contains(&stdout, "sockname: AF_NETLINK");
}

#[test]
fn pfiles_matrix_covers_file_types_and_socket_families() {
    let stdout = common::run_ptool("pfiles", "examples/pfiles_matrix");

    assert_contains(&stdout, "S_IFCHR");
    assert_contains(&stdout, "/dev/null");

    assert_contains(&stdout, "S_IFREG");
    assert_contains(&stdout, "/tmp/ptools-pfiles-matrix-file");

    assert_contains(&stdout, "S_IFDIR");

    assert_contains(&stdout, "S_IFLNK");
    assert_contains(&stdout, "/tmp/ptools-pfiles-matrix-link");

    if let Some(block_device_path) = find_block_device_path() {
        assert_contains(&stdout, "S_IFBLK");
        assert_contains(&stdout, &block_device_path);
    }

    assert_contains(&stdout, "S_IFIFO");
    assert_contains(&stdout, "pipe:[");

    assert_contains(&stdout, "S_IFSOCK");
    assert_contains(&stdout, "SOCK_STREAM");
    assert_contains(&stdout, "SOCK_DGRAM");
    assert_contains(&stdout, "sockname: AF_UNIX");
    assert_contains(&stdout, "sockname: AF_INET");
    assert_contains(&stdout, "peername: AF_INET");

    assert_contains(&stdout, "anon_inode(epoll)");
    assert_contains(&stdout, "anon_inode(eventfd)");

    assert_contains(&stdout, "O_RDONLY");
    assert_contains(&stdout, "O_WRONLY");
    assert_contains(&stdout, "O_RDWR");
    assert_contains(&stdout, "O_CLOEXEC");
    assert_contains(&stdout, "O_NONBLOCK");

    assert_offset_for_path(&stdout, "/tmp/ptools-pfiles-matrix-file", 3);
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
