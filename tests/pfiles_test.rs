mod common;

use std::os::unix::fs::FileTypeExt;
use std::process::Command;

fn assert_contains(output: &str, needle: &str) {
    assert!(
        output.contains(needle),
        "Expected to find {:?} in output:\n{}",
        needle,
        output
    );
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
fn pfiles_reports_epoll_anon_inode() {
    let stdout = common::run_ptool("pfiles", "examples/epoll");

    assert_contains(&stdout, "anon_inode(epoll)");
    assert_contains(&stdout, "anon_inode:[eventpoll]");
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
