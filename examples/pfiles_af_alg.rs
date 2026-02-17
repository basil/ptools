use nix::errno::Errno;
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use std::env;
use std::fs::File;
use std::io::Write;
use std::thread;
use std::time::Duration;

fn main() {
    let signal_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");
    let status_path = env::var("PTOOLS_AFALG_STATUS_FILE").ok();

    let alg_socket = match socket(
        AddressFamily::Alg,
        SockType::SeqPacket,
        SockFlag::empty(),
        None,
    ) {
        Ok(fd) => Some(fd),
        Err(Errno::EAFNOSUPPORT | Errno::EPROTONOSUPPORT) => None,
        Err(e) => panic!("failed to create AF_ALG socket: {}", e),
    };
    let alg_supported = alg_socket.is_some();
    let _alg_socket = alg_socket;

    if let Some(path) = status_path {
        let mut status_file = File::create(path).expect("failed to create status file");
        if alg_supported {
            writeln!(status_file, "supported").expect("failed to write status");
        } else {
            writeln!(status_file, "unsupported").expect("failed to write status");
        }
    }

    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create(signal_path).unwrap();

    // Keep the socket alive until killed by test harness.
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
