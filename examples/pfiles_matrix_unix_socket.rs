use std::env;
use std::fs::File;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let signal_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let unix_socket_path = format!(
        "/tmp/ptools-pfiles-matrix-unix-{}-{}.sock",
        std::process::id(),
        unique
    );
    let _ = std::fs::remove_file(&unix_socket_path);
    let unix_listener = std::os::unix::net::UnixListener::bind(&unix_socket_path).unwrap();

    File::create(signal_path).unwrap();

    let _keep_alive = unix_listener;
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
