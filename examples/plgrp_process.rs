use std::env;
use std::fs::File;
use std::thread;
use std::time::Duration;

fn main() {
    let signal_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");

    // Spawn a second thread so the test can verify multi-thread enumeration.
    thread::spawn(move || {
        // Signal readiness from the spawned thread so both threads are alive.
        File::create(signal_path).unwrap();

        loop {
            thread::sleep(Duration::from_millis(100));
        }
    });

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
