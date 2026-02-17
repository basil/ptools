use std::env;
use std::fs::File;
use std::thread;
use std::time::Duration;

fn main() {
    let signal_path =
        env::var("PTOOLS_TEST_READY_FILE").unwrap_or_else(|_| "/tmp/ptools-test-ready".to_string());

    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create(signal_path).unwrap();

    // Wait for the parent to finish running the ptool and then kill us.
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
