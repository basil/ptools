use std::fs::File;
use std::thread;
use std::time::Duration;

fn main() {
    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create("/tmp/ptools-test-ready").unwrap();

    // Wait for the parent to finish running the ptool and then kill us.
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
