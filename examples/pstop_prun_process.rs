use std::env;
use std::fs::File;
use std::thread;
use std::time::Duration;

fn main() {
    let ready_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");

    File::create(ready_path).unwrap();

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
