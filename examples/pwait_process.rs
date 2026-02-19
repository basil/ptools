use std::env;
use std::fs::File;
use std::thread;
use std::time::Duration;

fn main() {
    let ready_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");

    // How long to sleep before exiting.
    let delay_ms: u64 = env::var("PTOOLS_TEST_DELAY_MS")
        .unwrap_or_else(|_| "200".to_string())
        .parse()
        .expect("PTOOLS_TEST_DELAY_MS must be a number");

    // Exit code to use.
    let exit_code: i32 = env::var("PTOOLS_TEST_EXIT_CODE")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .expect("PTOOLS_TEST_EXIT_CODE must be a number");

    File::create(ready_path).unwrap();

    thread::sleep(Duration::from_millis(delay_ms));

    std::process::exit(exit_code);
}
