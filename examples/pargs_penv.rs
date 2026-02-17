use std::env;
use std::fs::File;
use std::thread;
use std::time::Duration;

fn apply_test_overrides_from_env() {
    let soft = env::var("PTOOLS_TEST_SET_RLIMIT_NOFILE_SOFT").ok();
    let hard = env::var("PTOOLS_TEST_SET_RLIMIT_NOFILE_HARD").ok();
    match (soft, hard) {
        (Some(soft), Some(hard)) => {
            let soft = soft.parse::<u64>().expect("invalid NOFILE soft override");
            let hard = hard.parse::<u64>().expect("invalid NOFILE hard override");
            let lim = nix::libc::rlimit {
                rlim_cur: soft,
                rlim_max: hard,
            };
            let rc = unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_NOFILE, &lim) };
            if rc != 0 {
                panic!(
                    "setrlimit(RLIMIT_NOFILE) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        (None, None) => {}
        _ => panic!("both NOFILE soft/hard overrides must be set together"),
    }

    if let Some(umask) = env::var("PTOOLS_TEST_SET_UMASK").ok() {
        let umask =
            u32::from_str_radix(&umask, 8).expect("invalid umask override (expected octal)");
        unsafe {
            nix::libc::umask(umask);
        }
    }
}

fn main() {
    apply_test_overrides_from_env();

    let signal_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");

    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create(signal_path).unwrap();

    // Wait for the parent to finish running the ptool and then kill us.
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
