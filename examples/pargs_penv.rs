//
//   Copyright (c) 2026 Basil Crow
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

use std::env;
use std::fs::File;
use std::thread;
use std::time::Duration;

fn apply_test_overrides_from_env() {
    let soft = env::var("PTOOLS_TEST_SET_RLIMIT_NOFILE_SOFT").ok();
    let hard = env::var("PTOOLS_TEST_SET_RLIMIT_NOFILE_HARD").ok();
    match (soft, hard) {
        (Some(soft), Some(hard)) => {
            let soft = soft
                .parse::<nix::libc::rlim_t>()
                .expect("invalid NOFILE soft override");
            let hard = hard
                .parse::<nix::libc::rlim_t>()
                .expect("invalid NOFILE hard override");
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

    if let Ok(umask) = env::var("PTOOLS_TEST_SET_UMASK") {
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
