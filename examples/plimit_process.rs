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

use nix::sys::resource::{rlim_t, setrlimit, Resource};

fn set_rlimit(resource: Resource, soft_var: &str, hard_var: &str) {
    let soft = env::var(soft_var).ok();
    let hard = env::var(hard_var).ok();
    match (soft, hard) {
        (Some(soft), Some(hard)) => {
            let soft = soft
                .parse::<rlim_t>()
                .unwrap_or_else(|_| panic!("invalid {} override", soft_var));
            let hard = hard
                .parse::<rlim_t>()
                .unwrap_or_else(|_| panic!("invalid {} override", hard_var));
            setrlimit(resource, soft, hard).unwrap_or_else(|e| {
                panic!("setrlimit({resource:?}) failed: {e}");
            });
        }
        (None, None) => {}
        _ => panic!("both {} and {} must be set together", soft_var, hard_var),
    }
}

fn main() {
    set_rlimit(
        Resource::RLIMIT_CORE,
        "PTOOLS_TEST_SET_RLIMIT_CORE_SOFT",
        "PTOOLS_TEST_SET_RLIMIT_CORE_HARD",
    );
    set_rlimit(
        Resource::RLIMIT_NOFILE,
        "PTOOLS_TEST_SET_RLIMIT_NOFILE_SOFT",
        "PTOOLS_TEST_SET_RLIMIT_NOFILE_HARD",
    );
    set_rlimit(
        Resource::RLIMIT_STACK,
        "PTOOLS_TEST_SET_RLIMIT_STACK_SOFT",
        "PTOOLS_TEST_SET_RLIMIT_STACK_HARD",
    );

    let signal_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");

    File::create(signal_path).unwrap();

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
