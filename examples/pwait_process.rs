//
//   Copyright 2026 Basil Crow
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
