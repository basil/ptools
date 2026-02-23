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
