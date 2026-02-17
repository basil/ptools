//
//   Copyright 2018, 2019 Delphix
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

use std::path::PathBuf;

// Find an executable produced by the Cargo build
pub fn find_exec(name: &str) -> PathBuf {
    // Find the path where Cargo has placed the executables by looking at this test process's
    // executable, which was also built by Cargo.
    let this_exec = std::env::current_exe().unwrap();
    let exec_dir = this_exec.parent().unwrap().parent().unwrap();

    exec_dir.join(name)
}
