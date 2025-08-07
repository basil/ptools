//
//   Copyright 2019 Delphix
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

mod common;

#[test]
fn netlink_basic() {
    let stdout = common::run_ptool("pfiles", "netlink_example");
    let lines = stdout.lines().collect::<Vec<&str>>();

    //
    // We expect something along the lines of
    // ...
    //     3: S_IFSOCK mode:777 dev:0,9 ino:725134 uid:65433 gid:50 size:0
    //        O_RDWR
    //          SOCK_DGRAM
    //          sockname: AF_NETLINK
    //
    let pattern = "3: S_IFSOCK";
    let split_lines = lines
        .split(|l| l.trim().starts_with(pattern))
        .collect::<Vec<_>>();

    if split_lines.len() != 2 {
        panic!(
            "String '{}' not found in command output:\n\n{}\n\n",
            pattern, stdout
        );
    }
    let fd_info = split_lines[1];

    let pattern = "sockname: AF_NETLINK";
    if fd_info[2].trim() != pattern {
        panic!(
            "String '{}' not found in command output:\n\n{}\n\n",
            pattern,
            fd_info.join("\n")
        );
    }
}
