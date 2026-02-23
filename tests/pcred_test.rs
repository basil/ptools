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

mod common;

#[test]
fn pcred_reports_condensed_credentials() {
    let output = common::run_ptool("pcred", &[], "examples/pcred_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    let mut lines = stdout.lines();
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("Expected credential line in pcred output:\n{}", stdout));

    // A regular process has equal real/effective/saved UIDs and GIDs.
    assert!(
        first.contains("e/r/s/fsuid="),
        "Expected condensed UID format:\n{}",
        stdout
    );
    assert!(
        first.contains("e/r/s/fsgid="),
        "Expected condensed GID format:\n{}",
        stdout
    );
}

#[test]
fn pcred_all_flag_shows_separate_credentials() {
    let output = common::run_ptool("pcred", &["-a"], "examples/pcred_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    let mut lines = stdout.lines();
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("Expected credential line in pcred output:\n{}", stdout));

    assert!(
        first.contains("euid="),
        "Expected separate euid with -a flag:\n{}",
        stdout
    );
    assert!(
        first.contains("ruid="),
        "Expected separate ruid with -a flag:\n{}",
        stdout
    );
    assert!(
        first.contains("suid="),
        "Expected separate suid with -a flag:\n{}",
        stdout
    );
    assert!(
        first.contains("egid="),
        "Expected separate egid with -a flag:\n{}",
        stdout
    );
    assert!(
        first.contains("rgid="),
        "Expected separate rgid with -a flag:\n{}",
        stdout
    );
    assert!(
        first.contains("sgid="),
        "Expected separate sgid with -a flag:\n{}",
        stdout
    );
}

#[test]
fn pcred_reports_groups_when_supplementary_groups_exist() {
    // Check whether this process has supplementary groups. The child inherits
    // them, so we can read our own /proc status to decide what to expect.
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let has_groups = status
        .lines()
        .any(|l| l.starts_with("Groups:") && !l["Groups:".len()..].trim().is_empty());

    if !has_groups {
        // No supplementary groups in this environment (e.g., mock build chroot).
        // Nothing to test -- pcred correctly omits the groups line.
        return;
    }

    // The default mode may suppress the groups line if there is only one group
    // matching rgid, so verify with -a which shows groups unconditionally.
    let output = common::run_ptool("pcred", &["-a"], "examples/pcred_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    assert!(
        stdout.contains("groups:"),
        "Expected groups line with -a flag:\n{}",
        stdout
    );
}
