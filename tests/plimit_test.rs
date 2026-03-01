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
fn plimit_displays_resource_limits() {
    let output = common::run_ptool("plimit", &[], "examples/plimit_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    assert!(
        stdout.contains("RESOURCE"),
        "Expected RESOURCE header:\n{stdout}"
    );
    assert!(
        stdout.contains("CURRENT"),
        "Expected CURRENT header:\n{stdout}"
    );
    assert!(
        stdout.contains("MAXIMUM"),
        "Expected MAXIMUM header:\n{stdout}"
    );

    for name in &[
        "time", "file", "data", "stack", "coredump", "nofiles", "vmemory",
    ] {
        assert!(
            stdout.contains(name),
            "Expected limit '{name}' in output:\n{stdout}"
        );
    }

    // Default mode shows bytes for file/memory sizes.
    assert!(
        stdout.contains("file (bytes)"),
        "Expected bytes unit for file in default mode:\n{stdout}"
    );
}

#[test]
fn plimit_reports_known_nofile_limit() {
    let output = common::run_ptool(
        "plimit",
        &[],
        "examples/plimit_process",
        &[],
        &[
            ("PTOOLS_TEST_SET_RLIMIT_NOFILE_SOFT", "123"),
            ("PTOOLS_TEST_SET_RLIMIT_NOFILE_HARD", "456"),
        ],
        false,
    );
    let stdout = common::assert_success_and_get_stdout(output);

    let nofile_line = stdout
        .lines()
        .find(|l| l.contains("nofiles"))
        .unwrap_or_else(|| panic!("Expected nofiles line in output:\n{stdout}"));

    assert!(
        nofile_line.contains("123"),
        "Expected soft limit 123 in nofiles line:\n{nofile_line}"
    );
    assert!(
        nofile_line.contains("456"),
        "Expected hard limit 456 in nofiles line:\n{nofile_line}"
    );
}

#[test]
fn plimit_k_flag_shows_kilobytes() {
    let output = common::run_ptool(
        "plimit",
        &["-k"],
        "examples/plimit_process",
        &[],
        &[],
        false,
    );
    let stdout = common::assert_success_and_get_stdout(output);

    let file_line = stdout
        .lines()
        .find(|l| l.contains("file ("))
        .unwrap_or_else(|| panic!("Expected file line in output:\n{stdout}"));
    assert!(
        file_line.contains("kilobytes"),
        "Expected kilobytes unit for file with -k:\n{file_line}"
    );

    let coredump_line = stdout
        .lines()
        .find(|l| l.contains("coredump ("))
        .unwrap_or_else(|| panic!("Expected coredump line in output:\n{stdout}"));
    assert!(
        coredump_line.contains("kilobytes"),
        "Expected kilobytes unit for coredump with -k:\n{coredump_line}"
    );
}

#[test]
fn plimit_m_flag_shows_megabytes() {
    let output = common::run_ptool(
        "plimit",
        &["-m"],
        "examples/plimit_process",
        &[],
        &[],
        false,
    );
    let stdout = common::assert_success_and_get_stdout(output);

    for name in &["file", "data", "stack", "coredump", "vmemory"] {
        let line = stdout
            .lines()
            .find(|l| l.contains(&format!("{name} (")))
            .unwrap_or_else(|| panic!("Expected {name} line in output:\n{stdout}"));
        assert!(
            line.contains("megabytes"),
            "Expected megabytes unit for {name} with -m:\n{line}"
        );
    }
}

#[test]
fn plimit_k_flag_converts_stack_bytes_to_kilobytes() {
    let output = common::run_ptool(
        "plimit",
        &["-k"],
        "examples/plimit_process",
        &[],
        &[
            ("PTOOLS_TEST_SET_RLIMIT_STACK_SOFT", "10485760"),
            ("PTOOLS_TEST_SET_RLIMIT_STACK_HARD", "10485760"),
        ],
        false,
    );
    let stdout = common::assert_success_and_get_stdout(output);

    let stack_line = stdout
        .lines()
        .find(|l| l.contains("stack"))
        .unwrap_or_else(|| panic!("Expected stack line in output:\n{stdout}"));

    // 10485760 bytes / 1024 = 10240 kilobytes
    assert!(
        stack_line.contains("10240"),
        "Expected 10240 kilobytes for 10485760 byte stack with -k:\n{stack_line}"
    );
}

#[test]
fn plimit_rejects_missing_pid() {
    let output = common::run_ptool(
        "plimit",
        &["__NO_PID__"],
        "examples/plimit_process",
        &[],
        &[],
        false,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "Expected non-zero exit for missing PID"
    );
    assert!(
        stderr.contains("at least one PID"),
        "Expected usage error:\n{stderr}"
    );
}

#[test]
fn plimit_rejects_invalid_pid() {
    let output = common::run_ptool(
        "plimit",
        &["__NO_PID__", "not_a_pid"],
        "examples/plimit_process",
        &[],
        &[],
        false,
    );
    assert!(
        !output.status.success(),
        "Expected non-zero exit for invalid PID"
    );
}
