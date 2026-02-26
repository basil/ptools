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

use std::process::{Command, Stdio};

use common::find_exec;

/// Parse a time string in `S.nnnnnnnnn`, `M:SS.nnnnnnnnn`, or
/// `H:MM:SS.nnnnnnnnn` format into seconds as f64.
fn parse_time_str(s: &str) -> f64 {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        1 => {
            // S.nnnnnnnnn
            s.parse::<f64>()
                .unwrap_or_else(|_| panic!("Failed to parse time: {s}"))
        }
        2 => {
            // M:SS.nnnnnnnnn
            let m: f64 = parts[0]
                .parse()
                .unwrap_or_else(|_| panic!("Failed to parse minutes: {s}"));
            let s_part: f64 = parts[1]
                .parse()
                .unwrap_or_else(|_| panic!("Failed to parse seconds: {s}"));
            m * 60.0 + s_part
        }
        3 => {
            // H:MM:SS.nnnnnnnnn
            let h: f64 = parts[0]
                .parse()
                .unwrap_or_else(|_| panic!("Failed to parse hours: {s}"));
            let m: f64 = parts[1]
                .parse()
                .unwrap_or_else(|_| panic!("Failed to parse minutes: {s}"));
            let s_part: f64 = parts[2]
                .parse()
                .unwrap_or_else(|_| panic!("Failed to parse seconds: {s}"));
            h * 3600.0 + m * 60.0 + s_part
        }
        _ => panic!("Unexpected time format: {s}"),
    }
}

/// Parse stderr for `real`, `user`, and `sys` timing lines.
/// Asserts all three are present and non-negative, returns (real, user, sys).
fn assert_timing_lines(stderr: &str) -> (f64, f64, f64) {
    let mut real = None;
    let mut user = None;
    let mut sys = None;

    for line in stderr.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("real") {
            real = Some(parse_time_str(
                val.split_whitespace().next().unwrap().trim_end_matches('*'),
            ));
        } else if let Some(val) = trimmed.strip_prefix("user") {
            user = Some(parse_time_str(
                val.split_whitespace().next().unwrap().trim_end_matches('*'),
            ));
        } else if let Some(val) = trimmed.strip_prefix("sys") {
            sys = Some(parse_time_str(
                val.split_whitespace().next().unwrap().trim_end_matches('*'),
            ));
        }
    }

    let real = real.unwrap_or_else(|| panic!("Missing 'real' line in stderr:\n{stderr}"));
    let user = user.unwrap_or_else(|| panic!("Missing 'user' line in stderr:\n{stderr}"));
    let sys = sys.unwrap_or_else(|| panic!("Missing 'sys' line in stderr:\n{stderr}"));

    assert!(real >= 0.0, "real time should be non-negative: {real}");
    assert!(user >= 0.0, "user time should be non-negative: {user}");
    assert!(sys >= 0.0, "sys time should be non-negative: {sys}");

    (real, user, sys)
}

#[test]
fn ptime_run_reports_timing() {
    let output = Command::new(find_exec("ptime"))
        .arg("true")
        .stdin(Stdio::null())
        .output()
        .expect("failed to run ptime");

    assert!(
        output.status.success(),
        "ptime true should exit 0, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_timing_lines(&stderr);
}

#[test]
fn ptime_run_preserves_exit_code() {
    let output = Command::new(find_exec("ptime"))
        .arg("false")
        .stdin(Stdio::null())
        .output()
        .expect("failed to run ptime");

    assert_eq!(
        output.status.code(),
        Some(1),
        "ptime false should exit 1, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_timing_lines(&stderr);
}

#[test]
fn ptime_run_nonexistent_command() {
    let output = Command::new(find_exec("ptime"))
        .arg("nonexistent-command-ptools-test")
        .stdin(Stdio::null())
        .output()
        .expect("failed to run ptime");

    assert_eq!(
        output.status.code(),
        Some(127),
        "ptime with nonexistent command should exit 127, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot execute"),
        "Expected 'cannot execute' in stderr:\n{stderr}"
    );
    assert!(
        !stderr.lines().any(|l| l.trim().starts_with("real")),
        "Should not show timing for failed exec:\n{stderr}"
    );
}

#[test]
fn ptime_snapshot_reports_timing() {
    let output = common::run_ptool(
        "ptime",
        &["-p", "__PID__"],
        "examples/pcred_process",
        &[],
        &[],
        false,
    );

    assert!(
        output.status.success(),
        "ptime -p should exit 0, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_timing_lines(&stderr);

    let stdout = String::from_utf8_lossy(&output.stdout);
    // print_proc_summary_from outputs "<pid>:\t<command>"
    assert!(
        stdout.contains(":\t"),
        "Expected process summary in stdout:\n{stdout}"
    );
}

#[test]
fn ptime_snapshot_invalid_pid() {
    let output = Command::new(find_exec("ptime"))
        .args(["-p", "999999999"])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run ptime");

    assert!(
        !output.status.success(),
        "Expected nonzero exit for non-existent PID"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("999999999"),
        "Error message should mention the PID:\n{stderr}"
    );
}
