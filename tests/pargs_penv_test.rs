//
//   Copyright 2026 Delphix
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

use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }

    let is_shell_safe = arg
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
    if is_shell_safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\"'\"'"))
    }
}

#[test]
fn pargs_matches_started_process_arguments() {
    let expected_args = [
        "simple",
        "contains spaces",
        "quote\"inside",
        "unicode-✓",
        "tabs\tinside",
    ];

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let test_pid = std::process::id();
    let signal_path = format!("/tmp/ptools-test-ready-{}-{}", test_pid, unique);
    let signal_file = Path::new(&signal_path);
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut examined_proc = Command::new(common::find_exec("examples/pargs_penv"))
        .args(expected_args)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .env("PTOOLS_TEST_READY_FILE", &signal_path)
        .spawn()
        .unwrap();

    while !signal_file.exists() {
        if let Some(status) = examined_proc.try_wait().unwrap() {
            panic!("Child exited too soon with status {}", status)
        }
        thread::sleep(Duration::from_millis(5));
    }

    let output = Command::new(common::find_exec("pargs"))
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = examined_proc.kill();
    let _ = examined_proc.wait();
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stderr, "");
    assert!(output.status.success());
    let stdout = stdout.into_owned();

    for arg in expected_args {
        let expected_line = format!("{}", arg);
        if !stdout.contains(&expected_line) {
            panic!(
                "Argument '{}' not found in pargs output:\n\n{}\n\n",
                arg, stdout
            );
        }
    }

    for (i, arg) in expected_args.iter().enumerate() {
        let expected_line = format!("argv[{}]: {}", i + 1, arg);
        if !stdout.contains(&expected_line) {
            panic!(
                "Expected line '{}' not found in pargs output:\n\n{}\n\n",
                expected_line, stdout
            );
        }
    }
}

#[test]
fn pargs_l_matches_started_process_arguments_as_shell_command_line() {
    let expected_args = [
        "simple",
        "contains spaces",
        "quote\"inside",
        "unicode-✓",
        "tabs\tinside",
    ];

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let test_pid = std::process::id();
    let signal_path = format!("/tmp/ptools-test-ready-{}-{}", test_pid, unique);
    let signal_file = Path::new(&signal_path);
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut examined_proc = Command::new(common::find_exec("examples/pargs_penv"))
        .args(expected_args)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .env("PTOOLS_TEST_READY_FILE", &signal_path)
        .spawn()
        .unwrap();

    while !signal_file.exists() {
        if let Some(status) = examined_proc.try_wait().unwrap() {
            panic!("Child exited too soon with status {}", status)
        }
        thread::sleep(Duration::from_millis(5));
    }

    let output = Command::new(common::find_exec("pargs"))
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = examined_proc.kill();
    let _ = examined_proc.wait();
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let regular_stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stderr, "");
    assert!(output.status.success());
    let regular_stdout = regular_stdout.into_owned();
    let argv0 = regular_stdout
        .lines()
        .find(|line| line.starts_with("argv[0]: "))
        .unwrap()
        .trim_start_matches("argv[0]: ");

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let test_pid = std::process::id();
    let signal_path = format!("/tmp/ptools-test-ready-{}-{}", test_pid, unique);
    let signal_file = Path::new(&signal_path);
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut examined_proc = Command::new(common::find_exec("examples/pargs_penv"))
        .args(expected_args)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .env("PTOOLS_TEST_READY_FILE", &signal_path)
        .spawn()
        .unwrap();

    while !signal_file.exists() {
        if let Some(status) = examined_proc.try_wait().unwrap() {
            panic!("Child exited too soon with status {}", status)
        }
        thread::sleep(Duration::from_millis(5));
    }

    let output = Command::new(common::find_exec("pargs"))
        .arg("-l")
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = examined_proc.kill();
    let _ = examined_proc.wait();
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stderr, "");
    assert!(output.status.success());
    let stdout = stdout.into_owned();

    let mut lines = stdout.lines();
    let command_line = lines.next().unwrap_or("");
    assert_eq!(
        lines.next(),
        None,
        "Expected a single command-line output line, got:\n\n{}\n\n",
        stdout
    );

    let expected_line = std::iter::once(argv0)
        .chain(expected_args.iter().copied())
        .map(shell_quote)
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(command_line, expected_line);
}

#[test]
fn penv_matches_started_process_environment() {
    let expected_env = [
        ("PTOOLS_TEST_SIMPLE", "value"),
        ("PTOOLS_TEST_WITH_SPACES", "value with spaces"),
        ("PTOOLS_TEST_WITH_EQUALS", "key=value"),
        ("PTOOLS_TEST_UNICODE", "✓"),
    ];

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let test_pid = std::process::id();
    let signal_path = format!("/tmp/ptools-test-ready-{}-{}", test_pid, unique);
    let signal_file = Path::new(&signal_path);
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut examined_proc = Command::new(common::find_exec("examples/pargs_penv"))
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .env("PTOOLS_TEST_READY_FILE", &signal_path)
        .envs(expected_env.iter().copied())
        .spawn()
        .unwrap();

    while !signal_file.exists() {
        if let Some(status) = examined_proc.try_wait().unwrap() {
            panic!("Child exited too soon with status {}", status)
        }
        thread::sleep(Duration::from_millis(5));
    }

    let output = Command::new(common::find_exec("penv"))
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = examined_proc.kill();
    let _ = examined_proc.wait();
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stderr, "");
    assert!(output.status.success());
    let stdout = stdout.into_owned();

    for (key, value) in expected_env {
        let expected_line = format!("{}={}", key, value);
        if !stdout.contains(&expected_line) {
            panic!(
                "Environment variable '{}' not found in penv output:\n\n{}\n\n",
                expected_line, stdout
            );
        }
    }
}

#[test]
fn pargs_e_alias_matches_started_process_environment() {
    let expected_env = [
        ("PTOOLS_TEST_SIMPLE", "value"),
        ("PTOOLS_TEST_WITH_SPACES", "value with spaces"),
        ("PTOOLS_TEST_WITH_EQUALS", "key=value"),
        ("PTOOLS_TEST_UNICODE", "✓"),
    ];

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let test_pid = std::process::id();
    let signal_path = format!("/tmp/ptools-test-ready-{}-{}", test_pid, unique);
    let signal_file = Path::new(&signal_path);
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut examined_proc = Command::new(common::find_exec("examples/pargs_penv"))
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .env("PTOOLS_TEST_READY_FILE", &signal_path)
        .envs(expected_env.iter().copied())
        .spawn()
        .unwrap();

    while !signal_file.exists() {
        if let Some(status) = examined_proc.try_wait().unwrap() {
            panic!("Child exited too soon with status {}", status)
        }
        thread::sleep(Duration::from_millis(5));
    }

    let output = Command::new(common::find_exec("pargs"))
        .arg("-e")
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = examined_proc.kill();
    let _ = examined_proc.wait();
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stderr, "");
    assert!(output.status.success());
    let stdout = stdout.into_owned();

    for (key, value) in expected_env {
        let expected_line = format!("{}={}", key, value);
        if !stdout.contains(&expected_line) {
            panic!(
                "Environment variable '{}' not found in pargs -e output:\n\n{}\n\n",
                expected_line, stdout
            );
        }
    }
}

#[test]
fn pargs_x_prints_auxv_entries() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let test_pid = std::process::id();
    let signal_path = format!("/tmp/ptools-test-ready-{}-{}", test_pid, unique);
    let signal_file = Path::new(&signal_path);
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut examined_proc = Command::new(common::find_exec("examples/pargs_penv"))
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .env("PTOOLS_TEST_READY_FILE", &signal_path)
        .spawn()
        .unwrap();

    while !signal_file.exists() {
        if let Some(status) = examined_proc.try_wait().unwrap() {
            panic!("Child exited too soon with status {}", status)
        }
        thread::sleep(Duration::from_millis(5));
    }

    let output = Command::new(common::find_exec("pargs"))
        .arg("-x")
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = examined_proc.kill();
    let _ = examined_proc.wait();
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stderr, "");
    assert!(output.status.success());
    let stdout = stdout.into_owned();

    assert!(
        !stdout.contains("argv["),
        "pargs -x should not print argv lines:\n\n{}\n\n",
        stdout
    );
    assert!(
        !stdout.contains("envp["),
        "pargs -x should not print env lines:\n\n{}\n\n",
        stdout
    );

    let mut saw_auxv_line = false;
    for line in stdout.lines() {
        if !line.starts_with("AT_") {
            continue;
        }
        saw_auxv_line = true;
        let mut parts = line.split_whitespace();
        let _key = parts.next().unwrap();
        let value = parts.next().unwrap_or("");
        assert!(
            value.starts_with("0x") && value.len() == 18,
            "Expected auxv value to be fixed-width hex, got '{}' in line '{}'",
            value,
            line
        );
    }

    assert!(
        saw_auxv_line,
        "Expected at least one auxv AT_* line:\n\n{}\n\n",
        stdout
    );
    let pagesz_line = stdout
        .lines()
        .find(|line| line.starts_with("AT_PAGESZ"))
        .unwrap_or_else(|| panic!("Expected AT_PAGESZ in pargs -x output:\n\n{}\n\n", stdout));
    let pagesz_hex = pagesz_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("Expected AT_PAGESZ value in line '{}'", pagesz_line));
    let pagesz = u64::from_str_radix(pagesz_hex.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| panic!("Expected AT_PAGESZ hex value, got '{}'", pagesz_hex));
    let allowed_page_sizes = [0x1000_u64, 0x4000_u64, 0x10000_u64];
    assert!(
        allowed_page_sizes.contains(&pagesz),
        "Unexpected AT_PAGESZ value 0x{:x}; expected one of {:?} for amd64/arm64",
        pagesz,
        allowed_page_sizes
    );
}
