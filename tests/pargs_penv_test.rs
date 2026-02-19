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

mod common;

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

    let output = common::run_ptool(
        "pargs",
        &[],
        "examples/pargs_penv",
        &expected_args,
        &[],
        false,
    );
    let stdout = common::assert_success_and_get_stdout(output);

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

    let regular_output = common::run_ptool(
        "pargs",
        &[],
        "examples/pargs_penv",
        &expected_args,
        &[],
        false,
    );
    let regular_stdout = common::assert_success_and_get_stdout(regular_output);
    let argv0 = regular_stdout
        .lines()
        .find(|line| line.starts_with("argv[0]: "))
        .unwrap()
        .trim_start_matches("argv[0]: ");

    let output = common::run_ptool(
        "pargs",
        &["-l"],
        "examples/pargs_penv",
        &expected_args,
        &[],
        false,
    );
    let stdout = common::assert_success_and_get_stdout(output);

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

    let output = common::run_ptool(
        "penv",
        &[],
        "examples/pargs_penv",
        &[],
        &expected_env,
        false,
    );
    let stdout = common::assert_success_and_get_stdout(output);

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

    let output = common::run_ptool(
        "pargs",
        &["-e"],
        "examples/pargs_penv",
        &[],
        &expected_env,
        false,
    );
    let stdout = common::assert_success_and_get_stdout(output);

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
fn pauxv_prints_auxv_entries() {
    let output = common::run_ptool("pauxv", &[], "examples/pargs_penv", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    assert!(
        !stdout.contains("argv["),
        "pauxv should not print argv lines:\n\n{}\n\n",
        stdout
    );
    assert!(
        !stdout.contains("envp["),
        "pauxv should not print env lines:\n\n{}\n\n",
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
        .unwrap_or_else(|| panic!("Expected AT_PAGESZ in pauxv output:\n\n{}\n\n", stdout));
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

#[test]
fn pargs_x_alias_matches_pauxv_output() {
    let pauxv_output = common::run_ptool("pauxv", &[], "examples/pargs_penv", &[], &[], false);
    let pauxv_stdout = common::assert_success_and_get_stdout(pauxv_output);

    let pargs_output = common::run_ptool("pargs", &["-x"], "examples/pargs_penv", &[], &[], false);
    let pargs_stdout = common::assert_success_and_get_stdout(pargs_output);

    // Both should contain AT_PAGESZ
    assert!(
        pauxv_stdout.contains("AT_PAGESZ"),
        "pauxv should contain AT_PAGESZ:\n\n{}\n\n",
        pauxv_stdout
    );
    assert!(
        pargs_stdout.contains("AT_PAGESZ"),
        "pargs -x should contain AT_PAGESZ:\n\n{}\n\n",
        pargs_stdout
    );

    // Both should have the same set of AT_* keys
    let pauxv_keys: Vec<&str> = pauxv_stdout
        .lines()
        .filter(|line| line.starts_with("AT_"))
        .map(|line| line.split_whitespace().next().unwrap())
        .collect();
    let pargs_keys: Vec<&str> = pargs_stdout
        .lines()
        .filter(|line| line.starts_with("AT_"))
        .map(|line| line.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(
        pauxv_keys, pargs_keys,
        "pauxv and pargs -x should produce the same AT_* keys"
    );
}

#[test]
fn pargs_x_prints_auxv_entries() {
    let output = common::run_ptool("pargs", &["-x"], "examples/pargs_penv", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

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
