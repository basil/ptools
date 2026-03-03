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
        let expected_line = arg.to_string();
        if !stdout.contains(&expected_line) {
            panic!("Argument '{arg}' not found in pargs output:\n\n{stdout}\n\n");
        }
    }

    for (i, arg) in expected_args.iter().enumerate() {
        let expected_line = format!("argv[{}]: {}", i + 1, arg);
        if !stdout.contains(&expected_line) {
            panic!("Expected line '{expected_line}' not found in pargs output:\n\n{stdout}\n\n");
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
        "Expected a single command-line output line, got:\n\n{stdout}\n\n"
    );

    // pargs -l resolves argv[0] to the real executable path via /proc/[pid]/exe,
    // so the first token should be the canonical path to the example binary.
    let exe_path = common::find_exec("examples/pargs_penv")
        .canonicalize()
        .unwrap();
    let expected_line = std::iter::once(exe_path.to_str().unwrap())
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
    let stdout = common::assert_success_and_get_stdout_allow_warnings(output);

    for (key, value) in expected_env {
        let expected_line = format!("{key}={value}");
        if !stdout.contains(&expected_line) {
            panic!(
                "Environment variable '{expected_line}' not found in penv output:\n\n{stdout}\n\n"
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
    let stdout = common::assert_success_and_get_stdout_allow_warnings(output);

    for (key, value) in expected_env {
        let expected_line = format!("{key}={value}");
        if !stdout.contains(&expected_line) {
            panic!(
                "Environment variable '{expected_line}' not found in pargs -e output:\n\n{stdout}\n\n"
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
        "pauxv should not print argv lines:\n\n{stdout}\n\n"
    );
    assert!(
        !stdout.contains("envp["),
        "pauxv should not print env lines:\n\n{stdout}\n\n"
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
            value.starts_with("0x") && (value.len() == 10 || value.len() == 18),
            "Expected auxv value to be fixed-width hex, got '{value}' in line '{line}'"
        );
    }

    assert!(
        saw_auxv_line,
        "Expected at least one auxv AT_* line:\n\n{stdout}\n\n"
    );
    let pagesz_line = stdout
        .lines()
        .find(|line| line.starts_with("AT_PAGESZ"))
        .unwrap_or_else(|| panic!("Expected AT_PAGESZ in pauxv output:\n\n{stdout}\n\n"));
    let pagesz_hex = pagesz_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("Expected AT_PAGESZ value in line '{pagesz_line}'"));
    let pagesz = u64::from_str_radix(pagesz_hex.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| panic!("Expected AT_PAGESZ hex value, got '{pagesz_hex}'"));
    let allowed_page_sizes = [0x1000_u64, 0x4000_u64, 0x10000_u64];
    assert!(
        allowed_page_sizes.contains(&pagesz),
        "Unexpected AT_PAGESZ value 0x{pagesz:x}; expected one of {allowed_page_sizes:?}"
    );

    // AT_EXECFN should show the dereferenced string (an absolute path) when
    // process_vm_readv is permitted.  On Ubuntu (yama ptrace_scope=1) the tool
    // process is a sibling, not a parent, of the target so the read is denied
    // and only the hex address is printed.
    let execfn_line = stdout
        .lines()
        .find(|line| line.starts_with("AT_EXECFN"))
        .unwrap_or_else(|| panic!("Expected AT_EXECFN in pauxv output:\n\n{stdout}\n\n"));
    let execfn_tokens: Vec<&str> = execfn_line.split_whitespace().collect();
    if execfn_tokens.len() >= 3 {
        assert!(
            execfn_tokens[2].starts_with('/'),
            "AT_EXECFN string should be an absolute path, got '{}' in '{}'",
            execfn_tokens[2],
            execfn_line
        );
    }

    // AT_PLATFORM: same caveat -- only validate the string when present.
    let platform_line = stdout.lines().find(|line| line.starts_with("AT_PLATFORM "));
    if let Some(platform_line) = platform_line {
        let platform_tokens: Vec<&str> = platform_line.split_whitespace().collect();
        if platform_tokens.len() >= 3 {
            assert!(
                !platform_tokens[2].starts_with("0x"),
                "AT_PLATFORM string should not be a hex address, got '{}' in '{}'",
                platform_tokens[2],
                platform_line
            );
        }
    }
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
        "pauxv should contain AT_PAGESZ:\n\n{pauxv_stdout}\n\n"
    );
    assert!(
        pargs_stdout.contains("AT_PAGESZ"),
        "pargs -x should contain AT_PAGESZ:\n\n{pargs_stdout}\n\n"
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
fn penv_reflects_runtime_setenv() {
    let output = common::run_ptool(
        "penv",
        &[],
        "examples/penv_setenv",
        &[],
        &[("PTOOLS_TEST_OVERWRITE_VAR", "before")],
        false,
    );
    let stdout = common::assert_success_and_get_stdout_allow_warnings(output);

    // PTOOLS_TEST_SETENV_VAR was added at runtime via setenv() and should
    // only be visible when reading the environ symbol (not /proc/pid/environ).
    assert!(
        stdout.contains("PTOOLS_TEST_SETENV_VAR=runtime_value"),
        "Runtime setenv variable not found in penv output:\n\n{stdout}\n\n"
    );

    // PTOOLS_TEST_OVERWRITE_VAR was passed as "before" at spawn time and then
    // overwritten to "after" via setenv().
    assert!(
        stdout.contains("PTOOLS_TEST_OVERWRITE_VAR=after"),
        "Overwritten env variable should show new value in penv output:\n\n{stdout}\n\n"
    );
    assert!(
        !stdout.contains("PTOOLS_TEST_OVERWRITE_VAR=before"),
        "Overwritten env variable should not show old value in penv output:\n\n{stdout}\n\n"
    );
}

#[test]
fn pargs_e_reflects_runtime_setenv() {
    let output = common::run_ptool(
        "pargs",
        &["-e"],
        "examples/penv_setenv",
        &[],
        &[("PTOOLS_TEST_OVERWRITE_VAR", "before")],
        false,
    );
    let stdout = common::assert_success_and_get_stdout_allow_warnings(output);

    assert!(
        stdout.contains("PTOOLS_TEST_SETENV_VAR=runtime_value"),
        "Runtime setenv variable not found in pargs -e output:\n\n{stdout}\n\n"
    );

    assert!(
        stdout.contains("PTOOLS_TEST_OVERWRITE_VAR=after"),
        "Overwritten env variable should show new value in pargs -e output:\n\n{stdout}\n\n"
    );
    assert!(
        !stdout.contains("PTOOLS_TEST_OVERWRITE_VAR=before"),
        "Overwritten env variable should not show old value in pargs -e output:\n\n{stdout}\n\n"
    );
}

#[test]
fn pargs_x_prints_auxv_entries() {
    let output = common::run_ptool("pargs", &["-x"], "examples/pargs_penv", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    assert!(
        !stdout.contains("argv["),
        "pargs -x should not print argv lines:\n\n{stdout}\n\n"
    );
    assert!(
        !stdout.contains("envp["),
        "pargs -x should not print env lines:\n\n{stdout}\n\n"
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
            value.starts_with("0x") && (value.len() == 10 || value.len() == 18),
            "Expected auxv value to be fixed-width hex, got '{value}' in line '{line}'"
        );
    }

    assert!(
        saw_auxv_line,
        "Expected at least one auxv AT_* line:\n\n{stdout}\n\n"
    );
    let pagesz_line = stdout
        .lines()
        .find(|line| line.starts_with("AT_PAGESZ"))
        .unwrap_or_else(|| panic!("Expected AT_PAGESZ in pargs -x output:\n\n{stdout}\n\n"));
    let pagesz_hex = pagesz_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("Expected AT_PAGESZ value in line '{pagesz_line}'"));
    let pagesz = u64::from_str_radix(pagesz_hex.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| panic!("Expected AT_PAGESZ hex value, got '{pagesz_hex}'"));
    let allowed_page_sizes = [0x1000_u64, 0x4000_u64, 0x10000_u64];
    assert!(
        allowed_page_sizes.contains(&pagesz),
        "Unexpected AT_PAGESZ value 0x{pagesz:x}; expected one of {allowed_page_sizes:?}"
    );

    // AT_EXECFN should show the dereferenced string (an absolute path) when
    // process_vm_readv is permitted.  On Ubuntu (yama ptrace_scope=1) the tool
    // process is a sibling, not a parent, of the target so the read is denied
    // and only the hex address is printed.
    let execfn_line = stdout
        .lines()
        .find(|line| line.starts_with("AT_EXECFN"))
        .unwrap_or_else(|| panic!("Expected AT_EXECFN in pargs -x output:\n\n{stdout}\n\n"));
    let execfn_tokens: Vec<&str> = execfn_line.split_whitespace().collect();
    if execfn_tokens.len() >= 3 {
        assert!(
            execfn_tokens[2].starts_with('/'),
            "AT_EXECFN string should be an absolute path, got '{}' in '{}'",
            execfn_tokens[2],
            execfn_line
        );
    }

    // AT_PLATFORM: same caveat -- only validate the string when present.
    let platform_line = stdout.lines().find(|line| line.starts_with("AT_PLATFORM "));
    if let Some(platform_line) = platform_line {
        let platform_tokens: Vec<&str> = platform_line.split_whitespace().collect();
        if platform_tokens.len() >= 3 {
            assert!(
                !platform_tokens[2].starts_with("0x"),
                "AT_PLATFORM string should not be a hex address, got '{}' in '{}'",
                platform_tokens[2],
                platform_line
            );
        }
    }
}
