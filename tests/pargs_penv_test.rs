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

#[test]
fn pargs_matches_started_process_arguments() {
    let expected_args = [
        "simple",
        "contains spaces",
        "quote\"inside",
        "unicode-✓",
        "tabs\tinside",
    ];

    let stdout =
        common::run_ptool_with_options("pargs", &[], "examples/args_env", &expected_args, &[]);

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
fn penv_matches_started_process_environment() {
    let expected_env = [
        ("PTOOLS_TEST_SIMPLE", "value"),
        ("PTOOLS_TEST_WITH_SPACES", "value with spaces"),
        ("PTOOLS_TEST_WITH_EQUALS", "key=value"),
        ("PTOOLS_TEST_UNICODE", "✓"),
    ];

    let stdout =
        common::run_ptool_with_options("penv", &[], "examples/args_env", &[], &expected_env);

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

    let stdout =
        common::run_ptool_with_options("pargs", &["-e"], "examples/args_env", &[], &expected_env);

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
