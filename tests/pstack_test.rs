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
fn pstack_prints_stack_trace() {
    let output = common::run_ptool("pstack", &[], "test_pstack_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    let mut lines = stdout.lines();
    let summary = lines
        .next()
        .unwrap_or_else(|| panic!("Expected process summary line in pstack output:\n{stdout}"));
    assert!(
        summary.contains("test_pstack_process"),
        "Expected summary to contain pstack_process executable name:\n{stdout}"
    );

    // At least one frame line should be present with a hex instruction pointer.
    let frame_lines: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("0x"))
        .collect();
    assert!(
        !frame_lines.is_empty(),
        "Expected at least one stack frame with hex address:\n{stdout}"
    );

    // Each frame line should have a symbol or "???" marker.
    for frame in &frame_lines {
        assert!(
            frame.contains('+') || frame.contains("???"),
            "Expected frame to contain symbol+offset or ???:\n{frame}"
        );
    }
}

#[test]
fn pstack_module_flag_shows_module_paths() {
    let output = common::run_ptool("pstack", &["-m"], "test_pstack_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    let frame_lines: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("0x"))
        .collect();
    assert!(
        !frame_lines.is_empty(),
        "Expected at least one stack frame:\n{stdout}"
    );

    // With -m, at least one frame should show an "in" clause with a module path.
    let has_module = frame_lines.iter().any(|line| line.contains(" in "));
    assert!(
        has_module,
        "Expected at least one frame to show a module path with -m:\n{stdout}"
    );
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "optimized builds may inline source locations"
)]
fn pstack_verbose_shows_source_locations() {
    let output = common::run_ptool("pstack", &["-v"], "test_pstack_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    let frame_lines: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("0x"))
        .collect();
    assert!(
        !frame_lines.is_empty(),
        "Expected at least one stack frame:\n{stdout}"
    );

    // With -v, frames with debug info should show source locations as (file:line).
    let has_source = frame_lines
        .iter()
        .any(|line| line.contains("pstack_process.rs:"));
    assert!(
        has_source,
        "Expected at least one frame to show a source location from pstack_process.rs:\n{stdout}"
    );
}

#[test]
fn pstack_n_limits_frame_count() {
    let output = common::run_ptool(
        "pstack",
        &["-n", "2"],
        "test_pstack_process",
        &[],
        &[],
        false,
    );
    assert!(output.status.success(), "pstack should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

    let frame_count = stdout.lines().filter(|line| line.starts_with("0x")).count();
    assert!(
        frame_count <= 2,
        "Expected at most 2 frames with -n 2, got {frame_count}:\n{stdout}"
    );
}
