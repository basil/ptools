mod common;

#[test]
fn plgrp_shows_home_node_for_all_threads() {
    let output = common::run_ptool("plgrp", &[], "examples/plgrp_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    // Header line should contain HOME.
    let mut lines = stdout.lines();
    let header = lines.next().expect("expected header line");
    assert!(
        header.contains("HOME"),
        "Expected header to contain HOME:\n{}",
        stdout
    );

    // Should have at least two data lines (main thread + spawned thread).
    let data_lines: Vec<&str> = lines.collect();
    assert!(
        data_lines.len() >= 2,
        "Expected at least 2 thread lines, got {}:\n{}",
        data_lines.len(),
        stdout
    );

    // Each data line should contain a PID/TID pair.
    for line in &data_lines {
        assert!(line.contains('/'), "Expected PID/TID in line: {}", line);
    }
}

#[test]
fn plgrp_shows_single_thread_with_tid() {
    // We need pid/tid syntax, so we can't use run_ptool's simple PID appending.
    // Spawn the example manually.
    use std::process::{Command, Stdio};

    let ready = common::ReadySignal::new(false);
    let mut example_cmd = Command::new(common::find_exec("examples/plgrp_process"));
    example_cmd
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit());
    ready.apply_to_command(&mut example_cmd);

    let mut child = example_cmd.spawn().expect("failed to spawn example");
    ready.wait_for_readiness(&mut child);

    let pid = child.id();
    let pid_tid = format!("{}/{}", pid, pid);
    let output = Command::new(common::find_exec("plgrp"))
        .arg(&pid_tid)
        .stdin(Stdio::null())
        .output()
        .expect("failed to run plgrp");

    let _ = child.kill();
    let _ = child.wait();
    ready.cleanup();

    let stdout = common::assert_success_and_get_stdout(output);
    let data_lines: Vec<&str> = stdout.lines().skip(1).collect();
    assert_eq!(
        data_lines.len(),
        1,
        "Expected exactly 1 thread line for specific tid:\n{}",
        stdout
    );
}

#[test]
fn plgrp_affinity_flag_shows_affinity_column() {
    let output = common::run_ptool(
        "plgrp",
        &["-a", "all"],
        "examples/plgrp_process",
        &[],
        &[],
        false,
    );
    let stdout = common::assert_success_and_get_stdout(output);

    let header = stdout.lines().next().expect("expected header line");
    assert!(
        header.contains("AFFINITY"),
        "Expected AFFINITY in header:\n{}",
        stdout
    );

    // Each data line should contain bound or none.
    for line in stdout.lines().skip(1) {
        assert!(
            line.contains("bound") || line.contains("none"),
            "Expected bound or none in affinity line: {}",
            line
        );
    }
}

#[test]
fn plgrp_error_for_nonexistent_pid() {
    let output = common::run_ptool(
        "plgrp",
        &["999999999", "__NO_PID__"],
        "examples/plgrp_process",
        &[],
        &[],
        false,
    );
    assert!(
        !output.status.success(),
        "Expected non-zero exit for nonexistent PID"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("999999999"),
        "Expected error message to mention the PID:\n{}",
        stderr
    );
}
