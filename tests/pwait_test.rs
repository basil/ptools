mod common;

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::{find_exec, ReadySignal};

/// Spawn the pwait_process example with the given environment overrides.
/// Returns the child and the ReadySignal for cleanup.
fn spawn_example(env: &[(&str, &str)]) -> (std::process::Child, ReadySignal) {
    let ready = ReadySignal::new(false);
    let mut cmd = Command::new(find_exec("examples/pwait_process"));
    cmd.stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .envs(env.iter().copied());
    ready.apply_to_command(&mut cmd);

    let mut child = cmd.spawn().expect("failed to spawn example");
    ready.wait_for_readiness(&mut child);
    (child, ready)
}

#[test]
fn pwait_waits_for_process_to_exit() {
    let (mut child, ready) = spawn_example(&[("PTOOLS_TEST_DELAY_MS", "300")]);
    let pid = child.id();

    let start = Instant::now();
    let output = Command::new(find_exec("pwait"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pwait");

    let elapsed = start.elapsed();
    let _ = child.wait();
    ready.cleanup();

    assert!(output.status.success(), "pwait should exit 0");
    // Should have actually waited (not returned immediately).
    assert!(
        elapsed >= Duration::from_millis(100),
        "pwait returned too quickly ({:?}), should have waited for process",
        elapsed
    );
    // stdout should be empty in non-verbose mode.
    assert!(
        output.stdout.is_empty(),
        "Non-verbose pwait should produce no stdout"
    );
}

#[test]
fn pwait_verbose_reports_termination() {
    let (mut child, ready) = spawn_example(&[("PTOOLS_TEST_DELAY_MS", "200")]);
    let pid = child.id();

    let output = Command::new(find_exec("pwait"))
        .args(["-v", &pid.to_string()])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pwait");

    let _ = child.wait();
    ready.cleanup();

    assert!(output.status.success(), "pwait -v should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should contain the PID and "terminated".
    assert!(
        stdout.contains(&format!("{}: terminated", pid)),
        "Expected termination message for pid {}, got: {}",
        pid,
        stdout
    );
}

#[test]
fn pwait_invalid_pid_exits_nonzero() {
    let output = Command::new(find_exec("pwait"))
        .arg("999999999")
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pwait");

    assert!(
        !output.status.success(),
        "Expected nonzero exit for non-existent PID"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("999999999"),
        "Error message should mention the PID: {}",
        stderr
    );
}

#[test]
fn pwait_waits_for_multiple_processes() {
    let (mut child1, ready1) = spawn_example(&[("PTOOLS_TEST_DELAY_MS", "200")]);
    let (mut child2, ready2) = spawn_example(&[("PTOOLS_TEST_DELAY_MS", "400")]);
    let pid1 = child1.id();
    let pid2 = child2.id();

    let start = Instant::now();
    let output = Command::new(find_exec("pwait"))
        .args(["-v", &pid1.to_string(), &pid2.to_string()])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pwait");

    let elapsed = start.elapsed();
    let _ = child1.wait();
    let _ = child2.wait();
    ready1.cleanup();
    ready2.cleanup();

    assert!(output.status.success(), "pwait should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Both PIDs should be reported.
    assert!(
        stdout.contains(&format!("{}: terminated", pid1)),
        "Missing termination for pid {}: {}",
        pid1,
        stdout
    );
    assert!(
        stdout.contains(&format!("{}: terminated", pid2)),
        "Missing termination for pid {}: {}",
        pid2,
        stdout
    );
    // Should have waited for the slower process.
    assert!(
        elapsed >= Duration::from_millis(200),
        "pwait returned too quickly ({:?}), should have waited for both processes",
        elapsed
    );
}

#[test]
fn pwait_duplicate_pids_reported_once() {
    let (mut child, ready) = spawn_example(&[("PTOOLS_TEST_DELAY_MS", "200")]);
    let pid = child.id();
    let pid_str = pid.to_string();

    let output = Command::new(find_exec("pwait"))
        .args(["-v", &pid_str, &pid_str])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pwait");

    let _ = child.wait();
    ready.cleanup();

    assert!(output.status.success(), "pwait should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let count = stdout.matches("terminated").count();
    assert_eq!(
        count, 1,
        "Duplicate PID should be reported only once, got {} termination messages: {}",
        count, stdout
    );
}

#[test]
fn pwait_mixed_valid_and_invalid_exits_nonzero() {
    let (mut child, ready) = spawn_example(&[("PTOOLS_TEST_DELAY_MS", "200")]);
    let pid = child.id();

    let output = Command::new(find_exec("pwait"))
        .args(["-v", &pid.to_string(), "999999999"])
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pwait");

    let _ = child.wait();
    ready.cleanup();

    // Should exit nonzero because one PID was invalid.
    assert!(
        !output.status.success(),
        "Expected nonzero exit when one PID is invalid"
    );
    // But should still have waited for and reported the valid one.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("{}: terminated", pid)),
        "Should still report valid PID termination: {}",
        stdout
    );
}

#[test]
fn pwait_already_exited_process() {
    // Spawn a process that exits almost immediately.
    let ready = ReadySignal::new(false);
    let mut cmd = Command::new(find_exec("examples/pwait_process"));
    cmd.stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .env("PTOOLS_TEST_DELAY_MS", "0");
    ready.apply_to_command(&mut cmd);

    let mut child = cmd.spawn().expect("failed to spawn example");
    ready.wait_for_readiness(&mut child);
    let pid = child.id();

    // Wait for the process to actually exit.
    let _ = child.wait();

    // Give the kernel a moment to clean up.
    thread::sleep(Duration::from_millis(50));

    // pwait on an already-exited process should fail (pidfd_open will get ESRCH).
    let output = Command::new(find_exec("pwait"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pwait");

    ready.cleanup();

    assert!(
        !output.status.success(),
        "Expected nonzero exit for already-exited process"
    );
}
