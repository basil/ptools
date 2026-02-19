mod common;

use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use common::{find_exec, ReadySignal};

/// Read the state character from /proc/[pid]/stat.
fn proc_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let after_comm = stat.find(')')? + 1;
    let rest = stat[after_comm..].trim_start();
    rest.chars().next()
}

/// Wait (with timeout) until the process reaches one of the expected states.
fn wait_for_state(pid: u32, expected: &[char], timeout_ms: u64) -> char {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if let Some(state) = proc_state(pid) {
            if expected.contains(&state) {
                return state;
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "Timed out waiting for pid {} to reach state {:?} (current: {:?})",
                pid,
                expected,
                proc_state(pid)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn pstop_stops_a_running_process() {
    let ready = ReadySignal::new(false);
    let mut example_cmd = Command::new(find_exec("examples/pstop_prun_process"));
    example_cmd
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit());
    ready.apply_to_command(&mut example_cmd);

    let mut child = example_cmd.spawn().expect("failed to spawn example");
    ready.wait_for_readiness(&mut child);

    let pid = child.id();

    // Process should be running (R) or sleeping (S)
    let state = wait_for_state(pid, &['R', 'S'], 2000);
    assert!(
        state == 'R' || state == 'S',
        "Expected running/sleeping before pstop, got '{}'",
        state
    );

    // Run pstop
    let output = Command::new(find_exec("pstop"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pstop");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "pstop failed: {}", stderr);

    // Process should now be stopped (T)
    let state = wait_for_state(pid, &['T'], 2000);
    assert!(
        state == 'T',
        "Expected stopped after pstop, got '{}'",
        state
    );

    let _ = child.kill();
    let _ = child.wait();
    ready.cleanup();
}

#[test]
fn prun_resumes_a_stopped_process() {
    let ready = ReadySignal::new(false);
    let mut example_cmd = Command::new(find_exec("examples/pstop_prun_process"));
    example_cmd
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit());
    ready.apply_to_command(&mut example_cmd);

    let mut child = example_cmd.spawn().expect("failed to spawn example");
    ready.wait_for_readiness(&mut child);

    let pid = child.id();

    // Stop the process first
    let output = Command::new(find_exec("pstop"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pstop");
    assert!(output.status.success(), "pstop failed");

    // Verify it is stopped
    wait_for_state(pid, &['T'], 2000);

    // Run prun to resume it
    let output = Command::new(find_exec("prun"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .output()
        .expect("failed to run prun");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "prun failed: {}", stderr);

    // Process should be running or sleeping again
    let state = wait_for_state(pid, &['R', 'S'], 2000);
    assert!(
        state == 'R' || state == 'S',
        "Expected running/sleeping after prun, got '{}'",
        state
    );

    let _ = child.kill();
    let _ = child.wait();
    ready.cleanup();
}

#[test]
fn pstop_invalid_pid_exits_nonzero() {
    let output = Command::new(find_exec("pstop"))
        .arg("999999999")
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pstop");

    assert!(
        !output.status.success(),
        "Expected nonzero exit for non-existent PID"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.is_empty(),
        "Expected error message for non-existent PID"
    );
}

#[test]
fn prun_invalid_pid_exits_nonzero() {
    let output = Command::new(find_exec("prun"))
        .arg("999999999")
        .stdin(Stdio::null())
        .output()
        .expect("failed to run prun");

    assert!(
        !output.status.success(),
        "Expected nonzero exit for non-existent PID"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.is_empty(),
        "Expected error message for non-existent PID"
    );
}
