mod common;

#[test]
fn pflags_reports_data_model_and_thread_state() {
    let output = common::run_ptool("pflags", &[], "examples/pflags_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    // Process summary line should contain the example binary name
    let first_line = stdout.lines().next().expect("expected output");
    assert!(
        first_line.contains("pflags_process"),
        "Expected summary to contain pflags_process:\n{}",
        stdout
    );

    // Should report a data model
    assert!(
        stdout.contains("data model = _LP64") || stdout.contains("data model = _ILP32"),
        "Expected data model line:\n{}",
        stdout
    );

    // Should have at least two threads (main + spawned)
    let thread_lines: Vec<&str> = stdout.lines().filter(|l| l.contains("flags = ")).collect();
    // One line is the process flags, the rest are per-thread
    let thread_count = thread_lines
        .iter()
        .filter(|l| l.trim_start().starts_with('/'))
        .count();
    assert!(
        thread_count >= 2,
        "Expected at least 2 threads, got {}:\n{}",
        thread_count,
        stdout
    );

    // Threads should be sleeping (in nanosleep or similar)
    assert!(
        stdout.contains("ASLEEP") || stdout.contains("SLEEPING"),
        "Expected sleeping thread state:\n{}",
        stdout
    );
}

#[test]
fn pflags_reports_held_signals() {
    let output = common::run_ptool("pflags", &[], "examples/pflags_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    // The main thread blocks SIGUSR1, so we should see held signals
    assert!(
        stdout.contains("held signals") && stdout.contains("USR1"),
        "Expected held signals containing USR1:\n{}",
        stdout
    );
}

#[test]
fn pflags_with_thread_filter() {
    use common::{find_exec, ReadySignal};
    use std::process::{Command, Stdio};

    let ready = ReadySignal::new(false);
    let mut example_cmd = Command::new(find_exec("examples/pflags_process"));
    example_cmd
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit());
    ready.apply_to_command(&mut example_cmd);

    let mut child = example_cmd.spawn().expect("failed to spawn example");
    ready.wait_for_readiness(&mut child);

    let pid = child.id();
    // On Linux, the main thread's TID equals the PID
    let arg = format!("{}/{}", pid, pid);
    let output = Command::new(find_exec("pflags"))
        .arg(&arg)
        .stdin(Stdio::null())
        .output()
        .expect("failed to run pflags");

    let _ = child.kill();
    let _ = child.wait();
    ready.cleanup();

    let stdout = common::assert_success_and_get_stdout(output);

    // Should still have summary and data model
    assert!(
        stdout.contains("pflags_process"),
        "Expected summary:\n{}",
        stdout
    );

    // Should have exactly one thread line (the filtered thread)
    let thread_count = stdout
        .lines()
        .filter(|l| l.trim_start().starts_with('/'))
        .count();
    assert_eq!(
        thread_count, 1,
        "Expected exactly 1 thread with /1 filter, got {}:\n{}",
        thread_count, stdout
    );
}
