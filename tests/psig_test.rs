mod common;

use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

fn find_line_for_signal<'a>(stdout: &'a str, name: &str) -> &'a str {
    stdout
        .lines()
        .find(|line| line.starts_with(name))
        .unwrap_or_else(|| panic!("Missing {} line in psig output:\n{}", name, stdout))
}

#[test]
fn psig_reports_default_ignored_and_caught_actions() {
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

    let mut examined_proc = Command::new(common::find_exec("examples/psig_signals"))
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

    let output = Command::new(common::find_exec("psig"))
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
    let summary = lines
        .next()
        .unwrap_or_else(|| panic!("Expected process summary line in psig output:\n{}", stdout));
    assert!(
        summary.contains("psig_signals"),
        "Expected summary to contain psig_signals executable path:\n{}",
        stdout
    );

    let usr1 = find_line_for_signal(&stdout, "USR1");
    assert!(
        usr1.contains("caught"),
        "Expected USR1 to be caught:\n{}",
        stdout
    );

    let usr2 = find_line_for_signal(&stdout, "USR2");
    assert!(
        usr2.contains("ignored"),
        "Expected USR2 to be ignored:\n{}",
        stdout
    );

    let term = find_line_for_signal(&stdout, "TERM");
    assert!(
        term.contains("default"),
        "Expected TERM to remain default:\n{}",
        stdout
    );
}
