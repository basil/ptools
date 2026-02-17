mod common;

use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

fn remove_if_exists(path: &Path) {
    if let Err(e) = fs::remove_file(path) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", path, e.kind());
        }
    }
}

#[test]
fn ptree_shows_parent_and_child_with_arguments() {
    let test_pid = std::process::id();
    let ready_file = std::path::PathBuf::from(format!("/tmp/ptools-test-ready-{}", test_pid));
    let child_ready_file =
        std::path::PathBuf::from(format!("/tmp/ptools-test-child-ready-{}", test_pid));

    let parent_arg = "PARG";
    let child_arg = "CARG";

    remove_if_exists(&ready_file);
    remove_if_exists(&child_ready_file);

    let mut examined_proc = Command::new(common::find_exec("ptree_parent_child"))
        .arg(parent_arg)
        .arg(child_arg)
        .arg(ready_file.to_str().unwrap())
        .arg(child_ready_file.to_str().unwrap())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    while !(ready_file.exists() && child_ready_file.exists()) {
        if let Some(status) = examined_proc.try_wait().unwrap() {
            panic!("Parent exited too soon with status {}", status);
        }
        thread::sleep(Duration::from_millis(5));
    }

    let output = Command::new(common::find_exec("ptree"))
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();

    examined_proc.kill().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let lines: Vec<&str> = stdout.lines().collect();

    let parent_index = lines
        .iter()
        .position(|line| line.contains(parent_arg))
        .expect(&format!(
            "Did not find parent process line in output:\n{}",
            stdout
        ));

    let child_index = lines
        .iter()
        .position(|line| line.contains("--child"))
        .expect(&format!(
            "Did not find child process line in output:\n{}",
            stdout
        ));

    assert!(
        parent_index < child_index,
        "Expected parent line to be printed before child line:\n{}",
        stdout
    );

    let parent_indent = leading_spaces(lines[parent_index]);
    let child_indent = leading_spaces(lines[child_index]);

    assert!(
        child_indent > parent_indent,
        "Expected child line to be more indented than parent line:\n{}",
        stdout
    );

    remove_if_exists(&ready_file);
    remove_if_exists(&child_ready_file);
}
