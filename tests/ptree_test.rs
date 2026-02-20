mod common;

use std::fs;
use std::process::{Command, Stdio};

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

fn assert_contains(output: &str, needle: &str, context: &str) {
    assert!(
        output.contains(needle),
        "{}: expected to find {:?} in output:\n{}",
        context,
        needle,
        output
    );
}

fn current_username() -> Option<String> {
    let output = Command::new("id")
        .arg("-un")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let username = String::from_utf8(output.stdout).ok()?;
    let username = username.trim().to_string();
    if username.is_empty() {
        None
    } else {
        Some(username)
    }
}

fn output_has_pid_line(output: &str, pid: u64) -> bool {
    let prefix = format!("{}  ", pid);
    output
        .lines()
        .any(|line| line.trim_start().starts_with(&prefix))
}

fn line_for_pid(output: &str, pid: u64) -> Option<&str> {
    let prefix = format!("{}  ", pid);
    output
        .lines()
        .find(|line| line.trim_start().starts_with(&prefix))
}

fn find_non_init_child_of_pid_zero() -> Option<u64> {
    let proc_dir = fs::read_dir("/proc").ok()?;
    for entry in proc_dir {
        let entry = entry.ok()?;
        let filename = entry.file_name();
        let Some(pid) = filename.to_str().and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        if pid == 1 {
            continue;
        }

        let status_path = format!("/proc/{}/status", pid);
        let Ok(status) = fs::read_to_string(status_path) else {
            continue;
        };
        if status.lines().any(|line| line.trim() == "PPid:\t0") {
            return Some(pid);
        }
    }
    None
}

#[test]
fn ptree_shows_parent_and_child_with_arguments() {
    let parent_arg = "P";
    let child_arg = "C";

    let output = common::run_ptool(
        "ptree",
        &[],
        "examples/ptree_parent_child",
        &[parent_arg, child_arg],
        &[],
        true,
    );

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    let lines: Vec<&str> = stdout.lines().collect();

    let parent_index = lines
        .iter()
        .position(|line| line.contains(parent_arg))
        .unwrap_or_else(|| panic!("Did not find parent process line in output:\n{}", stdout));

    let child_index = lines
        .iter()
        .position(|line| line.contains("--ch"))
        .unwrap_or_else(|| panic!("Did not find child process line in output:\n{}", stdout));

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
}

#[test]
fn ptree_a_includes_children_of_process_zero() {
    let Some(kernel_root_pid) = find_non_init_child_of_pid_zero() else {
        eprintln!("Skipping: no non-init child of PID 0 found in /proc");
        return;
    };

    let default_output = Command::new(common::find_exec("ptree"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(default_output.status.success());
    let default_stdout = String::from_utf8_lossy(&default_output.stdout);

    let all_output = Command::new(common::find_exec("ptree"))
        .arg("-a")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(all_output.status.success());
    let all_stdout = String::from_utf8_lossy(&all_output.stdout);

    assert!(
        output_has_pid_line(&default_stdout, 1),
        "Expected default ptree output to include PID 1:\n{}",
        default_stdout
    );
    assert!(
        output_has_pid_line(&all_stdout, 1),
        "Expected ptree -a output to include PID 1:\n{}",
        all_stdout
    );
    assert!(
        !output_has_pid_line(&default_stdout, kernel_root_pid),
        "Expected default ptree output to exclude PID {}:\n{}",
        kernel_root_pid,
        default_stdout
    );
    assert!(
        output_has_pid_line(&all_stdout, kernel_root_pid),
        "Expected ptree -a output to include PID {}:\n{}",
        kernel_root_pid,
        all_stdout
    );

    let kernel_line = line_for_pid(&all_stdout, kernel_root_pid).unwrap();
    let (_, rest) = kernel_line.trim_start().split_once("  ").unwrap();
    assert!(
        !rest.trim().is_empty(),
        "Expected ptree -a to print a process name for PID {}:\n{}",
        kernel_root_pid,
        all_stdout
    );
}

#[test]
fn ptree_accepts_username_operand() {
    let Some(username) = current_username() else {
        eprintln!("Skipping: unable to resolve current username");
        return;
    };

    let parent_arg = "PU";
    let child_arg = "CU";

    let output = common::run_ptool(
        "ptree",
        &[username.as_str(), "__NO_PID__"],
        "examples/ptree_parent_child",
        &[parent_arg, child_arg],
        &[],
        true,
    );

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(
        &stdout,
        parent_arg,
        "Expected ptree <user> output to include spawned parent process",
    );
    assert_contains(
        &stdout,
        "--ch",
        "Expected ptree <user> output to include spawned child process",
    );
}

#[test]
fn ptree_accepts_mixed_pid_and_user_operands() {
    let Some(username) = current_username() else {
        eprintln!("Skipping: unable to resolve current username");
        return;
    };

    let parent_arg = "PM";
    let child_arg = "CM";

    let output = common::run_ptool(
        "ptree",
        &["__PID__", username.as_str()],
        "examples/ptree_parent_child",
        &[parent_arg, child_arg],
        &[],
        true,
    );

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(
        &stdout,
        parent_arg,
        "Expected mixed ptree operands output to include spawned parent process",
    );
}
