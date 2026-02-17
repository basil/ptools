//
//   Copyright 2018, 2019 Delphix
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

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

// Find an executable produced by the Cargo build
pub fn find_exec(name: &str) -> PathBuf {
    // Find the path where Cargo has placed the executables by looking at this test process's
    // executable, which was also built by Cargo.
    let this_exec = std::env::current_exe().unwrap();
    let exec_dir = this_exec.parent().unwrap().parent().unwrap();

    exec_dir.join(name)
}

// Run a ptool against a sample process and return the stdout of the ptool
#[allow(dead_code)]
pub fn run_ptool(tool: &str, test_proc: &str) -> String {
    run_ptool_with_options(tool, &[], test_proc, &[], &[])
}

// Run a ptool against a sample process (with custom args/env) and return the stdout of the ptool
pub fn run_ptool_with_options(
    tool: &str,
    tool_args: &[&str],
    test_proc: &str,
    test_proc_args: &[&str],
    test_proc_env: &[(&str, &str)],
) -> String {
    let output = run_ptool_with_options_and_capture(
        tool,
        tool_args,
        test_proc,
        test_proc_args,
        test_proc_env,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stderr, "");
    assert!(output.status.success());

    stdout.into_owned()
}

pub fn run_ptool_with_options_and_capture(
    tool: &str,
    tool_args: &[&str],
    test_proc: &str,
    test_proc_args: &[&str],
    test_proc_env: &[(&str, &str)],
) -> Output {
    let signal_file = Path::new("/tmp/ptools-test-ready");
    if let Err(e) = fs::remove_file(signal_file) {
        if e.kind() != io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", signal_file, e.kind())
        }
    }

    let mut examined_proc_cmd = Command::new(find_exec(test_proc));
    examined_proc_cmd
        .args(test_proc_args)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .envs(test_proc_env.iter().copied());

    let mut examined_proc = examined_proc_cmd.spawn().unwrap();

    // Wait for process-to-be-examined to be ready
    while !signal_file.exists() {
        if let Some(status) = examined_proc.try_wait().unwrap() {
            panic!("Child exited too soon with status {}", status)
        }
    }

    let ptool_output = Command::new(find_exec(tool))
        .args(tool_args)
        .arg(examined_proc.id().to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();

    examined_proc.kill().unwrap();

    ptool_output
}
