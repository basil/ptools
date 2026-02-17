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

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

// Find an executable produced by the Cargo build
pub fn find_exec(name: &str) -> PathBuf {
    // Find the path where Cargo has placed the executables by looking at this test process's
    // executable, which was also built by Cargo.
    let this_exec = std::env::current_exe().unwrap();
    let exec_dir = this_exec.parent().unwrap().parent().unwrap();

    exec_dir.join(name)
}

fn remove_if_exists(path: &std::path::Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            panic!("Failed to remove {:?}: {:?}", path, e.kind());
        }
    }
}

#[derive(Debug)]
pub struct ReadySignal {
    ready_path: String,
    child_ready_path: Option<String>,
}

impl ReadySignal {
    pub fn new(wait_for_child_ready: bool) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let test_pid = std::process::id();

        let ready_path = format!("/tmp/ptools-test-ready-{}-{}", test_pid, unique);
        let child_ready_path = wait_for_child_ready
            .then(|| format!("/tmp/ptools-test-ready-child-{}-{}", test_pid, unique));

        remove_if_exists(std::path::Path::new(&ready_path));
        if let Some(path) = child_ready_path.as_ref() {
            remove_if_exists(std::path::Path::new(path));
        }

        Self {
            ready_path,
            child_ready_path,
        }
    }

    pub fn ready_path(&self) -> &str {
        &self.ready_path
    }

    pub fn child_ready_path(&self) -> Option<&str> {
        self.child_ready_path.as_deref()
    }

    pub fn apply_to_command(&self, cmd: &mut Command) {
        cmd.env("PTOOLS_TEST_READY_FILE", &self.ready_path);
        if let Some(path) = self.child_ready_path.as_ref() {
            cmd.env("PTOOLS_TEST_READY_CHILD_FILE", path);
        }
    }

    pub fn wait_for_readiness(&self, child: &mut Child) {
        let ready_file = std::path::Path::new(&self.ready_path);
        let child_ready_file = self.child_ready_path.as_ref().map(std::path::Path::new);
        while !(ready_file.exists() && child_ready_file.map(|p| p.exists()).unwrap_or(true)) {
            if let Some(status) = child.try_wait().expect("failed waiting for child") {
                panic!("Child exited too soon with status {}", status);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn cleanup(&self) {
        remove_if_exists(std::path::Path::new(&self.ready_path));
        if let Some(path) = self.child_ready_path.as_ref() {
            remove_if_exists(std::path::Path::new(path));
        }
    }
}

pub struct RunningReadyProcess {
    child: Child,
    ready: ReadySignal,
}

impl RunningReadyProcess {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn run_tool_against_pid(&self, tool: &str, tool_args: &[&str]) -> Output {
        Command::new(find_exec(tool))
            .args(tool_args)
            .arg(self.pid().to_string())
            .stdin(Stdio::null())
            .output()
            .expect("failed to run tool")
    }

    pub fn kill_and_wait(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.ready.cleanup();
    }
}

impl Drop for RunningReadyProcess {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

pub fn run_ptool(
    tool: &str,
    tool_args: &[&str],
    example: &str,
    example_args: &[&str],
    example_env: &[(&str, &str)],
    wait_for_child_ready: bool,
) -> Output {
    let ready = ReadySignal::new(wait_for_child_ready);
    let mut example_cmd = Command::new(find_exec(example));
    example_cmd
        .args(example_args)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .envs(example_env.iter().copied());
    ready.apply_to_command(&mut example_cmd);

    let mut child = example_cmd.spawn().expect("failed to spawn example");
    ready.wait_for_readiness(&mut child);

    let pid = child.id().to_string();
    let mut no_pid = false;
    let mut saw_pid_token = false;
    let mut resolved_args: Vec<String> = Vec::with_capacity(tool_args.len() + 1);
    for arg in tool_args {
        match *arg {
            "__NO_PID__" => no_pid = true,
            "__PID__" => {
                resolved_args.push(pid.clone());
                saw_pid_token = true;
            }
            _ => resolved_args.push((*arg).to_string()),
        }
    }
    if !no_pid && !saw_pid_token {
        resolved_args.push(pid);
    }

    let output = Command::new(find_exec(tool))
        .args(resolved_args.iter().map(String::as_str))
        .stdin(Stdio::null())
        .output()
        .expect("failed to run tool");

    let _ = child.kill();
    let _ = child.wait();
    ready.cleanup();

    output
}

pub fn assert_success_and_get_stdout(output: Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr, "");
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout).into_owned()
}
