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

use std::env;
use std::fs::File;
use std::net::TcpListener;
use std::net::UdpSocket;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;

fn find_exec(name: &str) -> std::path::PathBuf {
    let env_var = format!("CARGO_BIN_EXE_{name}");
    if let Some(p) = std::env::var_os(&env_var) {
        return p.into();
    }

    let this_exec = std::env::current_exe().expect("current exe");
    let exec_dir = this_exec
        .parent()
        .expect("exe dir")
        .parent()
        .expect("target dir");
    exec_dir.join(name)
}

fn child_main() {
    let ready_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");

    let _tcp_listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let _udp_socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp socket");

    File::create(ready_path).expect("create ready file");

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}

fn parent_main() {
    let ready_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");

    let mut child = Command::new(find_exec("test_pfiles_sockopts_parent"))
        .arg("--child")
        .env("PTOOLS_TEST_READY_FILE", &ready_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child mode");

    let ready_file = Path::new(&ready_path);
    while !ready_file.exists() {
        if let Some(status) = child.try_wait().expect("wait child") {
            panic!("child exited early: {status}");
        }
        thread::sleep(Duration::from_millis(100));
    }

    let output = Command::new(find_exec("pfiles"))
        .arg(child.id().to_string())
        .stdin(Stdio::null())
        .output()
        .expect("run pfiles");

    child.kill().expect("kill child");
    let _ = child.wait();
    let _ = std::fs::remove_file(ready_file);

    if !output.status.success() {
        eprintln!("pfiles failed: {:?}", output.status);
        std::process::exit(1);
    }

    print!("{}", String::from_utf8_lossy(&output.stdout));
}

fn main() {
    if env::args().any(|arg| arg == "--child") {
        child_main();
    } else {
        parent_main();
    }
}
