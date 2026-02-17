use std::env;
use std::fs::File;
use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn find_exec(name: &str) -> std::path::PathBuf {
    let this_exec = std::env::current_exe().expect("current exe");
    let exec_dir = this_exec
        .parent()
        .expect("exe dir")
        .parent()
        .expect("target dir");
    exec_dir.join(name)
}

fn child_main() {
    let ready_path = env::var("PTOOLS_TEST_READY_FILE").expect("ready path");

    let _tcp_listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let _udp_socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp socket");

    File::create(ready_path).expect("create ready file");

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn parent_main() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let ready_path = format!(
        "/tmp/ptools-sockopts-ready-{}-{}",
        std::process::id(),
        unique
    );

    let mut child = Command::new(find_exec("examples/pfiles_sockopts_parent"))
        .env("PTOOLS_CHILD_MODE", "1")
        .env("PTOOLS_TEST_READY_FILE", &ready_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child mode");

    let ready_file = Path::new(&ready_path);
    while !ready_file.exists() {
        if let Some(status) = child.try_wait().expect("wait child") {
            panic!("child exited early: {}", status);
        }
        thread::sleep(Duration::from_millis(5));
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
    if env::var_os("PTOOLS_CHILD_MODE").is_some() {
        child_main();
    } else {
        parent_main();
    }
}
