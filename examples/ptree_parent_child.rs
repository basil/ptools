use nix::unistd::getppid;
use std::env;
use std::fs::File;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.get(1).map(String::as_str) == Some("--child") {
        let ready_child_file = env::var("PTOOLS_TEST_READY_CHILD_FILE")
            .expect("PTOOLS_TEST_READY_CHILD_FILE must be set");
        File::create(ready_child_file).expect("failed to create ready child file");

        while getppid().as_raw() != 1 {
            thread::sleep(Duration::from_millis(100));
        }
        return;
    }

    args.get(1).expect("missing parent arg");
    let child_arg = args.get(2).expect("missing child arg");
    let ready_file =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");
    let ready_child_file =
        env::var("PTOOLS_TEST_READY_CHILD_FILE").expect("PTOOLS_TEST_READY_CHILD_FILE must be set");

    #[allow(clippy::zombie_processes)]
    let _child = Command::new(&args[0])
        .arg("--child")
        .arg(child_arg)
        .env("PTOOLS_TEST_READY_FILE", ready_file.as_str())
        .env("PTOOLS_TEST_READY_CHILD_FILE", ready_child_file)
        .spawn()
        .expect("failed to spawn child process");

    File::create(ready_file).expect("failed to create parent ready file");

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
