use nix::unistd::getppid;
use std::env;
use std::fs::File;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.get(1).map(String::as_str) == Some("--child") {
        let child_ready_file = args.get(3).expect("missing child ready file path");
        File::create(child_ready_file).expect("failed to create child ready file");

        while getppid().as_raw() != 1 {
            thread::sleep(Duration::from_millis(50));
        }
        return;
    }

    args.get(1).expect("missing parent arg");
    let child_arg = args.get(2).expect("missing child arg");
    let ready_file = args.get(3).expect("missing ready file path");
    let child_ready_file = args.get(4).expect("missing child ready file path");

    Command::new(&args[0])
        .arg("--child")
        .arg(child_arg)
        .arg(child_ready_file)
        .spawn()
        .expect("failed to spawn child process");

    File::create(ready_file).expect("failed to create parent ready file");

    thread::sleep(Duration::from_secs(600));
}
