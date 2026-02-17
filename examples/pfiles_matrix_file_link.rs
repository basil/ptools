use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use std::env;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::symlink;
use std::thread;
use std::time::Duration;

fn main() {
    let signal_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");
    let tmp_file_path = env::args()
        .nth(1)
        .expect("matrix file path argument must be provided");
    let symlink_path = env::args()
        .nth(2)
        .expect("matrix link path argument must be provided");

    let mut tmp_file = File::create(&tmp_file_path).unwrap();
    writeln!(tmp_file, "ptools").unwrap();
    tmp_file.seek(SeekFrom::Start(3)).unwrap();

    let _ = fs::remove_file(&symlink_path);
    symlink(&tmp_file_path, &symlink_path).unwrap();
    let symlink_fd = open(
        &*symlink_path,
        OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .unwrap();

    File::create(signal_path).unwrap();

    let _keep_alive = (tmp_file, symlink_fd);
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
