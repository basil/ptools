use nix::fcntl::OFlag;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};
use nix::unistd::pipe2;

use std::env;
use std::fs::File;
use std::thread;
use std::time::Duration;

fn main() {
    let signal_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");

    let (readfd, _writefd) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).unwrap();

    let epoll = Epoll::new(EpollCreateFlags::empty()).unwrap();
    let event = EpollEvent::new(EpollFlags::EPOLLIN, 0);
    epoll.add(&readfd, event).unwrap();

    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create(signal_path).unwrap();

    // Wait for the parent to finish running the ptool and then kill us.
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
