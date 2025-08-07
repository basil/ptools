use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};
use nix::unistd::pipe2;
use nix::fcntl::OFlag;

use std::fs::File;

extern crate nix;

fn main() {

    let (readfd, _writefd) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).unwrap();

    let epoll = Epoll::new(EpollCreateFlags::empty()).unwrap();
    let event = EpollEvent::new(EpollFlags::EPOLLIN, 0);
    epoll.add(&readfd, event).unwrap();

    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create("/tmp/ptools-test-ready").unwrap();

    // Wait for the parent finish running the ptool and then kill us.
    loop {}
}

