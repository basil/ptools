use nix::sys::signal::{pthread_sigmask, SigSet, SigmaskHow, Signal};
use std::env;
use std::fs::File;
use std::thread;
use std::time::Duration;

fn main() {
    let ready_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");

    // Block SIGUSR1 on the main thread so we can verify held signals are shown.
    let mut block_set = SigSet::empty();
    block_set.add(Signal::SIGUSR1);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&block_set), None).expect("block SIGUSR1");

    // Spawn a second thread so we can verify multi-thread output.
    thread::spawn(|| loop {
        thread::sleep(Duration::from_millis(100));
    });

    File::create(ready_path).unwrap();

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
