use nix::sys::signal::{pthread_sigmask, SigmaskHow};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use std::env;
use std::fs::File;
use std::thread;
use std::time::Duration;

extern "C" fn sigusr1_handler(_signal: i32) {}

fn main() {
    let signal_path =
        env::var("PTOOLS_TEST_READY_FILE").expect("PTOOLS_TEST_READY_FILE must be set");

    let mut mask = SigSet::empty();
    mask.add(Signal::SIGHUP);
    mask.add(Signal::SIGINT);
    mask.add(Signal::SIGQUIT);

    let caught = SigAction::new(
        SigHandler::Handler(sigusr1_handler),
        SaFlags::SA_RESTART,
        mask,
    );
    let ignored = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());

    // SAFETY: Installs signal dispositions for this process before it is inspected.
    unsafe {
        sigaction(Signal::SIGUSR1, &caught).expect("set SIGUSR1 handler");
        sigaction(Signal::SIGUSR2, &ignored).expect("ignore SIGUSR2");
    }

    // Block SIGHUP so we can verify psig shows "blocked" for it.
    let mut block_set = SigSet::empty();
    block_set.add(Signal::SIGHUP);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&block_set), None).expect("block SIGHUP");

    File::create(signal_path).unwrap();

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
