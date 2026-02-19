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

    // Block SIGHUP and SIGWINCH in the main thread.
    let mut block_set = SigSet::empty();
    block_set.add(Signal::SIGHUP);
    block_set.add(Signal::SIGWINCH);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&block_set), None).expect("block signals");

    // Spawn a thread that blocks SIGHUP but NOT SIGWINCH.
    // The thread inherits the main thread's mask, so we must unblock SIGWINCH.
    // This means the intersection is: SIGHUP blocked, SIGWINCH not blocked.
    let ready_path = signal_path.clone();
    thread::spawn(move || {
        let mut unblock_set = SigSet::empty();
        unblock_set.add(Signal::SIGWINCH);
        pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&unblock_set), None)
            .expect("unblock SIGWINCH in thread");

        // Signal readiness after the thread's mask is set.
        File::create(ready_path).unwrap();

        loop {
            thread::sleep(Duration::from_millis(100));
        }
    });

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
