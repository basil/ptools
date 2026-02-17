mod common;

use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

extern "C" fn sigusr1_handler(_signal: i32) {}

fn signal_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn find_line_for_signal<'a>(stdout: &'a str, name: &str) -> &'a str {
    stdout
        .lines()
        .find(|line| line.starts_with(name))
        .unwrap_or_else(|| panic!("Missing {} line in psig output:\n{}", name, stdout))
}

fn run_psig_on_current_process(args: &[&str]) -> String {
    let mut cmd = Command::new(common::find_exec("psig"));
    let pid = std::process::id().to_string();
    cmd.args(args).arg(pid).stdin(Stdio::null());
    let output = cmd.output().expect("failed to execute psig");
    assert!(
        output.status.success(),
        "psig exited with status {:?}",
        output.status.code()
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr, "");

    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn with_test_signal_dispositions<T>(f: impl FnOnce() -> T) -> T {
    let _guard = signal_test_lock().lock().unwrap();

    let caught = SigAction::new(
        SigHandler::Handler(sigusr1_handler),
        SaFlags::empty(),
        SigSet::empty(),
    );
    let ignored = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());

    // SAFETY: Reads and installs signal dispositions for the current process.
    let old_usr1 = unsafe { sigaction(Signal::SIGUSR1, &caught) }.expect("set SIGUSR1 handler");
    // SAFETY: Reads and installs signal dispositions for the current process.
    let old_usr2 = unsafe { sigaction(Signal::SIGUSR2, &ignored) }.expect("ignore SIGUSR2");

    let result = f();

    // SAFETY: Restores previous dispositions captured above.
    unsafe {
        sigaction(Signal::SIGUSR1, &old_usr1).expect("restore SIGUSR1 handler");
        sigaction(Signal::SIGUSR2, &old_usr2).expect("restore SIGUSR2 handler");
    }

    result
}

#[test]
fn psig_reports_default_ignored_and_caught_actions() {
    let stdout = with_test_signal_dispositions(|| run_psig_on_current_process(&[]));

    let mut lines = stdout.lines();
    let summary = lines
        .next()
        .unwrap_or_else(|| panic!("Expected process summary line in psig output:\n{}", stdout));
    assert!(
        summary.contains("psig_test"),
        "Expected summary to contain psig test executable path:\n{}",
        stdout
    );

    let usr1 = find_line_for_signal(&stdout, "USR1");
    assert!(
        usr1.contains("caught"),
        "Expected USR1 to be caught:\n{}",
        stdout
    );

    let usr2 = find_line_for_signal(&stdout, "USR2");
    assert!(
        usr2.contains("ignored"),
        "Expected USR2 to be ignored:\n{}",
        stdout
    );

    let term = find_line_for_signal(&stdout, "TERM");
    assert!(
        term.contains("default"),
        "Expected TERM to remain default:\n{}",
        stdout
    );
}
