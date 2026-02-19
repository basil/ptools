mod common;

fn find_line_for_signal<'a>(stdout: &'a str, name: &str) -> &'a str {
    stdout
        .lines()
        .find(|line| line.starts_with(name))
        .unwrap_or_else(|| panic!("Missing {} line in psig output:\n{}", name, stdout))
}

#[test]
fn psig_reports_default_ignored_and_caught_actions() {
    let output = common::run_ptool("psig", &[], "examples/psig_signals", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    let mut lines = stdout.lines();
    let summary = lines
        .next()
        .unwrap_or_else(|| panic!("Expected process summary line in psig output:\n{}", stdout));
    assert!(
        summary.contains("psig_signals"),
        "Expected summary to contain psig_signals executable path:\n{}",
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

    let hup = find_line_for_signal(&stdout, "HUP");
    assert!(
        hup.contains("blocked"),
        "Expected HUP to be blocked (blocked in all threads):\n{}",
        stdout
    );

    let winch = find_line_for_signal(&stdout, "WINCH");
    assert!(
        !winch.contains("blocked"),
        "Expected WINCH to NOT be blocked (only blocked in main thread, not all threads):\n{}",
        stdout
    );
}
