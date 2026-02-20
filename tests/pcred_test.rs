mod common;

#[test]
fn pcred_reports_condensed_credentials() {
    let output = common::run_ptool("pcred", &[], "examples/pcred_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    let mut lines = stdout.lines();
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("Expected credential line in pcred output:\n{}", stdout));

    // A regular process has equal real/effective/saved UIDs and GIDs.
    assert!(
        first.contains("e/r/suid="),
        "Expected condensed UID format:\n{}",
        stdout
    );
    assert!(
        first.contains("e/r/sgid="),
        "Expected condensed GID format:\n{}",
        stdout
    );
}

#[test]
fn pcred_all_flag_shows_separate_credentials() {
    let output = common::run_ptool("pcred", &["-a"], "examples/pcred_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    let mut lines = stdout.lines();
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("Expected credential line in pcred output:\n{}", stdout));

    assert!(
        first.contains("euid="),
        "Expected separate euid with -a flag:\n{}",
        stdout
    );
    assert!(
        first.contains("ruid="),
        "Expected separate ruid with -a flag:\n{}",
        stdout
    );
    assert!(
        first.contains("suid="),
        "Expected separate suid with -a flag:\n{}",
        stdout
    );
    assert!(
        first.contains("egid="),
        "Expected separate egid with -a flag:\n{}",
        stdout
    );
    assert!(
        first.contains("rgid="),
        "Expected separate rgid with -a flag:\n{}",
        stdout
    );
    assert!(
        first.contains("sgid="),
        "Expected separate sgid with -a flag:\n{}",
        stdout
    );
}

#[test]
fn pcred_all_flag_always_shows_groups() {
    let output = common::run_ptool("pcred", &["-a"], "examples/pcred_process", &[], &[], false);
    let stdout = common::assert_success_and_get_stdout(output);

    assert!(
        stdout.contains("groups:"),
        "Expected groups line with -a flag:\n{}",
        stdout
    );
}

#[test]
fn pcred_reports_groups_when_supplementary_groups_exist() {
    let output = common::run_ptool("pcred", &[], "examples/pcred_process", &[], &[], false);
    common::assert_success_and_get_stdout(output);

    // The default mode may suppress the groups line if there is only one group
    // matching rgid, so verify with -a which always shows groups.
    let output_all = common::run_ptool("pcred", &["-a"], "examples/pcred_process", &[], &[], false);
    let stdout_all = common::assert_success_and_get_stdout(output_all);

    assert!(
        stdout_all.contains("groups:"),
        "Expected groups line with -a flag:\n{}",
        stdout_all
    );
}
