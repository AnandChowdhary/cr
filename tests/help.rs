use std::process::Command;

#[test]
fn help_prints_usage_and_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_cr"))
        .arg("--help")
        .output()
        .expect("failed to run cr");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("help output was not UTF-8");
    assert!(stdout.contains("Usage: cr [OPTIONS]"));
    assert!(stdout.contains("-h, --help"));
}

#[test]
fn no_arguments_prints_help_and_returns_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_cr"))
        .output()
        .expect("failed to run cr");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("help output was not UTF-8");
    assert!(stderr.contains("Usage: cr [OPTIONS] <COMMAND>"));
}
