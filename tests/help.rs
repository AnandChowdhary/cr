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

#[test]
fn serve_help_documents_safe_defaults_and_limits() {
    let output = Command::new(env!("CARGO_BIN_EXE_cr"))
        .args(["serve", "--help"])
        .output()
        .expect("failed to run cr serve --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help output was not UTF-8");
    assert!(stdout.contains("Serve the database through a web UI and REST API"));
    assert!(stdout.contains("--bind <BIND>"));
    assert!(stdout.contains("127.0.0.1:3000"));
    assert!(stdout.contains("--max-page-size"));
    assert!(stdout.contains("--max-body-bytes"));
}

#[test]
fn query_help_documents_typed_filter_expressions() {
    for command in ["list", "search"] {
        let output = Command::new(env!("CARGO_BIN_EXE_cr"))
            .args([command, "--help"])
            .output()
            .unwrap_or_else(|_| panic!("failed to run cr {command} --help"));
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).expect("help output was not UTF-8");
        assert!(stdout.contains("--where-expr <EXPRESSION>"));
        assert!(stdout.contains("value>=10000"));
        assert!(stdout.contains("--sort <FIELD>"));
        assert!(stdout.contains("--desc"));
        assert!(stdout.contains("Missing fields stay last"));
    }
}

#[test]
fn view_help_documents_saved_view_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_cr"))
        .args(["view", "create", "--help"])
        .output()
        .expect("failed to run cr view create --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help output was not UTF-8");
    assert!(stdout.contains("Create a saved view definition"));
    assert!(stdout.contains("--collection <COLLECTION>"));
    assert!(stdout.contains("--where <KEY=YAML>"));
    assert!(stdout.contains("--where-expr <EXPRESSION>"));
    assert!(stdout.contains("--column <FIELD>"));
    assert!(stdout.contains("--layout <LAYOUT>"));
    assert!(stdout.contains("[possible values: table, kanban]"));
    assert!(stdout.contains("--group-by <FIELD>"));
    assert!(stdout.contains("--sort-by <FIELD>"));
    assert!(stdout.contains("--sort-direction <SORT_DIRECTION>"));
    assert!(stdout.contains("[possible values: asc, desc]"));
    assert!(stdout.contains("--page-size <PAGE_SIZE>"));
}

#[test]
fn sync_help_documents_protocol_safety_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_cr"))
        .args(["sync", "create", "--help"])
        .output()
        .expect("failed to run cr sync create --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help output was not UTF-8");
    assert!(stdout.contains("Create a versioned sync definition"));
    assert!(stdout.contains("--timeout-seconds"));
    assert!(stdout.contains("--max-output-bytes"));
    assert!(stdout.contains("--max-operations"));
    assert!(stdout.contains("--actor <ACTOR>"));
    assert!(stdout.contains("<COMMAND>..."));
}
