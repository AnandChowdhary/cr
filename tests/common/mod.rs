#![allow(dead_code)]

use std::{path::Path, process::Command};

pub struct TestDatabase {
    pub root: std::path::PathBuf,
    _temporary: tempfile::TempDir,
}

impl TestDatabase {
    pub fn new(name: &str) -> Self {
        let temporary = tempfile::tempdir().expect("could not create temporary directory");
        let root = temporary.path().join(name);
        run_success(Command::new(binary()).arg("init").arg(&root));
        Self {
            root,
            _temporary: temporary,
        }
    }

    pub fn command(&self) -> Command {
        command_for(&self.root)
    }
}

pub fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cr")
}

pub fn command_for(database: &Path) -> Command {
    let mut command = Command::new(binary());
    command.arg("--database").arg(database);
    command
}

pub fn run_success(command: &mut Command) -> String {
    let output = command.output().expect("failed to run cr");
    assert!(
        output.status.success(),
        "command failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout was not UTF-8")
}

pub fn run_failure(command: &mut Command) -> String {
    let output = command.output().expect("failed to run cr");
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stderr).expect("stderr was not UTF-8")
}
