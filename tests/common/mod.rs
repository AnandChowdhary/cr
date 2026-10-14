#![allow(dead_code)]

pub mod chain;
pub mod fault;
pub mod generate;
pub mod openapi;
pub mod rng;

use std::{path::Path, process::Command};

#[derive(Debug)]
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

    pub fn new_legacy(name: &str) -> Self {
        let database = Self::new(name);
        std::fs::remove_file(database.root.join(".cr/audit.sqlite")).unwrap();
        std::fs::write(
            database.root.join(".cr/config.yaml"),
            "version: 1\ndata_dir: records\n",
        )
        .unwrap();
        run_success(database.command().args(["audit", "head"]));
        database
    }

    pub fn command(&self) -> Command {
        command_for(&self.root)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

pub fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cr")
}

pub fn command_for(database: &Path) -> Command {
    let mut command = Command::new(binary());
    clear_attribution_environment(&mut command);
    command.arg("--database").arg(database);
    command
}

/// Remove every variable `cr` uses to detect or declare an acting agent.
///
/// Without this, running the suite inside a coding agent would produce
/// different audit events than running it in CI, and tests that assert what is
/// *not* recorded would depend on where they were run. Tests that care about
/// attribution set these variables back explicitly.
pub fn clear_attribution_environment(command: &mut Command) {
    for variable in [
        "CR_AGENT",
        "CR_AUTHORIZATION",
        "CR_INTENT",
        "CR_HOOK_AGENT",
        "CR_HOOK_AUTHORIZATION",
        "CR_ENCRYPTION_ACTIVE_KEY",
        "CR_ENCRYPTION_KEYS",
        "CR_AUDIT_SIGNING_KEY",
        "CR_AUDIT_TRUSTED_KEYS",
        "CLAUDECODE",
        "CLAUDE_CODE_SESSION_ID",
        "CURSOR_AGENT",
    ] {
        command.env_remove(variable);
    }
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

pub fn init_legacy(root: impl AsRef<Path>) -> anyhow::Result<cr::Database> {
    let root = root.as_ref();
    cr::Database::init(root)?;
    std::fs::remove_file(root.join(".cr/audit.sqlite"))?;
    std::fs::write(
        root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: records\n",
    )?;
    cr::Database::discover(Some(root))
}
