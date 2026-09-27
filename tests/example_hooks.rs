//! The hooks shipped under `examples/hooks/`, run the way their hosts run them.
//!
//! `claude-code-attribution.sh` is a Claude Code `PreToolUse` hook. These tests
//! feed it the JSON Claude Code documents on stdin, check the JSON it prints,
//! and then run the rewritten command with a shell and the `cr` under test, so
//! the whole path from hook payload to recorded audit event is covered without
//! Claude Code itself. `commit-msg` is a Git hook, exercised through real
//! `git commit` calls.
//!
//! Both scripts need tools outside Rust (`sh`, `jq`, `git`). Like the Git
//! assertions in `audit_anchor.rs`, a test skips with a note when one is absent;
//! the CI runners have all three.

mod common;

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use common::{TestDatabase, binary, clear_attribution_environment, run_success};
use serde_json::{Value, json};

const SESSION: &str = "6d1baa69-f114-490c-ae19-4be99c2bd744";
const PROMPT: &str = "550e8400-e29b-41d4-a716-446655440000";

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/hooks")
        .join(name)
}

fn available(tool: &str) -> bool {
    let present = Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !present {
        eprintln!("skipping: {tool} is not on PATH");
    }
    present
}

/// A `PATH` that finds the `cr` under test before any installed one.
fn path_with_cr() -> String {
    let directory = Path::new(binary())
        .parent()
        .expect("the binary has a parent");
    match std::env::var_os("PATH") {
        Some(path) => format!("{}:{}", directory.display(), path.to_string_lossy()),
        None => directory.display().to_string(),
    }
}

/// What Claude Code sends a `PreToolUse` hook for one Bash call.
fn payload(command: &str, permission_mode: Option<&str>) -> Value {
    let mut payload = json!({
        "session_id": SESSION,
        "prompt_id": PROMPT,
        "transcript_path": format!("/home/ada/.claude/projects/-home-ada-crm/{SESSION}.jsonl"),
        "cwd": "/home/ada/crm",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
            "description": "Mark the Acme renewal closed-won",
            "timeout": 120000,
            "run_in_background": false
        },
        "tool_use_id": "toolu_01ABC123"
    });
    if let Some(mode) = permission_mode {
        payload["permission_mode"] = json!(mode);
    }
    payload
}

/// Run the Claude Code hook on raw stdin, requiring exit status 0.
///
/// Exit status 2 is how a `PreToolUse` hook blocks a call, so any other status
/// would be a bug even where Claude Code treats it as a non-blocking error.
fn run_hook_raw(stdin: &[u8]) -> String {
    let mut child = Command::new("sh")
        .arg(example("claude-code-attribution.sh"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sh runs");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(stdin)
        .expect("the hook reads its input");
    let output = child.wait_with_output().expect("the hook finishes");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the hook must always exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("the hook prints UTF-8")
}

fn run_hook(payload: &Value) -> String {
    run_hook_raw(payload.to_string().as_bytes())
}

/// The rewritten Bash command the hook asks Claude Code to run instead.
fn rewritten(payload: &Value) -> String {
    let output: Value = serde_json::from_str(&run_hook(payload)).expect("the hook prints JSON");
    output["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .expect("the hook rewrites the command")
        .to_owned()
}

/// Run a command the way Claude Code's Bash tool would, with the test `cr`
/// first on `PATH` and none of the attribution variables of this process.
fn run_as_bash_tool(command: &str) -> String {
    let mut shell = Command::new("sh");
    clear_attribution_environment(&mut shell);
    run_success(shell.arg("-c").arg(command).env("PATH", path_with_cr()))
}

/// The exact exchange shown in the pull request and `docs/agents.md`.
#[test]
fn the_hook_prefixes_one_export_line_and_changes_nothing_else() {
    if !available("jq") {
        return;
    }
    let output: Value = serde_json::from_str(&run_hook(&payload(
        "cr update deals acme-renewal --set status=closed-won",
        Some("acceptEdits"),
    )))
    .expect("the hook prints JSON");

    assert_eq!(
        output,
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "updatedInput": {
                    "command": concat!(
                        r#"export CR_HOOK_AGENT='{"id":"claude-code","session":"6d1baa69-f114-490c-ae19-4be99c2bd744","turn":"550e8400-e29b-41d4-a716-446655440000"}'"#,
                        r#" CR_HOOK_AUTHORIZATION='{"mode":"unknown","grant":"acceptEdits"}'"#,
                        "\ncr update deals acme-renewal --set status=closed-won"
                    ),
                    "description": "Mark the Acme renewal closed-won",
                    "timeout": 120000,
                    "run_in_background": false
                }
            }
        })
    );
    // No permission decision: the rewritten command meets the user's rules.
    assert!(
        output["hookSpecificOutput"]
            .get("permissionDecision")
            .is_none()
    );
}

/// Every documented `permission_mode`, run through the hook, the shell, and
/// `cr identity`, lands on the approval mode the documentation promises.
#[test]
fn every_permission_mode_maps_to_the_documented_approval() {
    if !available("jq") {
        return;
    }
    let database = TestDatabase::new("hook-modes");
    let identity = format!(
        "cr --database '{}' identity --json",
        database.root.display()
    );
    for (permission_mode, expected) in [
        (
            Some("default"),
            json!({"mode": "unknown", "grant": "default"}),
        ),
        (
            Some("acceptEdits"),
            json!({"mode": "unknown", "grant": "acceptEdits"}),
        ),
        (Some("plan"), json!({"mode": "unknown", "grant": "plan"})),
        (Some("auto"), json!({"mode": "delegated", "grant": "auto"})),
        (
            Some("dontAsk"),
            json!({"mode": "delegated", "grant": "dontAsk"}),
        ),
        (
            Some("bypassPermissions"),
            json!({"mode": "delegated", "grant": "bypassPermissions"}),
        ),
        // A mode Claude Code adds later is kept verbatim and claims nothing.
        (
            Some("supervised"),
            json!({"mode": "unknown", "grant": "supervised"}),
        ),
        (None, json!({"mode": "unknown"})),
    ] {
        let command = rewritten(&payload(&identity, permission_mode));
        let recorded: Value =
            serde_json::from_str(&run_as_bash_tool(&command)).expect("identity is JSON");
        assert_eq!(recorded["authorization"], expected, "{permission_mode:?}");
        assert_eq!(
            recorded["agent"],
            json!({"id": "claude-code", "session": SESSION, "turn": PROMPT, "detected_from": "hook"}),
            "{permission_mode:?}"
        );
    }
}

/// The hook's whole purpose, end to end: a write Claude runs is recorded with
/// the session, the prompt, and the grant, all labelled `hook`, and the journal
/// still verifies. `CLAUDECODE` is set too, as it is under Claude Code, to show
/// that the hook's layer replaces what the probe alone would record.
#[test]
fn a_rewritten_write_records_a_hook_attributed_event_that_verifies() {
    if !available("jq") {
        return;
    }
    let database = TestDatabase::new("hook-write");
    let root = database.root.display();
    let command = rewritten(&payload(
        &format!(
            "cr --database '{root}' create deals acme-renewal --set status=open && \
             cr --database '{root}' update deals acme-renewal --set status=closed-won \
             --intent-rationale 'Set status to closed-won.'"
        ),
        Some("auto"),
    ));
    let mut shell = Command::new("sh");
    clear_attribution_environment(&mut shell);
    run_success(
        shell
            .arg("-c")
            .arg(&command)
            .env("PATH", path_with_cr())
            .env("CLAUDECODE", "1")
            .env("CLAUDE_CODE_SESSION_ID", SESSION),
    );

    let events: Value = serde_json::from_str(&run_success(
        database.command().args(["audit", "log", "--json"]),
    ))
    .expect("audit log is JSON");
    let events = events.as_array().expect("an array");
    assert_eq!(
        events.len(),
        2,
        "the export covers every command in the call"
    );
    for event in events {
        assert_eq!(event["agent"]["id"], "claude-code");
        assert_eq!(event["agent"]["session"], SESSION);
        assert_eq!(event["agent"]["turn"], PROMPT);
        assert_eq!(event["agent"]["detected_from"], "hook");
        assert_eq!(
            event["authorization"],
            json!({"mode": "delegated", "grant": "auto"})
        );
    }
    assert_eq!(events[0]["intent"]["rationale"]["author"], "agent");
    run_success(database.command().args(["audit", "verify"]));
}

/// As a `SessionStart` hook the script can only export to later commands
/// through `CLAUDE_ENV_FILE`, and only knows the session: it appends the agent
/// alone, says nothing on stdout (Claude would read that as context), and
/// never records a grant it cannot see.
#[test]
fn at_session_start_the_hook_exports_the_session_alone() {
    if !available("jq") {
        return;
    }
    let database = TestDatabase::new("hook-session-start");
    let environment_file = database.root.join("claude-env.sh");
    let start = json!({
        "session_id": SESSION,
        "transcript_path": format!("/home/ada/.claude/projects/-home-ada-crm/{SESSION}.jsonl"),
        "cwd": "/home/ada/crm",
        "hook_event_name": "SessionStart",
        "source": "startup",
        "model": "claude-opus-5"
    });

    let mut child = Command::new("sh")
        .arg(example("claude-code-attribution.sh"))
        .env("CLAUDE_ENV_FILE", &environment_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sh runs");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(start.to_string().as_bytes())
        .expect("the hook reads its input");
    let output = child.wait_with_output().expect("the hook finishes");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::read_to_string(&environment_file).expect("the hook appended an export"),
        format!("export CR_HOOK_AGENT='{{\"id\":\"claude-code\",\"session\":\"{SESSION}\"}}'\n")
    );

    // Claude Code runs the file ahead of every Bash command.
    let recorded: Value = serde_json::from_str(&run_as_bash_tool(&format!(
        ". '{}'\ncr --database '{}' identity --json",
        environment_file.display(),
        database.root.display()
    )))
    .expect("identity is JSON");
    assert_eq!(
        recorded["agent"],
        json!({"id": "claude-code", "session": SESSION, "detected_from": "hook"})
    );
    assert!(recorded["authorization"].is_null());

    // Without the file to write to, the hook does nothing at all.
    assert_eq!(run_hook(&start), "");
}

/// The hook runs on every Bash call its matcher admits. For anything that is
/// not a `cr` command, and for input it cannot read, it must say nothing, so
/// Claude Code runs the command exactly as written.
#[test]
fn the_hook_leaves_everything_else_alone() {
    if !available("jq") {
        return;
    }
    for command in [
        "ls -la",
        "crm list",
        "echo scr",
        "cargo build",
        "cr-lookalike --version",
    ] {
        assert_eq!(
            run_hook(&payload(command, Some("default"))),
            "",
            "{command}"
        );
    }

    let mut edit = payload("cr get deals acme", Some("default"));
    edit["tool_name"] = json!("Write");
    assert_eq!(run_hook(&edit), "");

    let mut later = payload("cr get deals acme", Some("default"));
    later["hook_event_name"] = json!("PostToolUse");
    assert_eq!(run_hook(&later), "");

    let mut no_command = payload("cr get deals acme", Some("default"));
    no_command["tool_input"] = json!({"description": "nothing to run"});
    assert_eq!(run_hook(&no_command), "");

    assert_eq!(run_hook_raw(b"{not json"), "");
    assert_eq!(run_hook_raw(b""), "");
}

/// Whatever is in the payload, the export line is inert shell: values are
/// single-quoted JSON, so a quote or a substitution in a session ID is text.
/// A value `cr` would refuse is dropped rather than allowed to fail the write.
#[test]
fn payload_values_cannot_escape_the_export_line_or_break_the_write() {
    if !available("jq") {
        return;
    }
    let database = TestDatabase::new("hook-quoting");
    let marker = database.root.join("escaped");
    let hostile = format!(
        "it's $(touch '{}') `touch '{}'`",
        marker.display(),
        marker.display()
    );
    let identity = format!(
        "cr --database '{}' identity --json",
        database.root.display()
    );

    let mut quoted = payload(&identity, Some("default"));
    quoted["session_id"] = json!(hostile);
    let recorded: Value =
        serde_json::from_str(&run_as_bash_tool(&rewritten(&quoted))).expect("identity is JSON");
    assert_eq!(recorded["agent"]["session"], json!(hostile));
    assert!(!marker.exists(), "a payload value was executed");

    let mut unusable = payload(&identity, Some("default"));
    unusable["session_id"] = json!("line\nbreak");
    unusable["prompt_id"] = json!("x".repeat(257));
    let recorded: Value =
        serde_json::from_str(&run_as_bash_tool(&rewritten(&unusable))).expect("identity is JSON");
    assert_eq!(
        recorded["agent"],
        json!({"id": "claude-code", "detected_from": "hook"})
    );
}

/// The settings snippet runs the script this repository ships, for Bash calls
/// with a `cr` subcommand and at session start, so copying both files as
/// documented installs a working hook.
#[test]
fn the_settings_snippet_installs_the_shipped_script() {
    let settings: Value = serde_json::from_str(
        &fs::read_to_string(example("claude-code-settings.json")).expect("the snippet exists"),
    )
    .expect("the snippet is JSON");
    let handler = |event: &str| {
        let groups = settings["hooks"][event]
            .as_array()
            .unwrap_or_else(|| panic!("a {event} hook list"));
        assert_eq!(groups.len(), 1, "{event}");
        let hook = groups[0]["hooks"][0].clone();
        assert_eq!(hook["type"], "command", "{event}");
        assert!(
            hook["command"]
                .as_str()
                .expect("a command")
                .ends_with("/claude-code-attribution.sh\""),
            "{hook}"
        );
        (groups[0]["matcher"].clone(), hook)
    };
    let (matcher, hook) = handler("PreToolUse");
    assert_eq!(matcher, "Bash");
    assert_eq!(hook["if"], "Bash(cr *)");
    let (matcher, hook) = handler("SessionStart");
    assert!(matcher.is_null());
    assert!(hook.get("if").is_none(), "`if` stops a SessionStart hook");
    assert!(example("claude-code-attribution.sh").exists());
    // The script makes no permission decision, and a wildcard rule for its
    // export line would approve other assignments too; see docs/agents.md.
    assert!(settings.get("permissions").is_none());
}

/// A Git repository holding a `cr` database, using `examples/hooks` as its
/// hooks directory and nothing from the machine's own Git configuration.
struct Repository {
    database: TestDatabase,
}

impl Repository {
    fn new(name: &str) -> Self {
        let database = TestDatabase::new(name);
        let repository = Self { database };
        repository.git(&["init", "--quiet"]);
        repository.git(&["config", "user.name", "Ada Lovelace"]);
        repository.git(&["config", "user.email", "ada@example.com"]);
        let hooks = example("");
        repository.git(&["config", "core.hooksPath", &hooks.display().to_string()]);
        repository
    }

    fn root(&self) -> &Path {
        self.database.root()
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        clear_attribution_environment(&mut command);
        command
            .current_dir(self.root())
            .env("PATH", path_with_cr())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1");
        for variable in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
        ] {
            command.env_remove(variable);
        }
        command
    }

    fn git(&self, arguments: &[&str]) -> String {
        run_success(self.command("git").args(arguments))
    }

    fn cr(&self, arguments: &[&str]) -> String {
        run_success(self.command("cr").args(arguments))
    }
}

/// The documented convention in one commit: the human as author, the agent as
/// committer, a `Co-authored-by:` trailer, and the audit head at commit time.
#[test]
fn a_commit_carries_the_audit_head_it_was_made_at() {
    if !available("git") {
        return;
    }
    let repository = Repository::new("commit-trailer");
    repository.cr(&["create", "deals", "acme-renewal", "--set", "status=open"]);
    repository.git(&["add", "-A"]);
    run_success(
        repository
            .command("git")
            .env("GIT_COMMITTER_NAME", "Claude Code")
            .env("GIT_COMMITTER_EMAIL", "noreply@anthropic.com")
            .args(["commit", "--quiet", "-m", "Open the Acme renewal"])
            .args(["-m", "Co-authored-by: Claude <noreply@anthropic.com>"]),
    );

    let head = repository.cr(&["audit", "head"]);
    let head = head.trim();
    assert!(head.starts_with("1 sha256:"), "{head}");
    assert_eq!(
        repository.git(&["log", "-1", "--format=%an <%ae>|%cn <%ce>"]),
        "Ada Lovelace <ada@example.com>|Claude Code <noreply@anthropic.com>\n"
    );
    assert_eq!(
        repository.git(&["log", "-1", "--format=%B"]),
        format!(
            "Open the Acme renewal\n\n\
             Co-authored-by: Claude <noreply@anthropic.com>\n\
             Cr-Audit-Head: {head}\n\n"
        )
    );
    // The journal's actor is the commit's author: both come from the same
    // Git identity.
    let events: Value = serde_json::from_str(&repository.cr(&["audit", "log", "--json"]))
        .expect("audit log is JSON");
    assert_eq!(events[0]["actor"], "Ada Lovelace <ada@example.com>");
}

/// Amending after another write moves the trailer instead of adding a second.
#[test]
fn amending_replaces_the_trailer() {
    if !available("git") {
        return;
    }
    let repository = Repository::new("commit-amend");
    repository.cr(&["create", "deals", "acme-renewal", "--set", "status=open"]);
    repository.git(&["add", "-A"]);
    repository.git(&["commit", "--quiet", "-m", "Open the Acme renewal"]);
    repository.cr(&["update", "deals", "acme-renewal", "--set", "status=won"]);
    repository.git(&["add", "-A"]);
    repository.git(&["commit", "--quiet", "--amend", "--no-edit"]);

    let head = repository.cr(&["audit", "head"]);
    assert!(head.starts_with("2 sha256:"), "{head}");
    assert_eq!(
        repository.git(&[
            "log",
            "-1",
            "--format=%(trailers:key=Cr-Audit-Head,valueonly,separator=%x2C)"
        ]),
        head
    );
}

/// A database below the repository root is named once in Git configuration.
/// Without a database or with an empty journal, the hook adds nothing and never
/// stops the commit.
#[test]
fn the_trailer_follows_a_configured_database_and_is_omitted_without_one() {
    if !available("git") {
        return;
    }
    let repository = Repository::new("commit-elsewhere");
    let nested = repository.root().join("crm");
    run_success(Command::new(binary()).arg("init").arg(&nested));

    // The root database's journal is empty, so there is nothing to anchor.
    fs::write(repository.root().join("notes.txt"), "one\n").unwrap();
    repository.git(&["add", "-A"]);
    repository.git(&["commit", "--quiet", "-m", "Empty journal"]);
    assert_eq!(
        repository.git(&["log", "-1", "--format=%B"]),
        "Empty journal\n\n"
    );

    let mut create = repository.command("cr");
    run_success(
        create
            .arg("--database")
            .arg(&nested)
            .args(["create", "deals", "acme-renewal"]),
    );
    repository.git(&["config", "cr.database", "crm"]);
    fs::write(repository.root().join("notes.txt"), "two\n").unwrap();
    repository.git(&["add", "-A"]);
    repository.git(&["commit", "--quiet", "-m", "Nested database"]);
    let mut head = repository.command("cr");
    let head = run_success(head.arg("--database").arg(&nested).args(["audit", "head"]));
    assert_eq!(
        repository.git(&["log", "-1", "--format=%B"]),
        format!("Nested database\n\nCr-Audit-Head: {}\n\n", head.trim())
    );

    repository.git(&["config", "cr.database", "missing"]);
    fs::write(repository.root().join("notes.txt"), "three\n").unwrap();
    repository.git(&["add", "-A"]);
    repository.git(&["commit", "--quiet", "-m", "No database"]);
    assert_eq!(
        repository.git(&["log", "-1", "--format=%B"]),
        "No database\n\n"
    );
}
