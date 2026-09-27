//! `cr serve` and the signals that stop it.
//!
//! Every test here runs a real server process and signals it, because the
//! behavior under test — which signals are caught, what the process prints,
//! and the status it exits with — belongs to the process rather than to the
//! router an in-process test would drive.
//!
//! A request is caught in flight with `Expect: 100-continue`. The server
//! answers `100 Continue` only once a handler starts reading the body, so a
//! client that has read it knows its request is being handled and not merely
//! queued in the listener's backlog, and the server cannot finish that request
//! until the client sends the body. That makes "signal the server while a
//! mutation is in flight" a sequence of steps rather than a race.

#![cfg(unix)]

mod common;

use std::{
    fs::{self, File},
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, ChildStdout, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use common::{TestDatabase, chain, command_for, fault::FaultDatabase, run_success};
use serde_json::{Value, json};

/// How long any one step may take before the test fails instead of hanging.
const DEADLINE: Duration = Duration::from_secs(20);

/// A running `cr serve`, killed if a test fails before it exits.
struct Server {
    child: Child,
    address: SocketAddr,
    log: PathBuf,
    // Held open so the server never writes to a closed pipe.
    _stdout: BufReader<ChildStdout>,
}

impl Server {
    /// Start a server on a port the kernel chooses, and return once it has
    /// printed the address it is listening on.
    ///
    /// Reading the address from the banner, rather than reserving a port and
    /// passing it in, means no other process can take the port in between.
    /// The banner is printed after the shutdown signals are registered and
    /// the listener is bound, so from here on a connection is queued rather
    /// than refused and a signal drains the server rather than killing it.
    fn start(root: &Path, log: PathBuf) -> Self {
        let mut child = command_for(root)
            .args(["serve", "--bind", "127.0.0.1:0"])
            .env_remove("CR_API_TOKEN")
            .stdout(Stdio::piped())
            .stderr(Stdio::from(File::create(&log).unwrap()))
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut banner = String::new();
        stdout.read_line(&mut banner).unwrap();
        let address = banner
            .trim()
            .strip_prefix("Serving cr on http://")
            .unwrap_or_else(|| {
                let _ = child.kill();
                panic!(
                    "server did not start: {banner:?}\n{}",
                    fs::read_to_string(&log).unwrap_or_default()
                )
            })
            .parse()
            .unwrap();
        Self {
            child,
            address,
            log,
            _stdout: stdout,
        }
    }

    fn signal(&self, signal: libc::c_int) {
        // SAFETY: `self.child` is a process this test spawned and has not yet
        // reaped, so its PID cannot have been reused; the call only delivers a
        // signal.
        let sent = unsafe { libc::kill(self.child.id() as libc::pid_t, signal) };
        assert_eq!(sent, 0, "could not signal the server");
    }

    fn is_running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "server did not exit:\n{}",
                self.log()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Wait until the server's standard error contains `needle`.
    fn wait_for_log(&self, needle: &str) {
        let deadline = Instant::now() + DEADLINE;
        while !self.log().contains(needle) {
            assert!(
                Instant::now() < deadline,
                "server never logged {needle:?}:\n{}",
                self.log()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Wait until connecting is refused, which is how a client sees the
    /// listener closed.
    fn wait_until_refusing(&self) {
        let deadline = Instant::now() + DEADLINE;
        loop {
            match TcpStream::connect_timeout(&self.address, Duration::from_secs(1)) {
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => return,
                // Queued before the listener closed; the kernel resets it.
                _ => {}
            }
            assert!(
                Instant::now() < deadline,
                "server kept accepting connections:\n{}",
                self.log()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn connect(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&address, DEADLINE).unwrap();
    stream.set_read_timeout(Some(DEADLINE)).unwrap();
    stream.set_write_timeout(Some(DEADLINE)).unwrap();
    stream
}

/// Send a request's head announcing a `length`-byte JSON body, and wait for
/// the server to ask for that body.
fn start_request(address: SocketAddr, method: &str, path: &str, length: usize) -> TcpStream {
    let mut stream = connect(address);
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {length}\r\n\
         X-CR-Actor: shutdown@example.com\r\nExpect: 100-continue\r\n\r\n"
    )
    .unwrap();
    stream.flush().unwrap();
    let interim = read_head(&mut stream);
    assert!(
        interim.starts_with("HTTP/1.1 100 "),
        "expected 100 Continue, got {interim:?}"
    );
    stream
}

/// Read one response head, byte by byte so nothing after it is consumed.
fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = stream.read(&mut byte).unwrap();
        assert_eq!(read, 1, "connection closed inside a response head");
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

fn status_of(head: &str) -> u16 {
    head.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// Read a response to the end of the connection.
fn finish_response(stream: &mut TcpStream) -> (u16, String) {
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("incomplete response: {response:?}"));
    (status_of(head), body.to_owned())
}

/// Send a whole request and read its response on a connection of its own.
fn request(address: SocketAddr, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let mut stream = connect(address);
    let body = body.unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         X-CR-Actor: shutdown@example.com\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    stream.flush().unwrap();
    finish_response(&mut stream)
}

#[test]
fn sigterm_and_sigint_each_drain_the_server_and_exit_cleanly() {
    for (signal, name) in [(libc::SIGTERM, "SIGTERM"), (libc::SIGINT, "SIGINT")] {
        let database = TestDatabase::new("idle-shutdown");
        let log = database.root().with_extension("log");
        let mut server = Server::start(database.root(), log);

        // An idle keep-alive connection must not hold shutdown open: it has
        // finished one exchange and is waiting for a next request that may
        // never come.
        let mut idle = connect(server.address);
        write!(
            idle,
            "GET /health HTTP/1.1\r\nHost: {}\r\n\r\n",
            server.address
        )
        .unwrap();
        idle.flush().unwrap();
        let head = read_head(&mut idle);
        assert_eq!(status_of(&head), 200, "{head}");
        let length: usize = head
            .lines()
            .find_map(|line| {
                let (header, value) = line.split_once(':')?;
                header
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .expect("health response has a length");
        let mut body = vec![0; length];
        idle.read_exact(&mut body).unwrap();

        server.signal(signal);
        let status = server.wait_for_exit();
        let log = server.log();
        assert_eq!(
            status.code(),
            Some(0),
            "{name} exited with {status}:\n{log}"
        );
        assert!(
            log.contains(&format!("cr shutdown signal={name} state=draining")),
            "{log}"
        );
        assert!(log.contains("cr shutdown state=stopped"), "{log}");
        assert!(!log.contains("error"), "{log}");

        // Closed with nothing more sent: no stray response, and no reset.
        let mut rest = Vec::new();
        idle.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "{}", String::from_utf8_lossy(&rest));
    }
}

#[test]
fn sigterm_waits_for_an_in_flight_mutation_and_commits_it() {
    let database = TestDatabase::new("draining-shutdown");
    let log = database.root().with_extension("log");
    let mut server = Server::start(database.root(), log);

    let body = json!({
        "id": "acme",
        "front_matter": { "stage": "won" },
        "markdown": "Created while the server was shutting down."
    })
    .to_string();
    let mut in_flight = start_request(
        server.address,
        "POST",
        "/api/v1/collections/deals/records",
        body.len(),
    );

    server.signal(libc::SIGTERM);
    server.wait_for_log("cr shutdown signal=SIGTERM state=draining");
    // New work is turned away while old work is finished.
    server.wait_until_refusing();
    assert!(
        server.is_running(),
        "the server exited with a request still in flight:\n{}",
        server.log()
    );
    assert!(!database.root().join("records/deals/acme.md").exists());

    in_flight.write_all(body.as_bytes()).unwrap();
    in_flight.flush().unwrap();
    let (status, response) = finish_response(&mut in_flight);
    assert_eq!(status, 201, "{response}");

    let exit = server.wait_for_exit();
    let log = server.log();
    assert_eq!(exit.code(), Some(0), "exited with {exit}:\n{log}");
    assert!(log.contains("cr shutdown state=stopped"), "{log}");

    // The mutation committed completely: record, event, and no pending file.
    assert!(!database.root().join(".cr/audit/pending.json").exists());
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(
        verification.contains("Verified 1 audit events"),
        "{verification}"
    );
    let history: Value = serde_json::from_str(&run_success(
        database.command().args(["audit", "log", "--json"]),
    ))
    .unwrap();
    assert_eq!(history[0]["source"], "api");
    assert_eq!(history[0]["actor"], "shutdown@example.com");
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
}

#[test]
fn a_second_signal_stops_waiting_without_starting_the_mutation() {
    let database = TestDatabase::new("abandoned-shutdown");
    let log = database.root().with_extension("log");
    let mut server = Server::start(database.root(), log);

    let body = json!({ "id": "acme", "front_matter": { "stage": "won" } }).to_string();
    let mut in_flight = start_request(
        server.address,
        "POST",
        "/api/v1/collections/deals/records",
        body.len(),
    );

    server.signal(libc::SIGTERM);
    server.wait_for_log("cr shutdown signal=SIGTERM state=draining");
    assert!(server.is_running(), "{}", server.log());
    // Either signal counts as the second.
    server.signal(libc::SIGINT);
    let exit = server.wait_for_exit();
    let log = server.log();
    assert_eq!(exit.code(), Some(1), "exited with {exit}:\n{log}");
    assert!(
        log.contains("cr shutdown signal=SIGINT state=abandoned"),
        "{log}"
    );
    assert!(
        log.contains("error: stopped before every in-flight request finished"),
        "{log}"
    );
    assert!(!log.contains("state=stopped"), "{log}");

    // The request was never answered, and because its body never arrived its
    // mutation never began: nothing was written, and nothing needs recovery.
    let mut rest = Vec::new();
    let _ = in_flight.read_to_end(&mut rest);
    assert!(rest.is_empty(), "{}", String::from_utf8_lossy(&rest));
    assert!(!database.root().join("records/deals/acme.md").exists());
    assert!(!database.root().join(".cr/audit/pending.json").exists());
    // Read without `cr`, which would run recovery before answering.
    assert!(chain::read_chain(database.root()).is_empty());
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
}

/// Even a stop that abandons responses lets a mutation that has started finish.
///
/// The mutation is held at its first step, taking the audit lock, by this
/// process holding that lock. Linux lists a process blocked in `flock` in
/// `/proc/locks`, which is what makes "the mutation has started" something the
/// test can observe rather than guess at, and why this test is Linux-only.
#[cfg(target_os = "linux")]
#[test]
fn a_second_signal_still_lets_a_started_mutation_commit() {
    use std::os::unix::fs::MetadataExt;

    let database = TestDatabase::new("forced-shutdown");
    let log = database.root().with_extension("log");
    let mut server = Server::start(database.root(), log);

    // Startup recovery took this lock once, so the file exists.
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(database.root().join(".cr/audit/lock"))
        .unwrap();
    let inode = lock.metadata().unwrap().ino();
    lock.lock().expect("the test can hold the audit lock");

    let address = server.address;
    let client = thread::spawn(move || {
        let body = json!({ "id": "acme", "front_matter": { "stage": "won" } }).to_string();
        let mut stream = connect(address);
        write!(
            stream,
            "POST /api/v1/collections/deals/records HTTP/1.1\r\nHost: {address}\r\n\
             Connection: close\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        response
    });

    // A waiter reads `1: -> FLOCK  ADVISORY  WRITE <pid> <major>:<minor>:<inode> 0 EOF`.
    let pid = server.child.id().to_string();
    let inode = format!(":{inode}");
    let blocked = || {
        fs::read_to_string("/proc/locks")
            .unwrap()
            .lines()
            .any(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.get(1) == Some(&"->")
                    && fields.get(5) == Some(&pid.as_str())
                    && fields.get(6).is_some_and(|file| file.ends_with(&inode))
            })
    };
    let wait_until_blocked = |server: &Server| {
        let deadline = Instant::now() + DEADLINE;
        while !blocked() {
            assert!(
                Instant::now() < deadline,
                "no mutation is waiting for the audit lock:\n{}",
                server.log()
            );
            thread::sleep(Duration::from_millis(10));
        }
    };
    wait_until_blocked(&server);

    server.signal(libc::SIGTERM);
    server.wait_for_log("cr shutdown signal=SIGTERM state=draining");
    server.signal(libc::SIGTERM);
    server.wait_for_log("cr shutdown signal=SIGTERM state=abandoned");
    // Still here: exiting now would kill the mutation, and it cannot finish
    // until the lock is released. Polled rather than read once, because a
    // signal delivered to the waiting thread takes it off the lock's wait list
    // for as long as the kernel takes to restart its `flock`.
    wait_until_blocked(&server);
    assert!(server.is_running(), "{}", server.log());

    lock.unlock().expect("the audit lock releases");
    drop(lock);
    let exit = server.wait_for_exit();
    assert_eq!(
        exit.code(),
        Some(1),
        "exited with {exit}:\n{}",
        server.log()
    );

    // Whether the response went out before the connection was dropped is a
    // race this test does not decide; if one did, it reports the commit.
    let response = String::from_utf8(client.join().unwrap()).unwrap();
    assert!(
        response.is_empty() || response.starts_with("HTTP/1.1 201 "),
        "{response}"
    );
    assert!(database.root().join("records/deals/acme.md").exists());
    assert!(!database.root().join(".cr/audit/pending.json").exists());
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(
        verification.contains("Verified 1 audit events"),
        "{verification}"
    );
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
}

/// A mutation the server leaves half done is finished when it next starts.
///
/// No signal stops a mutation midway, so the half-done state is produced the
/// way `tests/audit_fault_injection.rs` produces it: a directory occupying the
/// name the next audit segment will take makes the append, and only the
/// append, fail, after the server has written its pending file and replaced
/// the record. That is the state a `SIGKILL` between those steps would leave.
#[test]
fn a_mutation_the_server_left_half_done_is_recovered_when_it_restarts() {
    let database = FaultDatabase::new("shutdown-recovery");
    run_success(
        database
            .command()
            .args(["create", "deals", "acme", "--set", "stage=lead"]),
    );
    let log = database.root().with_extension("log");
    let mut server = Server::start(database.root(), log.clone());

    let blocked = database.segments_path().join(format!("{:020}.jsonl", 2));
    fs::create_dir(&blocked).unwrap();
    let (status, body) = request(
        server.address,
        "PATCH",
        "/api/v1/collections/deals/records/acme",
        Some(&json!({ "front_matter": { "stage": "won" } }).to_string()),
    );
    assert!(status >= 500, "{status} {body}");

    // Stopping is still clean: the half-done mutation is a durable state, not
    // work the server was in the middle of.
    server.signal(libc::SIGTERM);
    let exit = server.wait_for_exit();
    assert_eq!(
        exit.code(),
        Some(0),
        "exited with {exit}:\n{}",
        server.log()
    );
    drop(server);

    fs::remove_dir(&blocked).unwrap();
    assert!(database.read_pending().is_some());
    let record = String::from_utf8(database.read_record("deals", "acme").unwrap()).unwrap();
    assert!(record.contains("stage: won"), "{record}");
    assert_eq!(database.head_sequence_unrecovered(), 1);
    let mut server = Server::start(database.root(), log);
    // Recovery runs before the server listens, so it is done by now.
    assert!(database.read_pending().is_none());
    assert_eq!(database.head_sequence_unrecovered(), 2);
    let (status, head) = request(server.address, "GET", "/api/v1/audit/head", None);
    assert_eq!(status, 200, "{head}");
    assert_eq!(serde_json::from_str::<Value>(&head).unwrap()["sequence"], 2);
    let (status, record) = request(
        server.address,
        "GET",
        "/api/v1/collections/deals/records/acme",
        None,
    );
    assert_eq!(status, 200, "{record}");
    assert_eq!(
        serde_json::from_str::<Value>(&record).unwrap()["front_matter"]["stage"],
        "won"
    );
    server.signal(libc::SIGTERM);
    assert_eq!(server.wait_for_exit().code(), Some(0), "{}", server.log());

    // The recovered event is the one the server prepared, not a new one.
    let history: Value = serde_json::from_str(&run_success(
        database.command().args(["audit", "log", "--json"]),
    ))
    .unwrap();
    assert_eq!(history[0]["action"], "update");
    assert_eq!(history[0]["source"], "api");
    assert_eq!(history[0]["actor"], "shutdown@example.com");
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(
        verification.contains("Verified 2 audit events"),
        "{verification}"
    );
    chain::assert_chain_is_well_formed(database.root());
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
}
