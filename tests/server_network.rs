mod common;

use std::{
    fs::File,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use common::{binary, run_success};
use serde_json::{json, Value};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn installed_style_server_handles_real_http_requests() {
    let temporary = tempfile::tempdir().unwrap();
    let database = temporary.path().join("network-server");
    run_success(Command::new(binary()).args(["init"]).arg(&database));

    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);

    let child = Command::new(binary())
        .args(["--database"])
        .arg(&database)
        .args(["serve", "--bind", &address.to_string()])
        .env("CR_API_TOKEN", "network-secret")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = ChildGuard(child);
    wait_until_ready(&mut server.0, address);

    let health = http_request(address, "GET", "/health", &[], None);
    assert_eq!(health.0, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&health.1).unwrap()["status"],
        "ok"
    );

    let unauthorized = http_request(
        address,
        "GET",
        "/api/v1/collections/deals/records",
        &[],
        None,
    );
    assert_eq!(unauthorized.0, 401);

    let created = http_request(
        address,
        "POST",
        "/api/v1/collections/deals/records",
        &[
            ("Authorization", "Bearer network-secret"),
            ("X-CR-Actor", "network@example.com"),
            ("Content-Type", "application/json"),
        ],
        Some(
            &json!({
                "id": "acme",
                "front_matter": { "status": "won", "value": 25000 },
                "markdown": "Created through a real HTTP socket."
            })
            .to_string(),
        ),
    );
    assert_eq!(created.0, 201, "{}", created.1);
    assert_eq!(
        serde_json::from_str::<Value>(&created.1).unwrap()["front_matter"]["status"],
        "won"
    );

    let listed = http_request(
        address,
        "GET",
        "/api/v1/collections/deals/records?where=status%3Dwon&limit=10",
        &[("Authorization", "Bearer network-secret")],
        None,
    );
    assert_eq!(listed.0, 200);
    let listed: Value = serde_json::from_str(&listed.1).unwrap();
    assert_eq!(listed["data"][0]["path"], "records/deals/acme.md");
    assert_eq!(listed["pagination"]["total"], 1);

    let audit = http_request(
        address,
        "GET",
        "/api/v1/audit/log?limit=1",
        &[("Authorization", "Bearer network-secret")],
        None,
    );
    assert_eq!(audit.0, 200);
    let audit: Value = serde_json::from_str(&audit.1).unwrap();
    assert_eq!(audit["data"][0]["source"], "api");
    assert_eq!(audit["data"][0]["actor"], "network@example.com");

    let openapi = http_request(
        address,
        "GET",
        "/openapi.json",
        &[("Authorization", "Bearer network-secret")],
        None,
    );
    assert_eq!(openapi.0, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&openapi.1).unwrap()["openapi"],
        "3.1.1"
    );
}

fn wait_until_ready(child: &mut Child, address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("server exited before becoming ready: {status}");
        }
        if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "server did not become ready");
        thread::sleep(Duration::from_millis(25));
    }
}

fn http_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let body = body.unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .unwrap();
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").unwrap();
    }
    write!(stream, "\r\n{body}").unwrap();
    stream.flush().unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let response = String::from_utf8(response).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    let status = headers
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, body.to_owned())
}

/// The response a caller sees and the diagnostics an operator needs are two
/// different things, joined only by the request ID.
#[test]
fn error_responses_are_redacted_while_the_server_log_keeps_the_full_chain() {
    let temporary = tempfile::tempdir().unwrap();
    let database = temporary.path().join("network-errors");
    run_success(Command::new(binary()).args(["init"]).arg(&database));

    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);

    let log_path = temporary.path().join("serve.log");
    let child = Command::new(binary())
        .args(["--database"])
        .arg(&database)
        .args(["serve", "--bind", &address.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::from(File::create(&log_path).unwrap()))
        .spawn()
        .unwrap();
    let mut server = ChildGuard(child);
    wait_until_ready(&mut server.0, address);

    let (status, body) = http_request(
        address,
        "GET",
        "/api/v1/collections/deals/records/nope",
        &[],
        None,
    );
    assert_eq!(status, 404, "{body}");
    let payload: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(payload["error"]["code"], "not_found");
    assert_eq!(
        payload["error"]["message"],
        "record deals/nope does not exist"
    );
    let request_id = payload["error"]["request_id"].as_str().unwrap().to_owned();
    assert!(!request_id.is_empty());

    // Nothing about the filesystem or the operating system reaches the caller.
    assert!(!body.contains("records/deals/nope.md"), "{body}");
    assert!(!body.contains("os error"), "{body}");
    assert!(!body.contains(database.to_str().unwrap()), "{body}");

    // All of it reaches the log, under the request ID the caller was given.
    let log = read_until(&log_path, &request_id);
    let line = log
        .lines()
        .find(|line| line.contains(&request_id))
        .unwrap_or_else(|| panic!("no log line for request {request_id}:\n{log}"));
    assert!(line.contains("status=404"), "{line}");
    assert!(line.contains("code=not_found"), "{line}");
    assert!(
        line.contains("path=/api/v1/collections/deals/records/nope"),
        "{line}"
    );
    assert!(line.contains("could not read record"), "{line}");
    assert!(line.contains("records/deals/nope.md"), "{line}");
    assert!(line.contains("os error"), "{line}");
}

/// Read `path` until it contains `needle`, because the child process flushes
/// its log independently of the request that produced it.
fn read_until(path: &std::path::Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let contents = std::fs::read_to_string(path).unwrap_or_default();
        if contents.contains(needle) {
            return contents;
        }
        assert!(
            Instant::now() < deadline,
            "log never mentioned {needle}:\n{contents}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}
