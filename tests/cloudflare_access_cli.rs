mod common;

use common::{TestDatabase, run_failure};
use serde_json::Value;

fn usage_error(database: &TestDatabase, args: &[&str]) -> String {
    let output = database
        .command()
        .args(["serve", "--json-errors", "--bind", "127.0.0.1:0"])
        .args(args)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{args:?}");
    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["error"]["code"], "usage_error", "{args:?}");
    envelope["error"]["message"].as_str().unwrap().to_owned()
}

/// Everything here is refused before the server fetches a key or opens a
/// port, so none of it needs a network.
#[test]
fn cloudflare_access_flags_are_checked_before_the_server_starts() {
    let database = TestDatabase::new("cloudflare-access-flags");

    // The team and the application are one setting between them.
    let message = usage_error(&database, &["--cloudflare-access", "harmess"]);
    assert!(message.contains("--cloudflare-access-aud"), "{message}");
    let message = usage_error(&database, &["--cloudflare-access-aud", "tag"]);
    assert!(
        message.contains("--cloudflare-access <TEAM_DOMAIN>"),
        "{message}"
    );

    for team in [
        "http://harmess.cloudflareaccess.com",
        "harmess.example.com",
        "https://harmess.cloudflareaccess.com/cdn-cgi/access/certs",
    ] {
        let message = usage_error(
            &database,
            &[
                "--cloudflare-access",
                team,
                "--cloudflare-access-aud",
                "tag",
            ],
        );
        assert!(
            message.contains("is not a Cloudflare Access team domain"),
            "{team}: {message}"
        );
    }
    let message = usage_error(
        &database,
        &[
            "--cloudflare-access",
            "harmess",
            "--cloudflare-access-aud",
            "not a tag",
        ],
    );
    assert!(message.contains("AUD tag"), "{message}");

    // A database with no users has nobody to sign in as.
    let stderr = run_failure(database.command().args([
        "serve",
        "--bind",
        "127.0.0.1:0",
        "--cloudflare-access",
        "https://harmess.cloudflareaccess.com",
        "--cloudflare-access-aud",
        "tag",
    ]));
    assert!(stderr.contains("needs access control"), "{stderr}");
}
