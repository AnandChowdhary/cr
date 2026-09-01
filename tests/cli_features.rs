mod common;

use std::{fs, process::Command};

use common::{TestDatabase, binary, run_failure, run_success};
use serde_json::Value;

#[test]
fn raw_field_body_only_update_and_parent_discovery_work() {
    let database = TestDatabase::new("reads-and-discovery");
    run_success(database.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=screening",
        "--body",
        "# Jane\n\nOriginal notes.\n",
    ]));

    let raw = run_success(database.command().args(["get", "candidates", "jane"]));
    assert!(raw.starts_with("---\n"));
    assert!(raw.contains("stage: screening"));
    assert!(raw.ends_with("# Jane\n\nOriginal notes.\n"));

    let field =
        run_success(
            database
                .command()
                .args(["get", "candidates", "jane", "--field", "stage"]),
        );
    assert_eq!(field.trim(), "screening");

    run_success(database.command().args([
        "update",
        "candidates",
        "jane",
        "--body",
        "# Jane\n\nReplacement notes.\n",
    ]));
    let fetched = run_success(
        database
            .command()
            .args(["get", "candidates", "jane", "--json"]),
    );
    let fetched: Value = serde_json::from_str(&fetched).unwrap();
    assert_eq!(fetched["attributes"]["stage"], "screening");
    assert!(
        fetched["body"]
            .as_str()
            .unwrap()
            .contains("Replacement notes")
    );

    let nested = database.root.join("records/candidates/nested");
    fs::create_dir_all(&nested).unwrap();
    let discovered = run_success(Command::new(binary()).current_dir(nested).args([
        "get",
        "candidates",
        "jane",
        "--field",
        "stage",
    ]));
    assert_eq!(discovered.trim(), "screening");
}

#[test]
fn every_supported_yaml_shape_round_trips_through_json() {
    let database = TestDatabase::new("typed-values");
    run_success(database.command().args([
        "create",
        "items",
        "typed",
        "--set",
        "boolean=true",
        "--set",
        "integer=42",
        "--set",
        "float=1.5",
        "--set",
        "nothing=null",
        "--set",
        "list=[rust, cli]",
        "--set",
        "object={city: Amsterdam, zip: 1012}",
        "--set",
        "code=\"001\"",
        "--set",
        "unicode=你好 👋",
    ]));

    let fetched = run_success(database.command().args(["get", "items", "typed", "--json"]));
    let fetched: Value = serde_json::from_str(&fetched).unwrap();
    let attributes = &fetched["attributes"];
    assert_eq!(attributes["boolean"], true);
    assert_eq!(attributes["integer"], 42);
    assert_eq!(attributes["float"], 1.5);
    assert!(attributes["nothing"].is_null());
    assert_eq!(attributes["list"], serde_json::json!(["rust", "cli"]));
    assert_eq!(
        attributes["object"],
        serde_json::json!({"city": "Amsterdam", "zip": 1012})
    );
    assert_eq!(attributes["code"], "001");
    assert_eq!(attributes["unicode"], "你好 👋");

    for filter in [
        "nothing=null",
        "list=[rust, cli]",
        "object={city: Amsterdam, zip: 1012}",
        "code=\"001\"",
    ] {
        let listed = run_success(
            database
                .command()
                .args(["list", "items", "--where", filter, "--json"]),
        );
        assert_eq!(
            serde_json::from_str::<Value>(&listed)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1,
            "filter did not match: {filter}"
        );
    }
}

#[test]
fn unicode_collection_and_record_identity_round_trip() {
    let database = TestDatabase::new("unicode-identity");
    run_success(
        database
            .command()
            .args(["create", "候補者", "山田-太郎", "--set", "stage=面接"]),
    );

    let fetched = run_success(
        database
            .command()
            .args(["get", "候補者", "山田-太郎", "--json"]),
    );
    let fetched: Value = serde_json::from_str(&fetched).unwrap();
    assert_eq!(fetched["collection"], "候補者");
    assert_eq!(fetched["id"], "山田-太郎");
    assert_eq!(fetched["attributes"]["stage"], "面接");
}

#[test]
fn configured_records_directory_is_honored() {
    let database = TestDatabase::new("custom-data-directory");
    fs::write(
        database.root.join(".cr/config.yaml"),
        "data_dir: content/data\n",
    )
    .unwrap();

    run_success(database.command().args(["create", "companies", "acme"]));
    assert!(
        database
            .root
            .join("content/data/companies/acme.md")
            .exists()
    );
    assert_eq!(
        run_success(database.command().args(["list", "companies"])).trim(),
        "content/data/companies/acme.md"
    );
}

#[test]
fn list_combines_typed_nested_filters_and_orders_results() {
    let database = TestDatabase::new("querying");
    for (id, stage, active, score, country) in [
        ("zoe", "interview", "true", "42", "NL"),
        ("amy", "interview", "true", "41", "NL"),
        ("mira", "screening", "false", "42", "US"),
    ] {
        let mut command = database.command();
        command.args([
            "create",
            "candidates",
            id,
            "--set",
            &format!("stage={stage}"),
            "--set",
            &format!("active={active}"),
            "--set",
            &format!("score={score}"),
            "--set",
            &format!("contact.country={country}"),
        ]);
        run_success(&mut command);
    }

    let filtered = run_success(database.command().args([
        "list",
        "candidates",
        "--where",
        "stage=interview",
        "--where",
        "active=true",
        "--where",
        "score=42",
        "--where",
        "contact.country=NL",
        "--json",
    ]));
    let filtered: Value = serde_json::from_str(&filtered).unwrap();
    assert_eq!(filtered.as_array().unwrap().len(), 1);
    assert_eq!(filtered[0]["path"], "records/candidates/zoe.md");
    assert_eq!(filtered[0]["front_matter"]["stage"], "interview");
    assert_eq!(filtered[0]["front_matter"]["active"], true);
    assert_eq!(filtered[0]["front_matter"]["score"], 42);
    assert_eq!(filtered[0]["front_matter"]["contact"]["country"], "NL");
    assert!(filtered[0].get("body").is_none());
    assert!(filtered[0].get("id").is_none());
    assert!(filtered[0].get("collection").is_none());
    assert!(filtered[0].get("attributes").is_none());

    let compared = run_success(database.command().args([
        "list",
        "candidates",
        "--where-expr",
        "score>=42",
        "--json",
    ]));
    let compared: Value = serde_json::from_str(&compared).unwrap();
    assert_eq!(
        compared
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["records/candidates/mira.md", "records/candidates/zoe.md"]
    );

    let mixed = run_success(database.command().args([
        "list",
        "candidates",
        "--where",
        "active=true",
        "--where-expr",
        "score>=42",
        "--json",
    ]));
    let mixed: Value = serde_json::from_str(&mixed).unwrap();
    assert_eq!(mixed.as_array().unwrap().len(), 1);
    assert_eq!(mixed[0]["path"], "records/candidates/zoe.md");

    let no_match = run_success(database.command().args([
        "list",
        "candidates",
        "--where",
        "missing=true",
        "--json",
    ]));
    assert_eq!(
        serde_json::from_str::<Value>(&no_match).unwrap(),
        serde_json::json!([])
    );

    run_success(database.command().args([
        "create",
        "candidates",
        "noah",
        "--set",
        "stage=screening",
    ]));
    let sorted = run_success(database.command().args([
        "list",
        "candidates",
        "--sort",
        "score",
        "--desc",
        "--json",
    ]));
    let sorted: Value = serde_json::from_str(&sorted).unwrap();
    assert_eq!(
        sorted
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "records/candidates/mira.md",
            "records/candidates/zoe.md",
            "records/candidates/amy.md",
            "records/candidates/noah.md",
        ]
    );

    let invalid_sort =
        run_failure(
            database
                .command()
                .args(["list", "candidates", "--sort", "contact..country"]),
        );
    assert!(invalid_sort.contains("contains an empty segment"));

    let ordered = run_success(database.command().args(["list", "candidates"]));
    assert_eq!(
        ordered.lines().collect::<Vec<_>>(),
        [
            "records/candidates/amy.md",
            "records/candidates/mira.md",
            "records/candidates/noah.md",
            "records/candidates/zoe.md"
        ]
    );

    let missing = run_success(database.command().args(["list", "roles", "--json"]));
    assert_eq!(
        serde_json::from_str::<Value>(&missing).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn list_ignores_non_markdown_nested_and_symlink_entries() {
    let database = TestDatabase::new("collection-entries");
    run_success(database.command().args(["create", "items", "real"]));
    let collection = database.root.join("records/items");
    fs::write(collection.join("notes.txt"), "not a record").unwrap();
    fs::create_dir(collection.join("directory.md")).unwrap();
    fs::create_dir(collection.join("nested")).unwrap();
    fs::write(
        collection.join("nested/hidden.md"),
        "---\nname: hidden\n---\n",
    )
    .unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(collection.join("real.md"), collection.join("alias.md")).unwrap();

    let listed = run_success(database.command().args(["list", "items"]));
    assert_eq!(
        listed.lines().collect::<Vec<_>>(),
        ["records/items/real.md"]
    );
}

#[test]
fn links_are_idempotent_and_support_multiple_targets() {
    let database = TestDatabase::new("relations");
    run_success(database.command().args(["create", "candidates", "jane"]));
    run_success(database.command().args(["create", "companies", "acme"]));
    run_success(database.command().args(["create", "companies", "globex"]));

    for target in ["acme", "acme", "globex"] {
        run_success(database.command().args([
            "link",
            "candidates",
            "jane",
            "companies",
            "companies",
            target,
        ]));
    }

    let fetched = run_success(
        database
            .command()
            .args(["get", "candidates", "jane", "--json"]),
    );
    let fetched: Value = serde_json::from_str(&fetched).unwrap();
    let companies = fetched["attributes"]["relations"]["companies"]
        .as_array()
        .unwrap();
    assert_eq!(companies.len(), 2);
    assert_eq!(companies[0]["id"], "acme");
    assert_eq!(companies[1]["id"], "globex");
}

#[test]
fn malformed_relation_fields_and_schema_rejection_preserve_the_record() {
    let malformed = TestDatabase::new("malformed-relations");
    run_success(malformed.command().args(["create", "companies", "acme"]));
    run_success(malformed.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "relations.company=not-a-list",
    ]));
    let path = malformed.root.join("records/candidates/jane.md");
    let before = fs::read_to_string(&path).unwrap();
    let stderr = run_failure(malformed.command().args([
        "link",
        "candidates",
        "jane",
        "company",
        "companies",
        "acme",
    ]));
    assert!(stderr.contains("relation 'company' must be a list"));
    assert_eq!(fs::read_to_string(path).unwrap(), before);

    run_success(malformed.command().args([
        "create",
        "candidates",
        "mira",
        "--set",
        "relations=not-an-object",
    ]));
    let path = malformed.root.join("records/candidates/mira.md");
    let before = fs::read_to_string(&path).unwrap();
    let stderr = run_failure(malformed.command().args([
        "link",
        "candidates",
        "mira",
        "company",
        "companies",
        "acme",
    ]));
    assert!(stderr.contains("field 'relations' must be an object"));
    assert_eq!(fs::read_to_string(path).unwrap(), before);

    let constrained = TestDatabase::new("schema-link");
    fs::write(
        constrained.root.join(".cr/schemas/candidates.json"),
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": { "name": { "type": "string" } },
  "required": ["name"],
  "additionalProperties": false
}"#,
    )
    .unwrap();
    run_success(
        constrained
            .command()
            .args(["create", "candidates", "jane", "--set", "name=Jane"]),
    );
    run_success(constrained.command().args(["create", "companies", "acme"]));
    let path = constrained.root.join("records/candidates/jane.md");
    let before = fs::read_to_string(&path).unwrap();
    let stderr = run_failure(constrained.command().args([
        "link",
        "candidates",
        "jane",
        "company",
        "companies",
        "acme",
    ]));
    assert!(stderr.contains("does not match schema"));
    assert_eq!(fs::read_to_string(path).unwrap(), before);
}

#[test]
fn invalid_schema_create_does_not_leave_a_record() {
    let database = TestDatabase::new("schema-create");
    fs::write(
        database.root.join(".cr/schemas/candidates.json"),
        r#"{
  "type": "object",
  "required": ["stage"],
  "properties": { "stage": { "enum": ["screening", "interview"] } }
}"#,
    )
    .unwrap();

    let stderr = run_failure(database.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=offer",
    ]));
    assert!(stderr.contains("does not match schema"));
    assert!(!database.root.join("records/candidates/jane.md").exists());
}
