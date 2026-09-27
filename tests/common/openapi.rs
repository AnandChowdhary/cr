//! Structural checks for the generated OpenAPI document, shared by the
//! example-based tests in `tests/server_api.rs` and the generated-schema
//! properties in `tests/http_properties.rs`.
//!
//! These are not a validator. They check the things a validator would take
//! for granted and `cr` assembles by hand: that references point somewhere,
//! and that paths, parameters, and operation IDs are unambiguous.

#![allow(dead_code)]

use std::collections::BTreeSet;

use percent_encoding::percent_decode_str;
use serde_json::Value;

/// Assert that every `$ref` in `document` resolves.
///
/// A reference resolves the way OpenAPI 3.1 and JSON Schema 2020-12 resolve
/// it: a fragment is a JSON pointer, or an `$anchor` name, within the nearest
/// enclosing schema resource — an object with an `$id` — and outside any
/// resource, within the document itself. That is why a collection schema that
/// uses `#/$defs/...` needs an `$id` once it is embedded in the document; see
/// `tests/http_properties.rs::a_collection_schema_with_local_definitions_resolves_inside_the_openapi_document`.
/// Anything but a fragment is reported, because `cr` refuses to compile a
/// schema that names an external resource.
pub fn assert_references_resolve(document: &Value) {
    let mut unresolved = Vec::new();
    walk(document, document, "", &mut unresolved);
    assert!(
        unresolved.is_empty(),
        "unresolved references:\n{}",
        unresolved.join("\n")
    );
}

fn walk(resource: &Value, value: &Value, location: &str, unresolved: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            let resource = if object.get("$id").is_some_and(Value::is_string) {
                value
            } else {
                resource
            };
            if let Some(reference) = object.get("$ref").and_then(Value::as_str)
                && !resolves(resource, reference)
            {
                unresolved.push(format!("{location}: {reference}"));
            }
            for (key, child) in object {
                walk(resource, child, &format!("{location}/{key}"), unresolved);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                walk(resource, child, &format!("{location}/{index}"), unresolved);
            }
        }
        _ => {}
    }
}

fn resolves(resource: &Value, reference: &str) -> bool {
    let Some(fragment) = reference.strip_prefix('#') else {
        return false;
    };
    let Ok(fragment) = percent_decode_str(fragment).decode_utf8() else {
        return false;
    };
    if fragment.is_empty() {
        return true;
    }
    if fragment.starts_with('/') {
        return resource.pointer(&fragment).is_some();
    }
    has_anchor(resource, &fragment)
}

fn has_anchor(value: &Value, anchor: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.get("$anchor").and_then(Value::as_str) == Some(anchor)
                || object.values().any(|child| has_anchor(child, anchor))
        }
        Value::Array(items) => items.iter().any(|child| has_anchor(child, anchor)),
        _ => false,
    }
}

/// The HTTP methods a path item can hold operations for.
const METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Assert that operation IDs are unique, that no operation lists a parameter
/// twice (by name and location, counting the path item's own parameters), and
/// that every `{name}` in a path template is a required path parameter of each
/// operation on it, and nothing else is.
pub fn assert_operations_are_unambiguous(document: &Value) {
    let mut operation_ids = BTreeSet::new();
    let paths = document["paths"].as_object().expect("paths is an object");
    for (path, item) in paths {
        let templated: BTreeSet<String> = path
            .split('/')
            .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
            .map(str::to_owned)
            .collect();
        let shared = parameters(document, item.get("parameters"));
        for method in METHODS {
            let Some(operation) = item.get(*method) else {
                continue;
            };
            let label = format!("{} {path}", method.to_uppercase());
            if let Some(id) = operation.get("operationId") {
                let id = id.as_str().expect("an operationId is a string");
                assert!(
                    operation_ids.insert(id.to_owned()),
                    "operationId {id} is used twice, the second time by {label}"
                );
            }
            let own = parameters(document, operation.get("parameters"));
            let mut seen = BTreeSet::new();
            for parameter in &own {
                assert!(
                    seen.insert(identity(parameter)),
                    "{label} lists parameter {:?} twice",
                    identity(parameter)
                );
            }
            // An operation's parameter overrides the path item's by identity.
            let mut effective = own.clone();
            for parameter in &shared {
                if !seen.contains(&identity(parameter)) {
                    effective.push(parameter.clone());
                }
            }
            let in_path: BTreeSet<String> = effective
                .iter()
                .filter(|parameter| parameter["in"] == "path")
                .map(|parameter| {
                    assert_eq!(
                        parameter["required"], true,
                        "{label}: path parameter {} must be required",
                        parameter["name"]
                    );
                    parameter["name"].as_str().unwrap().to_owned()
                })
                .collect();
            assert_eq!(
                in_path, templated,
                "{label}: path parameters do not match the template"
            );
        }
    }
}

fn parameters(document: &Value, list: Option<&Value>) -> Vec<Value> {
    let Some(list) = list else {
        return Vec::new();
    };
    list.as_array()
        .expect("parameters is an array")
        .iter()
        .map(
            |parameter| match parameter.get("$ref").and_then(Value::as_str) {
                Some(reference) => document
                    .pointer(reference.strip_prefix('#').expect("a local reference"))
                    .unwrap_or_else(|| panic!("unresolved parameter {reference}"))
                    .clone(),
                None => parameter.clone(),
            },
        )
        .collect()
}

/// A parameter's name and location, which is what makes it unique. Header
/// names are case-insensitive, so `If-Match` and `if-match` are one header.
fn identity(parameter: &Value) -> (String, String) {
    let name = parameter["name"].as_str().expect("a parameter has a name");
    let location = parameter["in"]
        .as_str()
        .expect("a parameter has a location");
    let name = if location == "header" {
        name.to_ascii_lowercase()
    } else {
        name.to_owned()
    };
    (name, location.to_owned())
}
