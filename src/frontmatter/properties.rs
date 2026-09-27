//! Properties of the front matter parser and renderer over generated input.
//!
//! These live beside the parser rather than under `tests/` because
//! [`Document`] is not public: the integration tests reach it only through a
//! database, which is what `tests/frontmatter_properties.rs` does. The
//! generator and the seed convention are the integration tests' own, included
//! by path, so a failure here is reported and replayed exactly like one there;
//! see `tests/common/rng.rs`.

#[path = "../../tests/common/rng.rs"]
mod rng;

#[path = "../../tests/common/generate.rs"]
mod generate;

use yaml_serde::{Mapping, Value, value::TaggedValue};

use super::Document;
use crate::DomainError;
use rng::{Rng, cases};

/// Every reason the parser gives for refusing input, as the outermost message
/// of its error. Anything else is an unclassified failure.
const REFUSALS: &[&str] = &[
    "record is empty",
    "record must begin with a YAML front matter delimiter ('---')",
    "front matter is not valid YAML",
    "front matter must be a YAML mapping",
    "record is missing its closing front matter delimiter ('---')",
];

/// Parse `input`, requiring a refusal to be one of [`REFUSALS`] and a success
/// to have split the input exactly where the format says.
fn parse(input: &str) -> Option<Document> {
    match Document::parse(input) {
        Ok(document) => {
            assert_split_at_the_first_closing_delimiter(input, &document);
            Some(document)
        }
        Err(error) => {
            let message = error.to_string();
            assert!(
                REFUSALS.contains(&message.as_str()),
                "unclassified refusal {message:?} for {input:?}"
            );
            None
        }
    }
}

/// The body is the input's exact bytes after the first line, other than the
/// opening one, that is `---` with an optional line ending.
fn assert_split_at_the_first_closing_delimiter(input: &str, document: &Document) {
    let head = input
        .strip_suffix(document.body.as_str())
        .unwrap_or_else(|| panic!("the body is not a suffix of the input: {input:?}"));
    let lines: Vec<&str> = head.split_inclusive('\n').collect();
    assert!(lines.len() >= 2, "no delimiters before the body: {input:?}");
    assert_eq!(line_text(lines[0]), "---", "{input:?}");
    assert_eq!(line_text(lines[lines.len() - 1]), "---", "{input:?}");
    for line in &lines[1..lines.len() - 1] {
        assert_ne!(
            line_text(line),
            "---",
            "the front matter ran past a closing delimiter: {input:?}"
        );
    }
    if !document.body.is_empty() {
        assert!(
            head.ends_with('\n'),
            "a body started inside the closing delimiter line: {input:?}"
        );
    }
}

fn line_text(line: &str) -> &str {
    line.strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(line)
}

/// Whether a key anywhere in `mapping` is itself a mapping or a tagged value,
/// which the YAML emitter cannot write (see
/// [`non_string_keys_are_pinned_at_the_json_boundary`]).
fn has_unrenderable_key(mapping: &Mapping) -> bool {
    mapping.iter().any(|(key, value)| {
        key_is_unrenderable(key)
            || value_has_unrenderable_key(key)
            || value_has_unrenderable_key(value)
    })
}

fn key_is_unrenderable(key: &Value) -> bool {
    match key {
        Value::Mapping(_) | Value::Tagged(_) => true,
        Value::Sequence(items) => items.iter().any(key_is_unrenderable),
        _ => false,
    }
}

fn value_has_unrenderable_key(value: &Value) -> bool {
    match value {
        Value::Mapping(mapping) => has_unrenderable_key(mapping),
        Value::Sequence(items) => items.iter().any(value_has_unrenderable_key),
        Value::Tagged(tagged) => value_has_unrenderable_key(&tagged.value),
        _ => false,
    }
}

/// Whether any string in `mapping`, key or value, holds a line or paragraph
/// separator, which the emitter cannot always write back exactly.
fn has_separator(mapping: &Mapping) -> bool {
    fn value_has_separator(value: &Value) -> bool {
        match value {
            Value::String(text) => text.contains(['\u{2028}', '\u{2029}']),
            Value::Mapping(mapping) => has_separator(mapping),
            Value::Sequence(items) => items.iter().any(value_has_separator),
            Value::Tagged(tagged) => value_has_separator(&tagged.value),
            _ => false,
        }
    }
    mapping
        .iter()
        .any(|(key, value)| value_has_separator(key) || value_has_separator(value))
}

/// Render `document`, allowing only the two refusals `render` is known to
/// make: keys the emitter cannot write, and strings it cannot write exactly.
fn render(document: &Document, origin: &str) -> Option<String> {
    let error = match document.render() {
        Ok(rendered) => return Some(rendered),
        Err(error) => error,
    };
    let expected = match DomainError::of(&error) {
        Some(DomainError::Invalid(_)) => has_separator(&document.attributes),
        None => {
            error.to_string() == "could not serialize record front matter"
                && has_unrenderable_key(&document.attributes)
        }
        Some(_) => false,
    };
    assert!(expected, "{error:#} rendering {origin:?}: {document:?}");
    None
}

/// Rendering a parsed document and parsing it again changes nothing, and a
/// second render reproduces the first byte for byte.
fn assert_normalizes_once(document: &Document, origin: &str) {
    let Some(rendered) = render(document, origin) else {
        return;
    };
    let reparsed = parse(&rendered)
        .unwrap_or_else(|| panic!("a rendered document was refused: {rendered:?} from {origin:?}"));
    assert_eq!(
        reparsed.attributes, document.attributes,
        "front matter changed through a render: {rendered:?} from {origin:?}"
    );
    assert_eq!(
        reparsed.body, document.body,
        "the body changed through a render: {rendered:?}"
    );
    assert_eq!(
        reparsed.render().expect("a reparsed document renders"),
        rendered,
        "rendering is not a fixed point after one normalization: {origin:?}"
    );
}

fn generated_document(rng: &mut Rng) -> Document {
    Document {
        attributes: generate::mapping(rng, 3),
        body: generate::body(rng),
    }
}

/// Arbitrary text, including text that gets past the opening delimiter, is
/// parsed or refused for a stated reason, and never panics the parser.
#[test]
fn arbitrary_text_parses_or_is_refused_for_a_stated_reason() {
    for mut case in cases(
        "arbitrary_text_parses_or_is_refused_for_a_stated_reason",
        2000,
    ) {
        let rng = &mut case.rng;
        let input = match rng.below(4) {
            0 => {
                let bytes: Vec<u8> = (0..rng.below(200)).map(|_| rng.next() as u8).collect();
                String::from_utf8_lossy(&bytes).into_owned()
            }
            1 => format!("---\n{}", generate::noise(rng, 60)),
            2 => format!(
                "---{}{}\n---{}{}",
                rng.pick(&["\n", "\r\n", ""]),
                generate::noise(rng, 60),
                rng.pick(&["\n", "\r\n", ""]),
                generate::noise(rng, 20)
            ),
            _ => generate::noise(rng, 80),
        };
        if let Some(document) = parse(&input) {
            assert_normalizes_once(&document, &input);
        }
    }
}

/// Generated documents — nested mappings, sequences, scalars of every YAML
/// type, strings YAML has opinions about, and bodies that begin with or
/// contain `---` — survive a render and a parse exactly, and the render is a
/// fixed point.
#[test]
fn generated_documents_round_trip_exactly() {
    for mut case in cases("generated_documents_round_trip_exactly", 1000) {
        let document = generated_document(&mut case.rng);
        let Some(rendered) = render(&document, "a generated document") else {
            continue;
        };
        assert!(rendered.starts_with("---\n"), "{rendered:?}");
        assert!(rendered.ends_with(&document.body), "{rendered:?}");
        let parsed = parse(&rendered).unwrap_or_else(|| panic!("refused {rendered:?}"));
        assert_eq!(parsed.attributes, document.attributes, "{rendered:?}");
        assert_eq!(parsed.body, document.body, "{rendered:?}");
        assert_normalizes_once(&parsed, &rendered);
    }
}

/// Edits of a valid document — inserted YAML punctuation, deleted ranges,
/// duplicated lines, changed line endings, truncation — are parsed or refused
/// for a stated reason, and whatever parses normalizes in one render.
#[test]
fn near_valid_documents_parse_or_are_refused_and_normalize_once() {
    for mut case in cases(
        "near_valid_documents_parse_or_are_refused_and_normalize_once",
        1000,
    ) {
        let rng = &mut case.rng;
        let Ok(mut text) = generated_document(rng).render() else {
            continue;
        };
        for _ in 0..rng.between(1, 4) {
            text = mutate(rng, &text);
        }
        if let Some(document) = parse(&text) {
            assert_normalizes_once(&document, &text);
        }
    }
}

fn mutate(rng: &mut Rng, text: &str) -> String {
    let boundaries: Vec<usize> = text
        .char_indices()
        .map(|(index, _)| index)
        .chain([text.len()])
        .collect();
    let at = *rng.pick(&boundaries);
    let until = *rng.pick(&boundaries);
    let (start, end) = (at.min(until), at.max(until));
    match rng.below(6) {
        0 => format!("{}{}{}", &text[..at], generate::string(rng), &text[at..]),
        1 => format!("{}{}", &text[..start], &text[end..]),
        2 => format!("{}{}", &text[..at], text[at..].replacen('\n', "\r\n", 1)),
        3 => {
            let lines: Vec<&str> = text.split_inclusive('\n').collect();
            if lines.is_empty() {
                return text.to_owned();
            }
            let line = rng.below(lines.len());
            let mut edited = lines.clone();
            edited.insert(line, lines[line]);
            edited.concat()
        }
        4 => text[..at].to_owned(),
        _ => format!(
            "{}{}{}",
            &text[..at],
            rng.pick(&[
                "---\n", "\n---\n", ": ", "- ", "  ", "\t", "#", "&a ", "*a", "!t ", "? ", "|\n",
                ">-\n", "{", "[", "'", "\""
            ]),
            &text[at..]
        ),
    }
}

/// Front matter keys that are not strings parse, but JSON — the audit
/// journal's and the HTTP API's representation — has only string keys, and
/// the YAML emitter cannot write every key the parser accepts. This pins where
/// each kind of key lands today. It is a record of current behaviour, not an
/// endorsement: see the JSON-representability note in `TODO.md`.
#[test]
fn non_string_keys_are_pinned_at_the_json_boundary() {
    struct Pin {
        written: &'static str,
        key: Value,
        /// The key as `render` writes it, or `None` if `render` fails.
        rendered: Option<&'static str>,
        /// The JSON object key, or `None` if JSON cannot represent the key.
        json: Option<&'static str>,
    }
    let tagged = Value::Tagged(Box::new(TaggedValue {
        tag: yaml_serde::value::Tag::new("x"),
        value: Value::String("y".into()),
    }));
    let pins = [
        Pin {
            written: "plain",
            key: Value::String("plain".into()),
            rendered: Some("plain"),
            json: Some("plain"),
        },
        Pin {
            written: "'1'",
            key: Value::String("1".into()),
            rendered: Some("'1'"),
            json: Some("1"),
        },
        Pin {
            written: "1",
            key: Value::Number(1.into()),
            rendered: Some("1"),
            json: Some("1"),
        },
        Pin {
            written: "-7",
            key: Value::Number((-7).into()),
            rendered: Some("-7"),
            json: Some("-7"),
        },
        Pin {
            written: "1.5",
            key: Value::Number(1.5.into()),
            rendered: Some("1.5"),
            json: Some("1.5"),
        },
        Pin {
            written: "true",
            key: Value::Bool(true),
            rendered: Some("true"),
            json: Some("true"),
        },
        Pin {
            written: "null",
            key: Value::Null,
            rendered: Some("null"),
            json: None,
        },
        Pin {
            written: "~",
            key: Value::Null,
            rendered: Some("null"),
            json: None,
        },
        Pin {
            written: "[a, b]",
            key: Value::Sequence(vec!["a".into(), "b".into()]),
            rendered: Some("? - a\n  - b\n"),
            json: None,
        },
        Pin {
            written: "{a: b}",
            key: Value::Mapping([("a".into(), "b".into())].into_iter().collect()),
            rendered: None,
            json: None,
        },
        Pin {
            written: "!x y",
            key: tagged,
            rendered: None,
            json: None,
        },
    ];
    for pin in pins {
        let text = format!("---\n{}: value\n---\nBody\n", pin.written);
        let document = parse(&text).unwrap_or_else(|| panic!("{} was refused", pin.written));
        let (key, value) = document.attributes.iter().next().unwrap();
        assert_eq!(key, &pin.key, "{} parses as its YAML type", pin.written);
        assert_eq!(value, &Value::String("value".into()));

        match (document.render(), pin.rendered) {
            (Ok(rendered), Some(expected)) => {
                assert!(
                    rendered.starts_with(&format!("---\n{expected}")),
                    "{} renders as {rendered:?}",
                    pin.written
                );
                assert_eq!(parse(&rendered).unwrap().attributes, document.attributes);
            }
            (Err(error), None) => assert_eq!(
                error.to_string(),
                "could not serialize record front matter",
                "{}",
                pin.written
            ),
            (rendered, expected) => panic!(
                "{}: render gave {:?}, pinned {expected:?}",
                pin.written,
                rendered.map_err(|error| format!("{error:#}"))
            ),
        }

        match (serde_json::to_value(&document.attributes), pin.json) {
            (Ok(json), Some(expected)) => {
                let object = json.as_object().unwrap();
                assert_eq!(
                    object.keys().collect::<Vec<_>>(),
                    [expected],
                    "{}",
                    pin.written
                );
                // The JSON key is always a string, so a key that was not one
                // does not come back as itself from an audited state.
                let restored = Document::from_audit_value(
                    &serde_json::json!({ "attributes": json, "body": "Body\n" }),
                )
                .unwrap();
                assert_eq!(
                    restored.attributes.keys().next().unwrap(),
                    &Value::String(expected.to_owned())
                );
                assert_eq!(
                    restored.attributes == document.attributes,
                    matches!(pin.key, Value::String(_)),
                    "{}",
                    pin.written
                );
            }
            (Err(_), None) => {}
            (json, expected) => panic!("{}: JSON gave {json:?}, pinned {expected:?}", pin.written),
        }
    }

    // Distinct YAML keys can be one JSON key: the integer 1 and the string
    // '1' are two entries in YAML and one in JSON, where the later one wins.
    let document = parse("---\n1: integer\n'1': string\n---\n").unwrap();
    assert_eq!(document.attributes.len(), 2);
    let json = serde_json::to_value(&document.attributes).unwrap();
    assert_eq!(json, serde_json::json!({ "1": "string" }));
}
