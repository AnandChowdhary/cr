//! Properties of the small languages a caller writes: dotted field paths,
//! `KEY=YAML` assignments, `--where-expr` expressions, `--filter` expressions,
//! sort keys, and `--select` projections.
//!
//! Each parser is fed arbitrary text and must answer with a value or a
//! classified refusal, never a panic. Where a language has a written form the
//! code prints — sort keys and projections — printing and parsing round trip.
//! Where it has none — filters — the test prints generated expressions itself
//! and checks that what parses means what was generated, by evaluating it
//! against generated records beside a reference evaluator written here from
//! the documented semantics. The seed convention is `tests/common/rng.rs`'s.

mod common;

use std::{cmp::Ordering, fmt::Write as _, path::PathBuf, str::FromStr};

use common::{
    generate,
    rng::{Rng, cases},
};
use cr::{
    Assignment, DomainError, Filter, FilterExpression, FilterOperator, MAX_SORT_KEYS, Projection,
    Record, SortDirection, SortKey, compare_yaml_values, parse_sort_keys, sort_records,
};
use yaml_serde::{Mapping, Value};

/// `result` succeeded, or was refused as invalid input.
fn valid_or_invalid<T>(input: &str, result: anyhow::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            assert!(
                matches!(DomainError::of(&error), Some(DomainError::Invalid(_))),
                "{input:?} was refused unclassified: {error:#}"
            );
            None
        }
    }
}

/// Pieces of every language here, so arbitrary input is mostly near misses.
const TOKENS: &[&str] = &[
    "(",
    ")",
    "[",
    "]",
    ",",
    "=",
    "!=",
    "!",
    ">",
    ">=",
    "<",
    "<=",
    "\"",
    "'",
    "\\",
    "\\\"",
    "AND",
    "and",
    "OR",
    "or",
    "NOT",
    "not",
    "in",
    "not in",
    "is",
    "is not",
    "null",
    "empty",
    "exists",
    "contains",
    "not-contains",
    "starts-with",
    "ends-with",
    "is-empty",
    "is-not-empty",
    "$id",
    "$collection",
    "$path",
    "$version",
    "$body",
    "$x",
    "$",
    "stage",
    "value",
    "a.b",
    "a..b",
    ".",
    "..",
    ":",
    ":asc",
    ":desc",
    ":DESC",
    "-value",
    "og:title",
    "1",
    "-1",
    "1.5",
    "1e999",
    "true",
    "[a",
    "{a: b}",
    "&x",
    "*x",
    "!!str",
    "|",
    "#",
    " ",
    "  ",
    "\t",
    "\n",
    "é",
    "🙂",
    "\u{0}",
];

/// Text assembled from [`TOKENS`] and stray characters.
fn token_soup(rng: &mut Rng) -> String {
    let mut text = String::new();
    for _ in 0..rng.below(16) {
        match rng.below(5) {
            0 => text.push_str(&generate::noise(rng, 3)),
            1 => text.push_str(&generate::string(rng)),
            _ => text.push_str(rng.pick::<&str>(TOKENS)),
        }
        if rng.chance(1, 2) {
            text.push(' ');
        }
    }
    text
}

// ---------------------------------------------------------------------------
// Field paths and assignments
// ---------------------------------------------------------------------------

/// A field path is its text split on every dot, and nothing else: there is no
/// escape, so its written form is the parts joined with dots. A path with an
/// empty part is refused.
#[test]
fn field_paths_split_on_every_dot_and_refuse_empty_parts() {
    for mut case in cases(
        "field_paths_split_on_every_dot_and_refuse_empty_parts",
        2000,
    ) {
        let rng = &mut case.rng;
        let path = match rng.below(3) {
            0 => token_soup(rng),
            _ => (0..rng.between(1, 4))
                .map(|_| generate::string(rng))
                .collect::<Vec<_>>()
                .join("."),
        };
        let expected_valid = !path.is_empty() && !path.split('.').any(str::is_empty);
        let Some(assignment) = valid_or_invalid(&path, Assignment::string(&path, "value")) else {
            assert!(!expected_valid, "{path:?} was refused");
            continue;
        };
        assert!(expected_valid, "{path:?} was accepted");
        assert_eq!(
            assignment.path(),
            path.split('.').collect::<Vec<_>>(),
            "{path:?}"
        );
        assert_eq!(assignment.path().join("."), path);

        // The path addresses what the assignment wrote.
        let mut attributes = Mapping::new();
        assignment.apply(&mut attributes).unwrap();
        let record = record("items", "one", attributes);
        assert_eq!(
            record.field(&path).unwrap(),
            Some(&Value::String("value".into()))
        );
    }
}

/// `KEY=YAML` is total: any text is an assignment or a classified refusal.
#[test]
fn assignments_parse_or_are_refused_with_a_classification() {
    for mut case in cases(
        "assignments_parse_or_are_refused_with_a_classification",
        2000,
    ) {
        let rng = &mut case.rng;
        let input = match rng.below(3) {
            0 => token_soup(rng),
            1 => format!("{}={}", generate::string(rng), token_soup(rng)),
            _ => format!("{}={}", token_soup(rng), generate::string(rng)),
        };
        let Some(assignment) = valid_or_invalid(&input, Assignment::from_str(&input)) else {
            continue;
        };
        let (key, raw) = input.split_once('=').expect("an assignment has an '='");
        assert_eq!(assignment.path().join("."), key, "{input:?}");
        if raw.is_empty() {
            let mut attributes = Mapping::new();
            assignment.apply(&mut attributes).unwrap();
            assert_eq!(
                record("items", "one", attributes).field(key).unwrap(),
                Some(&Value::String(String::new()))
            );
        }
    }
}

/// Parts a generated path is made of: nothing a path or an expression treats
/// as punctuation, but otherwise as awkward as possible.
const PATH_PARTS: &[&str] = &[
    "stage",
    "value",
    "tags",
    "owner",
    "name",
    "notes",
    "flag",
    "missing",
    "a",
    "Z",
    "_x",
    "with-dash",
    "é",
    "日本",
    "🙂",
    "$not_a_field",
    "0",
    "true",
    "null",
];

fn path(rng: &mut Rng) -> String {
    (0..rng.between(1, 3))
        .map(|_| *rng.pick(PATH_PARTS))
        .collect::<Vec<_>>()
        .join(".")
}

/// A generated value written as YAML after `KEY=` reads back as itself, and
/// the assignment writes it at its path.
#[test]
fn generated_assignments_carry_their_yaml_value_exactly() {
    for mut case in cases("generated_assignments_carry_their_yaml_value_exactly", 1000) {
        let rng = &mut case.rng;
        let path = path(rng);
        let value = generate::value(rng, 2);
        let yaml = yaml_serde::to_string(&value).unwrap();
        // The emitter cannot write every string exactly (see
        // `src/frontmatter/properties.rs`); that is its property, not this one.
        if yaml_serde::from_str::<Value>(&yaml).ok().as_ref() != Some(&value) {
            continue;
        }
        let input = format!("{path}={yaml}");
        let assignment = Assignment::from_str(&input)
            .unwrap_or_else(|error| panic!("{input:?} was refused: {error:#}"));

        let mut attributes = Mapping::new();
        assignment.apply(&mut attributes).unwrap();
        assert_eq!(
            record("items", "one", attributes.clone())
                .field(&path)
                .unwrap(),
            Some(&value),
            "{input:?}"
        );
        // An assignment used as a filter is exact equality on the same value.
        assert!(FilterExpression::from(assignment).matches(&attributes));
    }
}

// ---------------------------------------------------------------------------
// Records and a reference evaluator
// ---------------------------------------------------------------------------

fn record(collection: &str, id: &str, attributes: Mapping) -> Record {
    Record {
        collection: collection.to_owned(),
        id: id.to_owned(),
        path: PathBuf::from(format!("records/{collection}/{id}.md")),
        version: String::new(),
        attributes,
        body: String::new(),
    }
}

/// Scalars small enough that generated predicates often hit.
fn small_scalar(rng: &mut Rng) -> Value {
    match rng.below(9) {
        0 => Value::Null,
        1 => Value::Bool(rng.chance(1, 2)),
        2 => Value::Number((rng.below(7) as i64 - 2).into()),
        3 => Value::Number((*rng.pick(&[2.5, -0.5, f64::NAN, f64::INFINITY])).into()),
        4 => Value::String(String::new()),
        5 => Value::String((rng.below(7) as i64 - 2).to_string()),
        _ => Value::String((*rng.pick(&["open", "won", "Acme Corp", "é", "a\"b'c\\d"])).into()),
    }
}

fn small_value(rng: &mut Rng) -> Value {
    match rng.below(6) {
        0 => Value::Sequence((0..rng.below(3)).map(|_| small_scalar(rng)).collect()),
        1 => Value::Mapping(
            (0..rng.below(3))
                .map(|_| {
                    (
                        Value::String((*rng.pick(&["name", "a"])).into()),
                        small_scalar(rng),
                    )
                })
                .collect(),
        ),
        _ => small_scalar(rng),
    }
}

/// A record over the field names [`PATH_PARTS`] starts with.
fn small_record(rng: &mut Rng, id: &str) -> Record {
    let mut attributes = Mapping::new();
    for field in ["stage", "value", "tags", "owner", "notes", "flag"] {
        if rng.chance(3, 4) {
            attributes.insert(field.into(), small_value(rng));
        }
    }
    let collection = *rng.pick(&["deals", "notes"]);
    record(collection, id, attributes)
}

/// The value at `path`, found by walking string keys.
fn lookup<'a>(attributes: &'a Mapping, path: &[&str]) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    let mut current = attributes.get(Value::String((*first).to_owned()))?;
    for part in rest {
        current = match current {
            Value::Mapping(mapping) => mapping.get(Value::String((*part).to_owned()))?,
            _ => return None,
        };
    }
    Some(current)
}

fn as_float(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        _ => None,
    }
}

/// The documented meaning of each operator, written out independently of
/// `src/value.rs`: every operator except the emptiness tests is false for a
/// missing field; ordering compares numbers numerically and strings
/// lexicographically and nothing else; containment is substring or list
/// membership.
fn reference_operator(operator: FilterOperator, current: Option<&Value>, expected: &Value) -> bool {
    let empty = match current {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(Value::Sequence(items)) => items.is_empty(),
        Some(Value::Mapping(mapping)) => mapping.is_empty(),
        Some(_) => false,
    };
    let order = || -> Option<Ordering> {
        match (current?, expected) {
            (Value::String(left), Value::String(right)) => Some(left.cmp(right)),
            (left, right) => as_float(left)?.partial_cmp(&as_float(right)?),
        }
    };
    let contains = || match (current, expected) {
        (Some(Value::String(text)), Value::String(part)) => text.contains(part.as_str()),
        (Some(Value::Sequence(items)), item) => items.contains(item),
        _ => false,
    };
    let strings = || match (current, expected) {
        (Some(Value::String(text)), Value::String(part)) => Some((text.as_str(), part.as_str())),
        _ => None,
    };
    match operator {
        FilterOperator::IsEmpty => empty,
        FilterOperator::IsNotEmpty => !empty,
        FilterOperator::Equal => current == Some(expected),
        FilterOperator::NotEqual => current.is_some_and(|current| current != expected),
        FilterOperator::GreaterThan => order() == Some(Ordering::Greater),
        FilterOperator::GreaterThanOrEqual => {
            matches!(order(), Some(Ordering::Greater | Ordering::Equal))
        }
        FilterOperator::LessThan => order() == Some(Ordering::Less),
        FilterOperator::LessThanOrEqual => {
            matches!(order(), Some(Ordering::Less | Ordering::Equal))
        }
        FilterOperator::Contains => contains(),
        FilterOperator::NotContains => current.is_some() && !contains(),
        FilterOperator::StartsWith => strings().is_some_and(|(text, part)| text.starts_with(part)),
        FilterOperator::EndsWith => strings().is_some_and(|(text, part)| text.ends_with(part)),
    }
}

const OPERATORS: &[FilterOperator] = &[
    FilterOperator::Equal,
    FilterOperator::NotEqual,
    FilterOperator::GreaterThan,
    FilterOperator::GreaterThanOrEqual,
    FilterOperator::LessThan,
    FilterOperator::LessThanOrEqual,
    FilterOperator::Contains,
    FilterOperator::NotContains,
    FilterOperator::StartsWith,
    FilterOperator::EndsWith,
    FilterOperator::IsEmpty,
    FilterOperator::IsNotEmpty,
];

fn symbol(operator: FilterOperator) -> Option<&'static str> {
    Some(match operator {
        FilterOperator::Equal => "=",
        FilterOperator::NotEqual => "!=",
        FilterOperator::GreaterThan => ">",
        FilterOperator::GreaterThanOrEqual => ">=",
        FilterOperator::LessThan => "<",
        FilterOperator::LessThanOrEqual => "<=",
        _ => return None,
    })
}

fn spaces(rng: &mut Rng) -> &'static str {
    rng.pick::<&str>(&["", " ", "  ", "\t"])
}

// ---------------------------------------------------------------------------
// --where-expr
// ---------------------------------------------------------------------------

/// Arbitrary text is a where-expression or a classified refusal, and `split`,
/// which the view builder uses on stored expressions, never panics.
#[test]
fn where_expressions_parse_or_are_refused_with_a_classification() {
    for mut case in cases(
        "where_expressions_parse_or_are_refused_with_a_classification",
        2000,
    ) {
        let input = token_soup(&mut case.rng);
        let _ = FilterExpression::split(&input);
        valid_or_invalid(&input, FilterExpression::from_str(&input));
    }
}

/// A value written as YAML on one line, so it can follow an operator.
fn inline_yaml(value: &Value) -> Option<String> {
    let yaml = yaml_serde::to_string(value).ok()?;
    let yaml = yaml.strip_suffix('\n')?;
    (!yaml.contains('\n') && !yaml.starts_with('=') && !yaml.is_empty()).then(|| yaml.to_owned())
}

/// A generated expression splits into exactly the path, operator, and value
/// it was written with, and matches exactly the records the reference says.
#[test]
fn where_expressions_split_where_they_were_joined_and_agree_with_a_reference() {
    for mut case in cases(
        "where_expressions_split_where_they_were_joined_and_agree_with_a_reference",
        1000,
    ) {
        let rng = &mut case.rng;
        let path = path(rng);
        let operator = *rng.pick(OPERATORS);
        let value = small_value(rng);
        let raw = if operator.requires_value() {
            match inline_yaml(&value) {
                Some(raw) => raw,
                None => continue,
            }
        } else {
            String::new()
        };
        let input = match symbol(operator) {
            Some(symbol) => format!(
                "{}{path}{}{symbol}{}{raw}",
                spaces(rng),
                spaces(rng),
                spaces(rng)
            ),
            None => format!("{path} {operator} {raw}"),
        };
        let (split_path, split_operator, split_raw) = FilterExpression::split(&input)
            .unwrap_or_else(|error| panic!("{input:?} did not split: {error:#}"));
        assert_eq!(
            (split_path, split_operator, split_raw),
            (path.as_str(), operator, raw.as_str()),
            "{input:?}"
        );
        let expression = FilterExpression::from_str(&input)
            .unwrap_or_else(|error| panic!("{input:?} was refused: {error:#}"));
        assert_eq!(expression.operator(), operator);

        let parts: Vec<&str> = path.split('.').collect();
        for index in 0..8 {
            let record = small_record(rng, &format!("r{index}"));
            let current = lookup(&record.attributes, &parts);
            assert_eq!(
                expression.matches(&record.attributes),
                reference_operator(operator, current, &value),
                "{input:?} against {:?}",
                record.attributes
            );
        }
    }
}

// ---------------------------------------------------------------------------
// --filter
// ---------------------------------------------------------------------------

/// Arbitrary text is a filter or a classified refusal.
#[test]
fn filters_parse_or_are_refused_with_a_classification() {
    for mut case in cases("filters_parse_or_are_refused_with_a_classification", 3000) {
        let input = token_soup(&mut case.rng);
        valid_or_invalid(&input, Filter::from_str(&input));
    }
}

/// Nesting deep enough to exhaust the parser's stack used to abort the whole
/// process — for `cr serve`, every connection at once. It is refused.
#[test]
fn ten_thousand_open_parentheses_are_refused_rather_than_overflowing_the_stack() {
    for input in [
        format!("{}stage = open{}", "(".repeat(10_000), ")".repeat(10_000)),
        format!("{}stage = open", "NOT ".repeat(10_000)),
        format!("{}stage = open", "(NOT ".repeat(10_000)),
    ] {
        let error = Filter::from_str(&input).unwrap_err();
        assert!(
            matches!(DomainError::of(&error), Some(DomainError::Invalid(_))),
            "{error:#}"
        );
        assert!(
            error
                .to_string()
                .starts_with("parentheses and NOT nest more than 64 levels deep"),
            "{error}"
        );
    }
}

#[derive(Clone, Debug)]
enum Expression {
    And(Vec<Expression>),
    Or(Vec<Expression>),
    Not(Box<Expression>),
    Predicate(Field, Test),
}

#[derive(Clone, Debug)]
enum Field {
    Attribute(String),
    Id,
    Collection,
    Path,
}

#[derive(Clone, Debug)]
enum Test {
    Operator(FilterOperator, Value),
    In(Vec<Value>),
    NotIn(Vec<Value>),
    Exists,
    NotExists,
    IsNull,
    IsNotNull,
}

fn expression(rng: &mut Rng, depth: usize) -> Expression {
    if depth == 0 || rng.chance(2, 5) {
        return Expression::Predicate(field(rng), test(rng));
    }
    match rng.below(3) {
        0 => Expression::And(
            (0..rng.between(2, 3))
                .map(|_| expression(rng, depth - 1))
                .collect(),
        ),
        1 => Expression::Or(
            (0..rng.between(2, 3))
                .map(|_| expression(rng, depth - 1))
                .collect(),
        ),
        _ => Expression::Not(Box::new(expression(rng, depth - 1))),
    }
}

fn field(rng: &mut Rng) -> Field {
    match rng.below(8) {
        0 => Field::Id,
        1 => Field::Collection,
        2 => Field::Path,
        _ => Field::Attribute(filter_path(rng)),
    }
}

/// A path a filter can name: not one whose first part starts with `$`, which
/// the filter reserves for `$id`, `$collection`, and `$path`.
fn filter_path(rng: &mut Rng) -> String {
    loop {
        let path = path(rng);
        if !path.starts_with('$') {
            return path;
        }
    }
}

fn test(rng: &mut Rng) -> Test {
    match rng.below(10) {
        0 => Test::In((0..rng.below(3)).map(|_| small_scalar(rng)).collect()),
        1 => Test::NotIn((0..rng.below(3)).map(|_| small_scalar(rng)).collect()),
        2 => rng
            .pick(&[Test::Exists, Test::NotExists, Test::IsNull, Test::IsNotNull])
            .clone(),
        _ => {
            let operator = *rng.pick(OPERATORS);
            let value = if !operator.requires_value() {
                Value::Null
            } else if rng.chance(1, 5) {
                Value::Sequence((0..rng.below(3)).map(|_| small_scalar(rng)).collect())
            } else {
                small_scalar(rng)
            };
            Test::Operator(operator, value)
        }
    }
}

fn keyword(rng: &mut Rng, word: &str) -> String {
    match rng.below(3) {
        0 => word.to_ascii_uppercase(),
        1 => word.to_ascii_lowercase(),
        _ => {
            let mut characters = word.chars();
            let first = characters.next().unwrap().to_ascii_uppercase();
            format!("{first}{}", characters.as_str().to_ascii_lowercase())
        }
    }
}

/// Write a filter value. A string is quoted unless it is a word YAML also
/// reads as that string; numbers, booleans, and null are bare words.
fn print_value(rng: &mut Rng, value: &Value, out: &mut String) {
    match value {
        Value::String(text)
            if ["open", "won", "Acme"].contains(&text.as_str()) && rng.chance(1, 2) =>
        {
            out.push_str(text);
        }
        Value::String(text) => {
            let quote = *rng.pick(&['"', '\'']);
            out.push(quote);
            for character in text.chars() {
                if character == '\\'
                    || character == quote
                    || (character == '\'' && rng.chance(1, 2))
                {
                    out.push('\\');
                }
                out.push(character);
            }
            out.push(quote);
        }
        Value::Number(number) => {
            let float = number.as_f64().unwrap();
            if float.is_nan() {
                out.push_str(".nan");
            } else if float.is_infinite() {
                out.push_str(if float > 0.0 { ".inf" } else { "-.inf" });
            } else {
                write!(out, "{number}").unwrap();
            }
        }
        Value::Bool(flag) => write!(out, "{flag}").unwrap(),
        Value::Null => out.push_str(rng.pick::<&str>(&["null", "~"])),
        Value::Sequence(items) => print_list(rng, items, out),
        other => panic!("filters have no spelling for {other:?}"),
    }
}

fn print_list(rng: &mut Rng, items: &[Value], out: &mut String) {
    out.push('[');
    out.push_str(spaces(rng));
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(spaces(rng));
            out.push(',');
            out.push_str(spaces(rng));
        }
        print_value(rng, item, out);
    }
    out.push_str(spaces(rng));
    out.push(']');
}

/// Print `expression` as a filter, parenthesizing only where precedence needs
/// it, and sometimes where it does not.
fn print(rng: &mut Rng, expression: &Expression, out: &mut String) {
    let tighter_than_and = |child: &Expression| !matches!(child, Expression::Or(_));
    let atomic =
        |child: &Expression| matches!(child, Expression::Predicate(..) | Expression::Not(_));
    let redundant = rng.chance(1, 6);
    if redundant {
        out.push('(');
        out.push_str(spaces(rng));
    }
    match expression {
        Expression::Or(children) | Expression::And(children) => {
            let is_and = matches!(expression, Expression::And(_));
            for (index, child) in children.iter().enumerate() {
                if index > 0 {
                    let word = keyword(rng, if is_and { "and" } else { "or" });
                    write!(out, " {word} ").unwrap();
                }
                let bare = if is_and {
                    tighter_than_and(child)
                } else {
                    true
                };
                print_grouped(rng, child, !bare, out);
            }
        }
        Expression::Not(child) => {
            let word = keyword(rng, "not");
            write!(out, "{word} ").unwrap();
            print_grouped(rng, child, !atomic(child), out);
        }
        Expression::Predicate(field, test) => {
            match field {
                Field::Attribute(path) => out.push_str(path),
                Field::Id => out.push_str("$id"),
                Field::Collection => out.push_str("$collection"),
                Field::Path => out.push_str("$path"),
            }
            print_test(rng, test, out);
        }
    }
    if redundant {
        out.push_str(spaces(rng));
        out.push(')');
    }
}

fn print_grouped(rng: &mut Rng, expression: &Expression, group: bool, out: &mut String) {
    if group {
        out.push('(');
        print(rng, expression, out);
        out.push(')');
    } else {
        print(rng, expression, out);
    }
}

fn print_test(rng: &mut Rng, test: &Test, out: &mut String) {
    let words = |rng: &mut Rng, words: &[&str], out: &mut String| {
        for word in words {
            let word = keyword(rng, word);
            write!(out, " {word}").unwrap();
        }
    };
    match test {
        Test::Operator(operator, value) => match symbol(*operator) {
            Some(symbol) => {
                out.push_str(spaces(rng));
                out.push_str(symbol);
                out.push_str(spaces(rng));
                print_value(rng, value, out);
            }
            None if operator.requires_value() => {
                write!(out, " {} ", keyword(rng, operator.as_str())).unwrap();
                print_value(rng, value, out);
            }
            None => match (operator, rng.chance(1, 2)) {
                (FilterOperator::IsEmpty, true) => words(rng, &["is", "empty"], out),
                (FilterOperator::IsNotEmpty, true) => words(rng, &["is", "not", "empty"], out),
                _ => words(rng, &[operator.as_str()], out),
            },
        },
        Test::In(values) => {
            words(rng, &["in"], out);
            out.push(' ');
            print_list(rng, values, out);
        }
        Test::NotIn(values) => {
            words(rng, &["not", "in"], out);
            out.push(' ');
            print_list(rng, values, out);
        }
        Test::Exists => words(rng, &["exists"], out),
        Test::NotExists => words(rng, &["not", "exists"], out),
        Test::IsNull => words(rng, &["is", "null"], out),
        Test::IsNotNull => words(rng, &["is", "not", "null"], out),
    }
}

/// The documented meaning of a filter, evaluated on the generated tree.
fn reference(expression: &Expression, record: &Record) -> bool {
    match expression {
        Expression::And(children) => children.iter().all(|child| reference(child, record)),
        Expression::Or(children) => children.iter().any(|child| reference(child, record)),
        Expression::Not(child) => !reference(child, record),
        Expression::Predicate(field, test) => {
            let pseudo;
            let current = match field {
                Field::Attribute(path) => {
                    lookup(&record.attributes, &path.split('.').collect::<Vec<_>>())
                }
                Field::Id => {
                    pseudo = Value::String(record.id.clone());
                    Some(&pseudo)
                }
                Field::Collection => {
                    pseudo = Value::String(record.collection.clone());
                    Some(&pseudo)
                }
                Field::Path => {
                    pseudo = Value::String(record.path.to_string_lossy().into_owned());
                    Some(&pseudo)
                }
            };
            match test {
                Test::Operator(operator, value) => reference_operator(*operator, current, value),
                Test::In(values) => current.is_some_and(|current| values.contains(current)),
                Test::NotIn(values) => current.is_some_and(|current| !values.contains(current)),
                Test::Exists => current.is_some(),
                Test::NotExists => current.is_none(),
                Test::IsNull => current == Some(&Value::Null),
                Test::IsNotNull => current.is_some_and(|current| current != &Value::Null),
            }
        }
    }
}

/// Every generated filter, printed with arbitrary keyword case, spacing,
/// quoting, and redundant parentheses, parses, and selects exactly the records
/// the reference evaluator selects.
#[test]
fn printed_filters_parse_and_agree_with_a_reference_evaluator() {
    for mut case in cases(
        "printed_filters_parse_and_agree_with_a_reference_evaluator",
        1000,
    ) {
        let rng = &mut case.rng;
        let tree = expression(rng, 3);
        let mut text = String::new();
        print(rng, &tree, &mut text);
        let filter = Filter::from_str(&text)
            .unwrap_or_else(|error| panic!("{text:?} was refused: {error:#}\n{tree:?}"));
        assert_eq!(filter.as_str(), text);
        for index in 0..10 {
            let record = small_record(rng, &format!("r{index}"));
            assert_eq!(
                filter.matches(&record),
                reference(&tree, &record),
                "{text:?} against {} {:?}",
                record.reference(),
                record.attributes
            );
        }
    }
}

/// `--filter` and `--where-expr` share their operators, so one written both
/// ways selects the same records.
#[test]
fn a_predicate_means_the_same_in_filter_and_where_expressions() {
    for mut case in cases(
        "a_predicate_means_the_same_in_filter_and_where_expressions",
        1000,
    ) {
        let rng = &mut case.rng;
        let path = filter_path(rng);
        let operator = *rng.pick(OPERATORS);
        let value = small_scalar(rng);
        let raw = if operator.requires_value() {
            match inline_yaml(&value) {
                Some(raw) => raw,
                None => continue,
            }
        } else {
            String::new()
        };
        let written = match symbol(operator) {
            Some(symbol) => format!("{path}{symbol}{raw}"),
            None => format!("{path} {operator} {raw}"),
        };
        let expression = FilterExpression::from_str(&written).unwrap();
        let mut text = String::new();
        print(
            rng,
            &Expression::Predicate(
                Field::Attribute(path.clone()),
                Test::Operator(operator, value),
            ),
            &mut text,
        );
        let filter = Filter::from_str(&text).unwrap();
        for index in 0..8 {
            let record = small_record(rng, &format!("r{index}"));
            assert_eq!(
                filter.matches(&record),
                expression.matches(&record.attributes),
                "{text:?} against {:?}",
                record.attributes
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Sort keys and ordering
// ---------------------------------------------------------------------------

/// Parts a sort field is made of, including every spelling that looks like a
/// direction.
const SORT_PARTS: &[&str] = &[
    "stage",
    "value",
    "owner.name",
    "og",
    "title",
    ":",
    "asc",
    "desc",
    "ASC",
    "Desc",
    " desc",
    "asc ",
    "é",
    "🙂",
    "$id",
    "a b",
    "-",
    "x-",
];

fn sort_field(rng: &mut Rng) -> Option<String> {
    let field: String = (0..rng.between(1, 3))
        .map(|_| *rng.pick(SORT_PARTS))
        .collect();
    // What a field cannot be, by the documented rules: empty, surrounded by
    // whitespace, holding a comma, or starting with '-'.
    (field.trim() == field && !field.is_empty() && !field.starts_with('-')).then_some(field)
}

/// A key's written form parses back to the key, alone and in a comma list.
#[test]
fn sort_keys_round_trip_through_their_written_form() {
    for mut case in cases("sort_keys_round_trip_through_their_written_form", 2000) {
        let rng = &mut case.rng;
        let mut keys: Vec<SortKey> = Vec::new();
        for _ in 0..rng.between(1, MAX_SORT_KEYS) {
            let Some(field) = sort_field(rng) else {
                continue;
            };
            if keys.iter().any(|key| key.field == field) {
                continue;
            }
            let direction = *rng.pick(&[SortDirection::Asc, SortDirection::Desc]);
            let key = SortKey::new(field, direction);
            assert_eq!(key.to_string().parse::<SortKey>().unwrap(), key, "{key}");
            keys.push(key);
        }
        if keys.is_empty() {
            continue;
        }
        let written: Vec<String> = keys.iter().map(ToString::to_string).collect();
        let joined = written.join(&format!("{},{}", spaces(rng), spaces(rng)));
        assert_eq!(
            parse_sort_keys(&[joined.as_str()], None, "direction").unwrap(),
            keys,
            "{joined:?}"
        );
        assert_eq!(parse_sort_keys(&written, None, "direction").unwrap(), keys);

        // One key too many, or one field twice, is refused.
        let mut too_many = written.clone();
        while too_many.len() <= MAX_SORT_KEYS {
            too_many.push(format!("extra{}", too_many.len()));
        }
        assert!(
            valid_or_invalid("too many", parse_sort_keys(&too_many, None, "direction")).is_none(),
            "{too_many:?} was accepted"
        );
        let mut repeated = written.clone();
        repeated.push(written[0].clone());
        assert!(
            valid_or_invalid("repeated", parse_sort_keys(&repeated, None, "direction")).is_none(),
            "{repeated:?} was accepted"
        );
    }
}

/// Arbitrary sort text is a key list or a classified refusal, with or without
/// the one-key direction.
#[test]
fn sort_key_lists_parse_or_are_refused_with_a_classification() {
    for mut case in cases(
        "sort_key_lists_parse_or_are_refused_with_a_classification",
        2000,
    ) {
        let rng = &mut case.rng;
        let lists: Vec<String> = (0..rng.between(0, 3)).map(|_| token_soup(rng)).collect();
        let direction = *rng.pick(&[None, Some(SortDirection::Asc), Some(SortDirection::Desc)]);
        let input = format!("{lists:?} {direction:?}");
        if let Some(keys) =
            valid_or_invalid(&input, parse_sort_keys(&lists, direction, "direction"))
        {
            assert!(keys.len() <= MAX_SORT_KEYS);
            let mut records = vec![record("deals", "a", Mapping::new())];
            valid_or_invalid(&input, sort_records(&mut records, &keys));
        }
    }
}

/// Values where an ordering is most likely to go wrong: NaN beside ordinary
/// numbers, negative and positive zero, infinities, and containers of them.
fn comparison_edge(rng: &mut Rng) -> Value {
    let number = |float: f64| Value::Number(float.into());
    match rng.below(12) {
        0 => number(f64::NAN),
        1 => Value::Sequence(vec![number(f64::NAN)]),
        2 => number(-0.0),
        3 => Value::Number(0.into()),
        4 => number(f64::INFINITY),
        5 => number(f64::NEG_INFINITY),
        6 => Value::Number((rng.below(3) as i64).into()),
        7 => Value::Sequence(vec![Value::Number((rng.below(3) as i64).into())]),
        8 => Value::Sequence(Vec::new()),
        9 => Value::Null,
        10 => Value::String(String::new()),
        _ => small_value(rng),
    }
}

/// `compare_yaml_values` is a total order: reflexive, antisymmetric, and
/// transitive over values of every type, NaN included. `slice::sort_by` may
/// panic when handed anything less.
#[test]
fn yaml_values_compare_as_a_total_order() {
    for mut case in cases("yaml_values_compare_as_a_total_order", 3000) {
        let rng = &mut case.rng;
        let values: Vec<Value> = (0..3)
            .map(|_| match rng.below(3) {
                0 => generate::value(rng, 2),
                _ => comparison_edge(rng),
            })
            .collect();
        for a in &values {
            assert_eq!(compare_yaml_values(a, a), Ordering::Equal, "{a:?}");
            for b in &values {
                assert_eq!(
                    compare_yaml_values(a, b),
                    compare_yaml_values(b, a).reverse(),
                    "{a:?} {b:?}"
                );
                for c in &values {
                    let (ab, bc, ac) = (
                        compare_yaml_values(a, b),
                        compare_yaml_values(b, c),
                        compare_yaml_values(a, c),
                    );
                    if ab.is_le() && bc.is_le() {
                        assert!(ac.is_le(), "{a:?} <= {b:?} <= {c:?} but not {a:?} <= {c:?}");
                    }
                    if ab.is_eq() && bc.is_eq() {
                        assert!(ac.is_eq(), "{a:?} == {b:?} == {c:?} but not {a:?} == {c:?}");
                    }
                }
            }
        }
    }
}

/// The documented order of two records under `keys`: key by key, present
/// values in the key's direction, a missing value after every present one in
/// either direction, then collection and ID ascending.
fn reference_order(left: &Record, right: &Record, keys: &[SortKey]) -> Ordering {
    for key in keys {
        let value = |record: &Record| -> Option<Value> {
            match key.field.as_str() {
                "$id" => Some(Value::String(record.id.clone())),
                "$collection" => Some(Value::String(record.collection.clone())),
                "$path" => Some(Value::String(record.path.to_string_lossy().into_owned())),
                field => lookup(&record.attributes, &field.split('.').collect::<Vec<_>>()).cloned(),
            }
        };
        let ordering = match (value(left), value(right)) {
            (Some(left), Some(right)) => {
                let ordering = compare_yaml_values(&left, &right);
                match key.direction {
                    SortDirection::Asc => ordering,
                    SortDirection::Desc => ordering.reverse(),
                }
            }
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        if ordering.is_ne() {
            return ordering;
        }
    }
    (&left.collection, &left.id).cmp(&(&right.collection, &right.id))
}

fn identities(records: &[Record]) -> Vec<String> {
    records.iter().map(Record::reference).collect()
}

/// Sorting is a total order with the collection and ID tie-break: every
/// arrangement of the same records sorts to one order, and it is the order
/// the documented rules give.
#[test]
fn sorting_is_one_total_order_whatever_the_input_order() {
    for mut case in cases("sorting_is_one_total_order_whatever_the_input_order", 500) {
        let rng = &mut case.rng;
        let mut records: Vec<Record> = (0..rng.between(0, 40))
            .map(|_| {
                let id = format!("r{:02}", rng.below(60));
                small_record(rng, &id)
            })
            .collect();
        records.sort_by_key(Record::reference);
        records.dedup_by(|left, right| left.reference() == right.reference());
        let fields = [
            "stage",
            "value",
            "tags",
            "owner.name",
            "notes",
            "flag",
            "$id",
            "$collection",
            "$path",
        ];
        let mut keys: Vec<SortKey> = Vec::new();
        for _ in 0..rng.between(1, MAX_SORT_KEYS) {
            let field = *rng.pick(&fields);
            if !keys.iter().any(|key| key.field == field) {
                let direction = *rng.pick(&[SortDirection::Asc, SortDirection::Desc]);
                keys.push(SortKey::new(field, direction));
            }
        }

        rng.shuffle(&mut records);
        let mut sorted = records.clone();
        sort_records(&mut sorted, &keys).unwrap();
        for pair in sorted.windows(2) {
            assert_eq!(
                reference_order(&pair[0], &pair[1], &keys),
                Ordering::Less,
                "{} before {} under {keys:?}",
                pair[0].reference(),
                pair[1].reference()
            );
        }
        rng.shuffle(&mut records);
        sort_records(&mut records, &keys).unwrap();
        assert_eq!(identities(&records), identities(&sorted), "{keys:?}");
    }
}

/// Found by `sorting_is_one_total_order_whatever_the_input_order` and
/// `yaml_values_compare_as_a_total_order`. NaN compared equal to
/// every number, so with the ID tie-break these three records formed a cycle:
/// the result depended on the input order, and two hundred such records
/// panicked the sort (`user-provided comparison function does not correctly
/// implement a total order`) — in `cr serve`, a `500` for any sorted listing.
#[test]
fn records_valued_1_2_and_nan_sort_the_same_whatever_their_input_order() {
    let value = |id: &str, value: &str| {
        record(
            "deals",
            id,
            yaml_serde::from_str(&format!("value: {value}\n")).unwrap(),
        )
    };
    let keys = [SortKey::new("value", SortDirection::Asc)];
    let mut forward = vec![value("z", "1"), value("a", "2"), value("m", ".nan")];
    let mut backward: Vec<Record> = forward.iter().rev().cloned().collect();
    sort_records(&mut forward, &keys).unwrap();
    sort_records(&mut backward, &keys).unwrap();
    assert_eq!(identities(&forward), ["deals/z", "deals/a", "deals/m"]);
    assert_eq!(identities(&backward), identities(&forward));

    let mut many: Vec<Record> = (0..200)
        .map(|index| {
            let number = if index % 3 == 0 {
                ".nan".to_owned()
            } else {
                ((index * 31) % 17).to_string()
            };
            value(&format!("{:03}", (index * 7919) % 1000), &number)
        })
        .collect();
    sort_records(&mut many, &keys).unwrap();
    assert!(many[..133].iter().all(|record| {
        record.attributes["value"]
            .as_f64()
            .is_some_and(|value| !value.is_nan())
    }));
}

// ---------------------------------------------------------------------------
// --select
// ---------------------------------------------------------------------------

const SELECTORS: &[&str] = &[
    "$id",
    "$collection",
    "$path",
    "$version",
    "$body",
    "stage",
    "value",
    "owner.name",
    "notes",
    "tags",
    "missing",
    "é",
    "a b",
];

/// A projection's written form parses back to the same selectors, and lists
/// combine in order without repeats.
#[test]
fn projections_round_trip_through_their_written_form() {
    for mut case in cases("projections_round_trip_through_their_written_form", 1000) {
        let rng = &mut case.rng;
        let lists: Vec<Vec<&str>> = (0..rng.between(1, 3))
            .map(|_| {
                (0..rng.between(1, 4))
                    .map(|_| *rng.pick(SELECTORS))
                    .collect()
            })
            .collect();
        let written: Vec<String> = lists
            .iter()
            .map(|list| list.join(&format!("{},{}", spaces(rng), spaces(rng))))
            .collect();
        let projection = Projection::from_lists(&written).unwrap().unwrap();
        let mut expected: Vec<&str> = Vec::new();
        for name in lists.iter().flatten() {
            if !expected.contains(name) {
                expected.push(name);
            }
        }
        assert_eq!(projection.names().collect::<Vec<_>>(), expected);
        assert_eq!(projection.to_string(), expected.join(","));
        assert_eq!(
            projection.to_string().parse::<Projection>().unwrap(),
            projection
        );
    }
}

/// Arbitrary selector text is a projection or a classified refusal.
#[test]
fn projections_parse_or_are_refused_with_a_classification() {
    for mut case in cases(
        "projections_parse_or_are_refused_with_a_classification",
        2000,
    ) {
        let input = token_soup(&mut case.rng);
        valid_or_invalid(&input, Projection::from_str(&input));
    }
}

fn unescape(cell: &str) -> String {
    let mut text = String::new();
    let mut characters = cell.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            text.push(character);
            continue;
        }
        match characters.next() {
            Some('\\') => text.push('\\'),
            Some('t') => text.push('\t'),
            Some('r') => text.push('\r'),
            Some('n') => text.push('\n'),
            other => panic!("unexpected escape {other:?} in {cell:?}"),
        }
    }
    text
}

/// A projected row is one line with one cell per selector, and each cell
/// unescapes to the value it shows.
#[test]
fn projected_rows_are_one_line_and_unescape_to_their_values() {
    for mut case in cases(
        "projected_rows_are_one_line_and_unescape_to_their_values",
        1000,
    ) {
        let rng = &mut case.rng;
        let mut attributes = Mapping::new();
        for field in ["stage", "notes"] {
            if rng.chance(3, 4) {
                attributes.insert(field.into(), Value::String(generate::string(rng)));
            }
        }
        if rng.chance(1, 2) {
            attributes.insert("value".into(), small_value(rng));
        }
        let mut subject = record("deals", "one", attributes);
        subject.body = generate::body(rng);
        let names = ["$id", "stage", "notes", "value", "$body", "missing"];
        let projection: Projection = names.join(",").parse().unwrap();
        let Ok(row) = projection.row(&subject) else {
            continue;
        };
        assert!(!row.contains(['\n', '\r']), "{row:?}");
        let cells: Vec<&str> = row.split('\t').collect();
        assert_eq!(cells.len(), names.len(), "{row:?}");
        let object = projection.object(&subject).unwrap();
        for (name, cell) in names.iter().zip(cells) {
            let expected = match object.get(*name) {
                None => String::new(),
                Some(serde_json::Value::String(text)) => text.clone(),
                Some(other) => other.to_string(),
            };
            assert_eq!(unescape(cell), expected, "{name} in {row:?}");
        }
    }
}
