//! Generators for the values records are made of: strings that are awkward in
//! YAML, Markdown, URLs, or all three, YAML values of every type, and bodies.
//!
//! Like `rng.rs`, this is compiled into the library's unit tests as well as the
//! integration tests, so it depends on nothing but the generator and
//! `yaml_serde`, which both builds already have.

#![allow(dead_code)]

use yaml_serde::{Mapping, Number, Value};

use super::rng::Rng;

/// Strings chosen because some layer has a reason to treat them specially: a
/// YAML indicator, a document marker, a value YAML 1.1 would retype, a line
/// ending, invisible or non-BMP Unicode, or path and query punctuation.
pub const TRICKY_STRINGS: &[&str] = &[
    "",
    " ",
    "  ",
    "---",
    "--- ",
    " ---",
    "...",
    ": ",
    "a: b",
    "a:b",
    "#",
    "# not a comment",
    "a #b",
    " leading",
    "trailing ",
    "\ttab",
    "line\nbreak",
    "two\n\nlines\n",
    "\n",
    "\r\n",
    "carriage\rreturn",
    "null",
    "Null",
    "NULL",
    "~",
    "true",
    "True",
    "false",
    "yes",
    "no",
    "on",
    "off",
    "y",
    "n",
    "0",
    "1",
    "-1",
    "01",
    "+1",
    "0x1F",
    "0o17",
    "1e3",
    "1_000",
    "1.5",
    ".inf",
    "-.inf",
    ".nan",
    "NaN",
    "12:30:00",
    "2027-01-01",
    "2027-01-01T00:00:00Z",
    "'",
    "''",
    "\"",
    "\\",
    "\\n",
    "- item",
    "-",
    "? key",
    "?",
    "!tag",
    "!!str",
    "&anchor",
    "*alias",
    "<<",
    "|",
    ">",
    "%YAML 1.2",
    "@",
    "`",
    "{",
    "}",
    "[",
    "]",
    "[a, b]",
    "{a: b}",
    ",",
    "=",
    "a=b",
    "!=",
    "..",
    ".",
    "a.b",
    "/",
    "../..",
    "%2e%2e",
    "%00",
    "&",
    "+",
    "é",
    "e\u{301}",
    "日本語",
    "🙂",
    "\u{0}",
    "\u{7}",
    "\u{1b}[31m",
    "\u{7f}",
    "\u{85}",
    "\u{a0}",
    "\u{200b}",
    "\u{2028}",
    "\u{2029}",
    "\u{feff}",
    "\u{fffd}",
    "\u{10ffff}",
];

/// Single characters to scatter into generated text.
pub const CHARACTERS: &[char] = &[
    'a',
    'b',
    'z',
    'A',
    'Z',
    '0',
    '9',
    ' ',
    ' ',
    '\t',
    '\n',
    '\r',
    '-',
    '_',
    '.',
    ':',
    '#',
    '"',
    '\'',
    '\\',
    '/',
    '[',
    ']',
    '{',
    '}',
    '(',
    ')',
    ',',
    '=',
    '!',
    '<',
    '>',
    '&',
    '*',
    '?',
    '|',
    '%',
    '@',
    '`',
    '~',
    '+',
    '$',
    ';',
    '\u{0}',
    '\u{1}',
    '\u{1b}',
    '\u{7f}',
    '\u{85}',
    '\u{a0}',
    'é',
    'ß',
    'Ω',
    '日',
    '\u{2028}',
    '\u{feff}',
    '\u{fffd}',
    '🙂',
    '\u{10ffff}',
];

/// Plain words, so generated data also contains the ordinary case.
pub const WORDS: &[&str] = &[
    "alpha", "beta", "gamma", "open", "won", "lost", "stage", "value", "owner", "notes",
];

/// Up to `length` characters drawn from [`CHARACTERS`].
pub fn noise(rng: &mut Rng, length: usize) -> String {
    (0..rng.below(length + 1))
        .map(|_| *rng.pick(CHARACTERS))
        .collect()
}

/// A string that is often awkward and sometimes ordinary.
pub fn string(rng: &mut Rng) -> String {
    match rng.below(4) {
        0 => rng.pick(TRICKY_STRINGS).to_string(),
        1 => rng.pick(WORDS).to_string(),
        2 => noise(rng, 12),
        _ => {
            let mut text = String::new();
            for _ in 0..rng.between(1, 4) {
                match rng.below(3) {
                    0 => text.push_str(rng.pick::<&str>(TRICKY_STRINGS)),
                    1 => text.push_str(rng.pick::<&str>(WORDS)),
                    _ => text.push(*rng.pick(CHARACTERS)),
                }
            }
            text
        }
    }
}

/// A YAML number: integers at and beyond the edges of `i64`, and floats that
/// are awkward to print (subnormal, huge, negative zero, infinite, NaN).
pub fn number(rng: &mut Rng) -> Number {
    match rng.below(6) {
        0 => Number::from(*rng.pick(&[0i64, 1, -1, 42, i64::MIN, i64::MAX])),
        1 => Number::from(rng.next() as i64),
        2 => Number::from(*rng.pick(&[i64::MAX as u64 + 1, u64::MAX])),
        3 => Number::from(*rng.pick(&[
            0.5,
            -0.0,
            1.0,
            0.1,
            1e300,
            1e-300,
            f64::MIN_POSITIVE,
            5e-324,
            f64::MAX,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
        ])),
        4 => {
            let float = f64::from_bits(rng.next());
            Number::from(if float.is_finite() { float } else { 2.5 })
        }
        _ => Number::from(rng.below(1000) as i64 - 500),
    }
}

pub fn scalar(rng: &mut Rng) -> Value {
    match rng.below(6) {
        0 => Value::Null,
        1 => Value::Bool(rng.chance(1, 2)),
        2 => Value::Number(number(rng)),
        _ => Value::String(string(rng)),
    }
}

/// Any YAML value with string keys, nested at most `depth` levels.
pub fn value(rng: &mut Rng, depth: usize) -> Value {
    if depth == 0 {
        return scalar(rng);
    }
    match rng.below(5) {
        0 => Value::Mapping(mapping(rng, depth - 1)),
        1 => Value::Sequence((0..rng.below(4)).map(|_| value(rng, depth - 1)).collect()),
        _ => scalar(rng),
    }
}

/// A mapping with string keys, which is what a record's front matter is.
pub fn mapping(rng: &mut Rng, depth: usize) -> Mapping {
    let mut mapping = Mapping::new();
    for _ in 0..rng.below(5) {
        mapping.insert(Value::String(string(rng)), value(rng, depth));
    }
    mapping
}

/// Fragments a Markdown body is built from, including lines that look like a
/// front matter delimiter, which only the first two delimiter lines may be.
pub const BODY_FRAGMENTS: &[&str] = &[
    "",
    "\n",
    "\r\n",
    "---\n",
    "---",
    "---\r\n",
    "--- \n",
    "...\n",
    "# Title\n",
    "Some text.",
    "  indented\n",
    "- item\n",
    "key: value\n",
    "```yaml\na: b\n```\n",
    "<script>alert(1)</script>",
    "🙂",
    "\u{feff}",
    "\u{0}",
    "\t",
];

pub fn body(rng: &mut Rng) -> String {
    let mut body = String::new();
    for _ in 0..rng.below(6) {
        if rng.chance(1, 4) {
            body.push_str(&noise(rng, 8));
        } else {
            body.push_str(rng.pick::<&str>(BODY_FRAGMENTS));
        }
    }
    body
}
