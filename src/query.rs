//! The `--filter` expression language.
//!
//! One grammar for the CLI and HTTP, parsed here and evaluated here, so a
//! filter cannot mean one thing in a terminal and another in a request:
//!
//! ```text
//! filter     := or
//! or         := and ( OR and )*
//! and        := not ( AND not )*
//! not        := NOT not | primary
//! primary    := '(' or ')' | predicate
//! predicate  := field test
//! test       := ( = | != | > | >= | < | <= ) value
//!             | contains value | not-contains value
//!             | starts-with value | ends-with value
//!             | in list | not in list
//!             | exists | not exists
//!             | is null | is not null
//!             | is-empty | is-not-empty
//! value      := "double" | 'single' | bare-word | list
//! list       := '[' ( value ( ',' value )* )? ']'
//! ```
//!
//! `NOT` binds tighter than `AND`, which binds tighter than `OR`. Keywords are
//! case-insensitive. A field is a dotted front matter path or one of `$id`,
//! `$collection`, and `$path`. A quoted value is always a string; a bare word
//! is read as a YAML scalar, exactly as `--where` reads one, so `10` is a
//! number, `true` a boolean, `null` null, and `open` a string.
//!
//! Missing, null, empty, and absent are distinct. `exists` asks whether a
//! field is present at all, `is null` whether it is present and null, `= ""`
//! and `= []` whether it is exactly empty, and `is-empty` whether it is any of
//! those. Every other test is false for a missing field, so `stage != won`
//! skips records without a stage and `NOT stage = won` includes them.

use std::{fmt, str::FromStr};

use anyhow::Result;
use yaml_serde::Value;

use crate::{
    database::Record,
    error::invalid,
    value::{FilterOperator, get_path, operator_matches, parse_filter_value, parse_path},
};

/// A parsed `--filter` expression.
#[derive(Clone, Debug, PartialEq)]
pub struct Filter {
    root: Node,
    source: String,
}

#[derive(Clone, Debug, PartialEq)]
enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    Predicate(Field, Test),
}

#[derive(Clone, Debug, PartialEq)]
enum Field {
    Attribute(Vec<String>),
    Id,
    Collection,
    Path,
}

#[derive(Clone, Debug, PartialEq)]
enum Test {
    Operator(FilterOperator, Option<Value>),
    In(Vec<Value>),
    NotIn(Vec<Value>),
    Exists,
    NotExists,
    IsNull,
    IsNotNull,
}

impl Filter {
    /// Whether `record` satisfies the filter.
    pub fn matches(&self, record: &Record) -> bool {
        self.root.matches(record)
    }

    /// The expression as it was written.
    pub fn as_str(&self) -> &str {
        &self.source
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.source)
    }
}

impl FromStr for Filter {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let tokens = tokenize(input)?;
        if tokens.is_empty() {
            return Err(invalid("a filter cannot be empty"));
        }
        let mut parser = Parser {
            tokens: &tokens,
            position: 0,
            input_length: input.chars().count(),
        };
        let root = parser.or()?;
        if let Some(token) = parser.peek() {
            return Err(parser.error_at(
                token,
                format!(
                    "unexpected {}; expected AND, OR, or the end of the filter",
                    token.kind
                ),
            ));
        }
        Ok(Self {
            root,
            source: input.to_owned(),
        })
    }
}

impl Node {
    fn matches(&self, record: &Record) -> bool {
        match self {
            Self::And(nodes) => nodes.iter().all(|node| node.matches(record)),
            Self::Or(nodes) => nodes.iter().any(|node| node.matches(record)),
            Self::Not(node) => !node.matches(record),
            Self::Predicate(field, test) => {
                let pseudo;
                let current = match field {
                    Field::Attribute(path) => get_path(&record.attributes, path),
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
                test.matches(current)
            }
        }
    }
}

impl Test {
    fn matches(&self, current: Option<&Value>) -> bool {
        match self {
            Self::Operator(operator, expected) => {
                operator_matches(*operator, current, expected.as_ref())
            }
            Self::In(values) => current.is_some_and(|current| values.contains(current)),
            Self::NotIn(values) => current.is_some_and(|current| !values.contains(current)),
            Self::Exists => current.is_some(),
            Self::NotExists => current.is_none(),
            Self::IsNull => current == Some(&Value::Null),
            Self::IsNotNull => current.is_some_and(|current| current != &Value::Null),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum TokenKind {
    Open,
    Close,
    OpenList,
    CloseList,
    Comma,
    Comparison(FilterOperator),
    Word(String),
    Quoted(String),
}

impl fmt::Display for TokenKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => formatter.write_str("'('"),
            Self::Close => formatter.write_str("')'"),
            Self::OpenList => formatter.write_str("'['"),
            Self::CloseList => formatter.write_str("']'"),
            Self::Comma => formatter.write_str("','"),
            Self::Comparison(operator) => write!(formatter, "'{}'", comparison_symbol(*operator)),
            Self::Word(word) => write!(formatter, "'{word}'"),
            Self::Quoted(text) => write!(formatter, "the string {text:?}"),
        }
    }
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    /// One-based character column where the token starts.
    column: usize,
}

fn comparison_symbol(operator: FilterOperator) -> &'static str {
    match operator {
        FilterOperator::Equal => "=",
        FilterOperator::NotEqual => "!=",
        FilterOperator::GreaterThan => ">",
        FilterOperator::GreaterThanOrEqual => ">=",
        FilterOperator::LessThan => "<",
        FilterOperator::LessThanOrEqual => "<=",
        other => other.as_str(),
    }
}

/// Characters that end a bare word.
fn is_delimiter(character: char) -> bool {
    character.is_whitespace() || "()[],=!<>\"'".contains(character)
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let characters: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        let column = index + 1;
        if character.is_whitespace() {
            index += 1;
            continue;
        }
        let single = match character {
            '(' => Some(TokenKind::Open),
            ')' => Some(TokenKind::Close),
            '[' => Some(TokenKind::OpenList),
            ']' => Some(TokenKind::CloseList),
            ',' => Some(TokenKind::Comma),
            _ => None,
        };
        if let Some(kind) = single {
            tokens.push(Token { kind, column });
            index += 1;
            continue;
        }
        if "=!<>".contains(character) {
            let next = characters.get(index + 1).copied();
            let (operator, width) = match (character, next) {
                ('!', Some('=')) => (FilterOperator::NotEqual, 2),
                ('>', Some('=')) => (FilterOperator::GreaterThanOrEqual, 2),
                ('<', Some('=')) => (FilterOperator::LessThanOrEqual, 2),
                ('=', _) => (FilterOperator::Equal, 1),
                ('>', _) => (FilterOperator::GreaterThan, 1),
                ('<', _) => (FilterOperator::LessThan, 1),
                _ => {
                    return Err(invalid(format!(
                        "unexpected '!' at column {column}; use '!=' or NOT"
                    )));
                }
            };
            tokens.push(Token {
                kind: TokenKind::Comparison(operator),
                column,
            });
            index += width;
            continue;
        }
        if character == '"' || character == '\'' {
            let mut text = String::new();
            index += 1;
            loop {
                match characters.get(index) {
                    None => {
                        return Err(invalid(format!(
                            "the string starting at column {column} is never closed"
                        )));
                    }
                    Some('\\') => match characters.get(index + 1) {
                        Some(escaped @ ('\\' | '"' | '\'')) => {
                            text.push(*escaped);
                            index += 2;
                        }
                        _ => {
                            return Err(invalid(format!(
                                "unsupported escape at column {}; only \\\\, \\\", and \\' are escapes",
                                index + 1
                            )));
                        }
                    },
                    Some(&closing) if closing == character => {
                        index += 1;
                        break;
                    }
                    Some(other) => {
                        text.push(*other);
                        index += 1;
                    }
                }
            }
            tokens.push(Token {
                kind: TokenKind::Quoted(text),
                column,
            });
            continue;
        }
        let start = index;
        while index < characters.len() && !is_delimiter(characters[index]) {
            index += 1;
        }
        tokens.push(Token {
            kind: TokenKind::Word(characters[start..index].iter().collect()),
            column,
        });
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    position: usize,
    input_length: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.position);
        self.position += usize::from(token.is_some());
        token
    }

    /// Whether the next token is the keyword `word`, consuming it if so.
    fn keyword(&mut self, word: &str) -> bool {
        let matched = matches!(
            self.peek(),
            Some(Token { kind: TokenKind::Word(candidate), .. }) if candidate.eq_ignore_ascii_case(word)
        );
        self.position += usize::from(matched);
        matched
    }

    fn error_at(&self, token: &Token, message: String) -> anyhow::Error {
        invalid(format!("{message} at column {}", token.column))
    }

    fn error_at_end(&self, message: String) -> anyhow::Error {
        invalid(format!(
            "{message} at the end of the filter (column {})",
            self.input_length + 1
        ))
    }

    fn or(&mut self) -> Result<Node> {
        let mut nodes = vec![self.and()?];
        while self.keyword("or") {
            nodes.push(self.and()?);
        }
        Ok(if nodes.len() == 1 {
            nodes.remove(0)
        } else {
            Node::Or(nodes)
        })
    }

    fn and(&mut self) -> Result<Node> {
        let mut nodes = vec![self.not()?];
        while self.keyword("and") {
            nodes.push(self.not()?);
        }
        Ok(if nodes.len() == 1 {
            nodes.remove(0)
        } else {
            Node::And(nodes)
        })
    }

    fn not(&mut self) -> Result<Node> {
        if self.keyword("not") {
            return Ok(Node::Not(Box::new(self.not()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Node> {
        let Some(token) = self.next().cloned() else {
            return Err(self.error_at_end("expected a field, NOT, or '('".to_owned()));
        };
        match token.kind.clone() {
            TokenKind::Open => {
                let node = self.or()?;
                match self.next() {
                    Some(Token {
                        kind: TokenKind::Close,
                        ..
                    }) => Ok(node),
                    Some(other) => {
                        let other = other.clone();
                        Err(self.error_at(
                            &other,
                            format!(
                                "expected ')' to close the '(' at column {}, found {}",
                                token.column, other.kind
                            ),
                        ))
                    }
                    None => Err(self.error_at_end(format!(
                        "expected ')' to close the '(' at column {}",
                        token.column
                    ))),
                }
            }
            TokenKind::Word(word) => {
                let field =
                    parse_field(&word).map_err(|error| self.error_at(&token, error.to_string()))?;
                let test = self.test(&word)?;
                Ok(Node::Predicate(field, test))
            }
            other => Err(self.error_at(
                &token,
                format!("unexpected {other}; expected a field, NOT, or '('"),
            )),
        }
    }

    fn test(&mut self, field: &str) -> Result<Test> {
        let expected = format!(
            "expected a comparison after the field '{field}', such as =, contains, in, exists, or is null"
        );
        let Some(token) = self.next().cloned() else {
            return Err(self.error_at_end(expected));
        };
        let word = match &token.kind {
            TokenKind::Comparison(operator) => {
                let value = self.value(&token)?;
                return Ok(Test::Operator(*operator, Some(value)));
            }
            TokenKind::Word(word) => word.to_ascii_lowercase(),
            _ => return Err(self.error_at(&token, expected)),
        };
        let operator_with_value = match word.as_str() {
            "contains" => Some(FilterOperator::Contains),
            "not-contains" => Some(FilterOperator::NotContains),
            "starts-with" => Some(FilterOperator::StartsWith),
            "ends-with" => Some(FilterOperator::EndsWith),
            _ => None,
        };
        if let Some(operator) = operator_with_value {
            let value = self.value(&token)?;
            return Ok(Test::Operator(operator, Some(value)));
        }
        match word.as_str() {
            "is-empty" => Ok(Test::Operator(FilterOperator::IsEmpty, None)),
            "is-not-empty" => Ok(Test::Operator(FilterOperator::IsNotEmpty, None)),
            "exists" => Ok(Test::Exists),
            "in" => Ok(Test::In(self.list(&token)?)),
            "not" => {
                if self.keyword("in") {
                    Ok(Test::NotIn(self.list(&token)?))
                } else if self.keyword("exists") {
                    Ok(Test::NotExists)
                } else {
                    Err(self.error_after(&token, "expected 'in' or 'exists' after 'not'"))
                }
            }
            "is" => {
                let negated = self.keyword("not");
                if self.keyword("null") {
                    Ok(if negated {
                        Test::IsNotNull
                    } else {
                        Test::IsNull
                    })
                } else if self.keyword("empty") {
                    Ok(Test::Operator(
                        if negated {
                            FilterOperator::IsNotEmpty
                        } else {
                            FilterOperator::IsEmpty
                        },
                        None,
                    ))
                } else {
                    Err(self.error_after(&token, "expected 'null' or 'empty' after 'is'"))
                }
            }
            _ => Err(self.error_at(&token, expected)),
        }
    }

    /// An error about the token after `previous`, or the end of the filter.
    fn error_after(&self, previous: &Token, message: &str) -> anyhow::Error {
        match self.peek() {
            Some(token) => self.error_at(token, format!("{message}, found {}", token.kind)),
            None => {
                let _ = previous;
                self.error_at_end(message.to_owned())
            }
        }
    }

    fn value(&mut self, operator: &Token) -> Result<Value> {
        let Some(token) = self.next().cloned() else {
            return Err(self.error_at_end(format!("expected a value after {}", operator.kind)));
        };
        let value = match token.kind.clone() {
            TokenKind::Quoted(text) => Value::String(text),
            TokenKind::Word(word) => parse_filter_value(&word)
                .map_err(|error| self.error_at(&token, error.to_string()))?,
            TokenKind::OpenList => {
                self.position -= 1;
                Value::Sequence(self.list(operator)?)
            }
            other => {
                return Err(self.error_at(
                    &token,
                    format!(
                        "expected a value after {}, found {other}; quote a value that contains spaces or punctuation",
                        operator.kind
                    ),
                ));
            }
        };
        // A value is one token, so a second bare word means an unquoted value
        // with a space in it: say so rather than calling it a missing AND.
        if let Some(Token {
            kind: TokenKind::Word(next),
            column,
        }) = self.peek()
            && !["and", "or"].contains(&next.to_ascii_lowercase().as_str())
        {
            return Err(invalid(format!(
                "unexpected '{next}' at column {column}; quote a value that contains spaces, such as \"{} {next}\"",
                display_value(&value)
            )));
        }
        Ok(value)
    }

    fn list(&mut self, operator: &Token) -> Result<Vec<Value>> {
        match self.next().cloned() {
            Some(Token {
                kind: TokenKind::OpenList,
                ..
            }) => {}
            Some(token) => {
                return Err(self.error_at(
                    &token,
                    format!(
                        "expected a list such as [open, won] after {}, found {}",
                        operator.kind, token.kind
                    ),
                ));
            }
            None => {
                return Err(self.error_at_end(format!(
                    "expected a list such as [open, won] after {}",
                    operator.kind
                )));
            }
        }
        let mut values = Vec::new();
        if matches!(
            self.peek(),
            Some(Token {
                kind: TokenKind::CloseList,
                ..
            })
        ) {
            self.position += 1;
            return Ok(values);
        }
        loop {
            let Some(token) = self.next().cloned() else {
                return Err(self.error_at_end("expected ']' to close the list".to_owned()));
            };
            values.push(match token.kind.clone() {
                TokenKind::Quoted(text) => Value::String(text),
                TokenKind::Word(word) => parse_filter_value(&word)
                    .map_err(|error| self.error_at(&token, error.to_string()))?,
                other => {
                    return Err(
                        self.error_at(&token, format!("expected a list item, found {other}"))
                    );
                }
            });
            match self.next().cloned() {
                Some(Token {
                    kind: TokenKind::Comma,
                    ..
                }) => continue,
                Some(Token {
                    kind: TokenKind::CloseList,
                    ..
                }) => return Ok(values),
                Some(token) => {
                    return Err(self.error_at(
                        &token,
                        format!("expected ',' or ']' in the list, found {}", token.kind),
                    ));
                }
                None => {
                    return Err(self.error_at_end("expected ']' to close the list".to_owned()));
                }
            }
        }
    }
}

fn parse_field(word: &str) -> Result<Field> {
    match word {
        "$id" => Ok(Field::Id),
        "$collection" => Ok(Field::Collection),
        "$path" => Ok(Field::Path),
        _ if word.starts_with('$') => Err(invalid(format!(
            "'{word}' is not a field; the record fields are $id, $collection, and $path"
        ))),
        _ => Ok(Field::Attribute(parse_path(word)?)),
    }
}

fn display_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => yaml_serde::to_string(other)
            .map(|text| text.trim_end().to_owned())
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use yaml_serde::Mapping;

    use super::Filter;
    use crate::database::Record;

    fn record(front_matter: &str) -> Record {
        Record {
            collection: "deals".to_owned(),
            id: "acme-renewal".to_owned(),
            path: PathBuf::from("records/deals/acme-renewal.md"),
            version: String::new(),
            attributes: yaml_serde::from_str::<Mapping>(front_matter).unwrap(),
            body: String::new(),
        }
    }

    fn matches(filter: &str, front_matter: &str) -> bool {
        filter
            .parse::<Filter>()
            .unwrap_or_else(|error| panic!("{filter}: {error}"))
            .matches(&record(front_matter))
    }

    fn error(filter: &str) -> String {
        filter.parse::<Filter>().unwrap_err().to_string()
    }

    const DEAL: &str = "stage: open\nvalue: 12000\nowner: null\nnotes: ''\ntags: [enterprise, renewal]\nname: Acme Corp\nclose: 2027-06-30\n";

    #[test]
    fn precedence_is_not_then_and_then_or() {
        assert!(matches(
            "stage = won OR stage = open AND value > 10000",
            DEAL
        ));
        assert!(!matches(
            "(stage = won OR stage = open) AND value > 20000",
            DEAL
        ));
        assert!(matches("NOT stage = won AND value >= 12000", DEAL));
        assert!(!matches("NOT (stage = open OR value > 1)", DEAL));
        assert!(matches("not not stage = open", DEAL));
    }

    #[test]
    fn values_are_typed_like_where_and_quotes_force_strings() {
        assert!(matches("value = 12000", DEAL));
        assert!(!matches("value = \"12000\"", DEAL));
        assert!(matches("name = 'Acme Corp'", DEAL));
        assert!(matches("name = \"Acme Corp\"", DEAL));
        assert!(matches("close < 2028-01-01", DEAL));
        assert!(matches("value>=12000 and stage=open", DEAL));
        assert!(matches("tags = [enterprise, renewal]", DEAL));
    }

    #[test]
    fn missing_null_and_empty_are_distinct() {
        assert!(matches("owner exists", DEAL));
        assert!(matches("owner is null", DEAL));
        assert!(!matches("owner is not null", DEAL));
        assert!(matches("owner is-empty", DEAL));
        assert!(matches("notes = \"\"", DEAL));
        assert!(matches("notes exists AND notes is not null", DEAL));
        assert!(matches("missing not exists", DEAL));
        assert!(!matches("missing is null", DEAL));
        assert!(matches("missing is empty", DEAL));
        assert!(!matches("notes is empty AND notes is null", DEAL));
        assert!(matches("tags is not empty", DEAL));
        assert!(matches("empty = []", "empty: []\n"));
        assert!(matches("empty = {}", "empty: {}\n"));
    }

    #[test]
    fn membership_and_containment() {
        assert!(matches("stage in [open, won]", DEAL));
        assert!(!matches("stage in []", DEAL));
        assert!(matches("stage not in [won, lost]", DEAL));
        assert!(matches("value in [1, 12000]", DEAL));
        assert!(matches("tags contains renewal", DEAL));
        assert!(matches("name contains 'Acme'", DEAL));
        assert!(matches(
            "name starts-with Acme AND name ends-with Corp",
            DEAL
        ));
        assert!(matches("tags not-contains trial", DEAL));
        // A missing field is in no list and outside none either.
        assert!(!matches("missing in [a]", DEAL));
        assert!(!matches("missing not in [a]", DEAL));
        assert!(!matches("missing != a", DEAL));
        assert!(matches("NOT missing = a", DEAL));
    }

    #[test]
    fn record_fields_can_be_filtered() {
        assert!(matches("$id starts-with acme", DEAL));
        assert!(matches("$collection = deals", DEAL));
        assert!(matches("$path ends-with .md", DEAL));
        assert!(error("$nope = 1").contains("$id, $collection, and $path"));
    }

    #[test]
    fn keywords_are_case_insensitive_and_strings_escape_quotes() {
        assert!(matches("STAGE = open", "STAGE: open\n"));
        assert!(matches("stage IN [open] And value Is Not Null", DEAL));
        assert!(matches(r#"quote = "say \"hi\"""#, "quote: say \"hi\"\n"));
        assert!(matches(r"quote = 'it\'s'", "quote: it's\n"));
    }

    #[test]
    fn parse_errors_say_what_was_expected_and_where() {
        assert_eq!(error(""), "a filter cannot be empty");
        assert_eq!(
            error("stage ="),
            "expected a value after '=' at the end of the filter (column 8)"
        );
        assert_eq!(
            error("(stage = open"),
            "expected ')' to close the '(' at column 1 at the end of the filter (column 14)"
        );
        assert_eq!(
            error("stage = open)"),
            "unexpected ')'; expected AND, OR, or the end of the filter at column 13"
        );
        assert_eq!(
            error("name = Acme Corp"),
            "unexpected 'Corp' at column 13; quote a value that contains spaces, such as \"Acme Corp\""
        );
        assert_eq!(
            error("stage"),
            "expected a comparison after the field 'stage', such as =, contains, in, exists, or is null at the end of the filter (column 6)"
        );
        assert_eq!(
            error("stage in open"),
            "expected a list such as [open, won] after 'in', found 'open' at column 10"
        );
        assert_eq!(
            error("stage in [open"),
            "expected ']' to close the list at the end of the filter (column 15)"
        );
        assert_eq!(
            error("name = \"Acme"),
            "the string starting at column 8 is never closed"
        );
        assert_eq!(
            error("stage is open"),
            "expected 'null' or 'empty' after 'is', found 'open' at column 10"
        );
        assert_eq!(
            error("stage ! open"),
            "unexpected '!' at column 7; use '!=' or NOT"
        );
        assert!(error("a..b = 1").contains("column 1"));
        assert_eq!(
            error("AND stage = open"),
            "expected a comparison after the field 'AND', such as =, contains, in, exists, or is null at column 5"
        );
    }
}
