//! Ordering records by one or more fields.
//!
//! A sort is an ordered list of keys, most significant first. Each key is a
//! dotted front matter path, or `$id`, `$collection`, or `$path`, and a
//! direction; server-rendered views may also sort by the audit-derived
//! `$created_at` and `$updated_at`. Records are compared key by key: the first
//! key that tells two records apart decides, and collection then record ID,
//! both ascending, decide what none of the keys does, so every ordering is
//! total and a page boundary never depends on the order records were read in.
//!
//! Within a key, values compare with [`compare_yaml_values`] — numbers
//! numerically, strings lexicographically, other types by a stable rank — and a
//! record without the field sorts after every record with it in either
//! direction, so reversing a key never floats the gaps to the top.
//!
//! The written form of a key is `FIELD`, `FIELD:asc`, or `FIELD:desc`. It is
//! the same text on the command line, in a query string, and in a saved view,
//! and it needs no quoting from a shell or encoding in a URL. Only a final
//! `:asc` or `:desc` is a direction, so a namespaced key such as `og:title`
//! still names a field.

use std::{cmp::Ordering, fmt, str::FromStr};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use yaml_serde::Value;

use crate::{
    database::Record,
    error::invalid,
    value::{compare_yaml_values, get_path, parse_path},
};

/// The most keys one sort may have.
///
/// Every key is compared for every pair of records a sort visits, and by the
/// fifth a tie is rare enough that another key would change nothing a reader
/// could see.
pub const MAX_SORT_KEYS: usize = 5;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}

impl SortDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }

    fn apply(self, ordering: Ordering) -> Ordering {
        match self {
            Self::Asc => ordering,
            Self::Desc => ordering.reverse(),
        }
    }
}

/// One key of a sort: a field and the direction it is ordered in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SortKey {
    pub field: String,
    pub direction: SortDirection,
}

impl SortKey {
    pub fn new(field: impl Into<String>, direction: SortDirection) -> Self {
        Self {
            field: field.into(),
            direction,
        }
    }

    /// Parse `FIELD[:asc|:desc]`, reporting whether the direction was written.
    fn parse(input: &str) -> Result<(Self, bool)> {
        let input = input.trim();
        let (field, direction) = match input.rsplit_once(':') {
            Some((field, suffix)) => match direction_suffix(suffix) {
                Some(direction) => (field.trim(), Some(direction)),
                None => (input, None),
            },
            None => (input, None),
        };
        if field.is_empty() {
            return Err(invalid(if input.is_empty() {
                "sort field cannot be empty".to_owned()
            } else {
                format!("sort key '{input}' names no field")
            }));
        }
        // `-value` is how JSON:API spells a descending key. Read here as a
        // field, it would name one no record has and quietly leave the result
        // in ID order, so it is refused with the spelling that works.
        if let Some(rest) = field.strip_prefix('-') {
            return Err(invalid(format!(
                "sort key '{input}' starts with '-'; write '{rest}:desc' to sort descending"
            )));
        }
        Ok((
            Self::new(field, direction.unwrap_or_default()),
            direction.is_some(),
        ))
    }
}

fn direction_suffix(suffix: &str) -> Option<SortDirection> {
    let suffix = suffix.trim();
    if suffix.eq_ignore_ascii_case("asc") {
        Some(SortDirection::Asc)
    } else if suffix.eq_ignore_ascii_case("desc") {
        Some(SortDirection::Desc)
    } else {
        None
    }
}

impl FromStr for SortKey {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input).map(|(key, _)| key)
    }
}

/// `FIELD` for an ascending key and `FIELD:desc` for a descending one, which
/// parse back to the same key.
impl fmt::Display for SortKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.field)?;
        let ambiguous = self
            .field
            .rsplit_once(':')
            .is_some_and(|(_, suffix)| direction_suffix(suffix).is_some());
        match self.direction {
            SortDirection::Desc => formatter.write_str(":desc"),
            // A field that itself ends in `:desc` keeps its name only if the
            // direction is spelled out after it.
            SortDirection::Asc if ambiguous => formatter.write_str(":asc"),
            SortDirection::Asc => Ok(()),
        }
    }
}

/// Read `--sort` or `sort`: keys written `FIELD[:asc|:desc]`, comma-separated
/// or repeated, most significant first.
///
/// `direction` is the older one-key spelling, `--desc` or `direction=desc`,
/// and `direction_name` is how the caller wrote it, for the refusal. It sets
/// the direction of a sort that has exactly one key, written without a
/// direction of its own. With more keys it could mean the first key or every
/// key, so rather than guess, it is refused.
pub fn parse_sort_keys<S: AsRef<str>>(
    lists: &[S],
    direction: Option<SortDirection>,
    direction_name: &str,
) -> Result<Vec<SortKey>> {
    let mut keys = Vec::new();
    let mut written = false;
    for list in lists {
        for item in list.as_ref().split(',') {
            let (key, has_direction) = SortKey::parse(item)?;
            written |= has_direction;
            keys.push(key);
        }
    }
    if let Some(direction) = direction {
        match keys.as_mut_slice() {
            // Nothing to order: accepted and ignored, as it always was.
            [] => {}
            [key] if !written => key.direction = direction,
            _ => {
                return Err(invalid(format!(
                    "{direction_name} applies only to a single sort key written without a direction; write FIELD:asc or FIELD:desc on each key instead"
                )));
            }
        }
    }
    validate_key_list(&keys)?;
    Ok(keys)
}

/// Refuse more than [`MAX_SORT_KEYS`] keys, or a field named twice.
///
/// A second key on the same field can never be consulted, because the first
/// has already told apart every pair of records it could, so naming one is a
/// mistake rather than a preference.
pub(crate) fn validate_key_list(keys: &[SortKey]) -> Result<()> {
    if keys.len() > MAX_SORT_KEYS {
        return Err(invalid(format!(
            "a sort can have at most {MAX_SORT_KEYS} keys, not {}",
            keys.len()
        )));
    }
    for (index, key) in keys.iter().enumerate() {
        if keys[..index]
            .iter()
            .any(|earlier| earlier.field.trim() == key.field.trim())
        {
            return Err(invalid(format!(
                "sort field '{}' is given more than once",
                key.field.trim()
            )));
        }
    }
    Ok(())
}

/// The audit-derived fields, which exist only in the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryField {
    Created,
    Updated,
}

/// What a key compares, resolved once rather than for every comparison.
enum Part {
    Id,
    Collection,
    Path,
    History(HistoryField),
    Field(Vec<String>),
}

impl Part {
    fn resolve(field: &str, history: bool) -> Result<Self> {
        let field = field.trim();
        if field.is_empty() {
            return Err(invalid("sort field cannot be empty"));
        }
        Ok(match field {
            "$id" => Self::Id,
            "$collection" => Self::Collection,
            "$path" => Self::Path,
            "$created_at" | "$updated_at" if !history => {
                // These exist only in the audit journal, and reading them is a
                // history read with its own permission. Sorting a plain record
                // scan by one would quietly replay the whole chain, so the
                // server-rendered views that already hold an activity map are
                // the only place they sort.
                return Err(invalid(format!(
                    "sort field '{field}' comes from audit history and is only available in server-rendered views"
                )));
            }
            "$created_at" => Self::History(HistoryField::Created),
            "$updated_at" => Self::History(HistoryField::Updated),
            _ => Self::Field(parse_path(field)?),
        })
    }
}

/// Sort records by `keys`. No keys leaves them in the order they are in.
pub fn sort_records(records: &mut [Record], keys: &[SortKey]) -> Result<()> {
    sort_by_record_keys(records, |record| record, keys)
}

/// Sort anything that carries a record by that record's fields, with exactly
/// the rules [`sort_records`] applies to plain records.
pub fn sort_by_record_keys<T>(
    items: &mut [T],
    record: impl Fn(&T) -> &Record,
    keys: &[SortKey],
) -> Result<()> {
    sort_with_history(
        items,
        record,
        keys,
        None::<fn(&Record, HistoryField) -> Option<u64>>,
    )
}

/// Sort by `keys`, where `history` gives a record's journal sequence for
/// `$created_at` and `$updated_at`.
///
/// Without `history` those two fields are refused by name. With it they order
/// by sequence number, which is the journal's exact total order, where
/// formatted instants can tie or, with fractional seconds, compare in the
/// wrong order as text. A record with no history sorts last, exactly like a
/// missing front matter value.
pub(crate) fn sort_with_history<T, H>(
    items: &mut [T],
    record: impl Fn(&T) -> &Record,
    keys: &[SortKey],
    history: Option<H>,
) -> Result<()>
where
    H: Fn(&Record, HistoryField) -> Option<u64>,
{
    validate_key_list(keys)?;
    let parts = keys
        .iter()
        .map(|key| Ok((Part::resolve(&key.field, history.is_some())?, key.direction)))
        .collect::<Result<Vec<_>>>()?;
    if parts.is_empty() {
        return Ok(());
    }
    items.sort_by(|left, right| {
        let (left, right) = (record(left), record(right));
        parts
            .iter()
            .map(|(part, direction)| {
                let direction = *direction;
                match part {
                    Part::Id => direction.apply(left.id.cmp(&right.id)),
                    Part::Collection => direction.apply(left.collection.cmp(&right.collection)),
                    Part::Path => direction.apply(left.path.cmp(&right.path)),
                    Part::History(field) => {
                        let sequence = |record: &Record| {
                            history.as_ref().and_then(|history| history(record, *field))
                        };
                        present_first(sequence(left), sequence(right), direction, Ord::cmp)
                    }
                    Part::Field(path) => present_first(
                        get_path(&left.attributes, path),
                        get_path(&right.attributes, path),
                        direction,
                        |left: &&Value, right: &&Value| compare_yaml_values(left, right),
                    ),
                }
            })
            .find(|ordering| ordering.is_ne())
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.collection.cmp(&right.collection))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(())
}

/// Order two values that may be missing: present values in `direction`, and
/// a missing one after every present one whichever way that is.
fn present_first<T>(
    left: Option<T>,
    right: Option<T>,
    direction: SortDirection,
    compare: impl Fn(&T, &T) -> Ordering,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => direction.apply(compare(&left, &right)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use yaml_serde::Mapping;

    use super::*;

    fn record(id: &str, front_matter: &str) -> Record {
        let attributes: Mapping = if front_matter.is_empty() {
            Mapping::new()
        } else {
            yaml_serde::from_str(front_matter).unwrap()
        };
        Record {
            collection: "deals".to_owned(),
            id: id.to_owned(),
            path: PathBuf::from(format!("records/deals/{id}.md")),
            version: String::new(),
            attributes,
            body: String::new(),
        }
    }

    fn ids(records: &[Record]) -> Vec<&str> {
        records.iter().map(|record| record.id.as_str()).collect()
    }

    fn keys(lists: &[&str]) -> Vec<SortKey> {
        parse_sort_keys(lists, None, "--desc").unwrap()
    }

    #[test]
    fn keys_are_written_with_an_optional_direction_suffix() {
        assert_eq!(
            keys(&["stage", "value:desc", " owner.name : ASC "]),
            [
                SortKey::new("stage", SortDirection::Asc),
                SortKey::new("value", SortDirection::Desc),
                SortKey::new("owner.name", SortDirection::Asc),
            ]
        );
        assert_eq!(keys(&["stage,value:desc"]), keys(&["stage", "value:desc"]));
        // Only a final asc or desc is a direction.
        assert_eq!(
            keys(&["og:title"]),
            [SortKey::new("og:title", SortDirection::Asc)]
        );
        assert_eq!(
            "og:title:desc".parse::<SortKey>().unwrap(),
            SortKey::new("og:title", SortDirection::Desc)
        );
        for key in [
            SortKey::new("value", SortDirection::Asc),
            SortKey::new("value", SortDirection::Desc),
            SortKey::new("og:title", SortDirection::Asc),
            SortKey::new("odd:desc", SortDirection::Asc),
            SortKey::new("odd:asc", SortDirection::Desc),
        ] {
            assert_eq!(key.to_string().parse::<SortKey>().unwrap(), key);
        }
        assert_eq!(
            SortKey::new("value", SortDirection::Desc).to_string(),
            "value:desc"
        );
        assert_eq!(
            SortKey::new("value", SortDirection::Asc).to_string(),
            "value"
        );
    }

    #[test]
    fn malformed_duplicate_and_excess_keys_are_refused() {
        let refused = |lists: &[&str]| {
            parse_sort_keys(lists, None, "--desc")
                .unwrap_err()
                .to_string()
        };
        assert!(refused(&[""]).contains("cannot be empty"));
        assert!(refused(&["stage,,value"]).contains("cannot be empty"));
        assert!(refused(&[":desc"]).contains("names no field"));
        assert!(refused(&["-value"]).contains("write 'value:desc'"));
        assert!(refused(&["value", "value:desc"]).contains("more than once"));
        assert!(refused(&["a,b,c,d,e,f"]).contains("at most 5 keys"));
        assert_eq!(keys(&["a,b,c,d,e"]).len(), MAX_SORT_KEYS);
    }

    #[test]
    fn the_one_key_direction_applies_only_to_one_undirected_key() {
        let desc = |lists: &[&str]| parse_sort_keys(lists, Some(SortDirection::Desc), "--desc");
        assert_eq!(
            desc(&["value"]).unwrap(),
            [SortKey::new("value", SortDirection::Desc)]
        );
        assert!(desc(&[]).unwrap().is_empty());
        for lists in [&["value:asc"][..], &["value:desc"], &["stage", "value"]] {
            let error = desc(lists).unwrap_err().to_string();
            assert!(error.starts_with("--desc applies only"), "{error}");
        }
    }

    #[test]
    fn keys_compare_in_order_with_missing_values_last_and_ids_breaking_ties() {
        let mut records = vec![
            record("f", "stage: won\nvalue: 5"),
            record("e", "stage: open"),
            record("d", "stage: open\nvalue: 5"),
            record("c", "value: 50"),
            record("b", "stage: open\nvalue: 20"),
            record("a", "stage: won\nvalue: 5"),
        ];
        sort_records(&mut records, &keys(&["stage", "value:desc"])).unwrap();
        assert_eq!(ids(&records), ["b", "d", "e", "a", "f", "c"]);

        sort_records(&mut records, &keys(&["stage:desc", "value"])).unwrap();
        assert_eq!(ids(&records), ["a", "f", "d", "b", "e", "c"]);

        sort_records(&mut records, &keys(&["value", "stage:desc", "$id:desc"])).unwrap();
        assert_eq!(ids(&records), ["f", "a", "d", "b", "c", "e"]);
    }

    #[test]
    fn history_fields_sort_only_where_history_is_given() {
        let mut records = vec![record("a", ""), record("b", ""), record("c", "")];
        let error = sort_records(&mut records, &keys(&["$updated_at"]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("comes from audit history"), "{error}");

        let sequence = |record: &Record, field: HistoryField| match (record.id.as_str(), field) {
            ("a", HistoryField::Created) => Some(1),
            ("b", HistoryField::Created) => Some(2),
            (_, HistoryField::Updated) => Some(7),
            _ => None,
        };
        sort_with_history(
            &mut records,
            |record| record,
            &keys(&["$created_at:desc"]),
            Some(sequence),
        )
        .unwrap();
        assert_eq!(ids(&records), ["b", "a", "c"]);
        sort_with_history(
            &mut records,
            |record| record,
            &keys(&["$updated_at", "$created_at:desc"]),
            Some(sequence),
        )
        .unwrap();
        assert_eq!(ids(&records), ["b", "a", "c"]);
    }
}
