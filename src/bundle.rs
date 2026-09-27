//! Bundle records: a Markdown entry file and the supporting files beside it.
//!
//! A collection normally stores each record as one Markdown file,
//! `records/<collection>/<id>.md`. A collection that `.cr/config.yaml` declares
//! with `layout: bundle` stores each record as a folder instead, the way Hugo
//! stores a page bundle:
//!
//! ```text
//! records/skills/pdf-forms/
//! ├── SKILL.md              # the entry: front matter and Markdown, as ever
//! ├── references/api.md     # supporting files, stored byte for byte
//! └── scripts/fill.py
//! ```
//!
//! The entry is the record exactly as a file-layout record is: parsed,
//! validated, and diffed field by field. Every other file in the folder
//! belongs to the record without being one. It has no front matter, so a
//! script stays runnable and a font stays a font, and it is written, audited,
//! versioned, and authorized only as part of its record.
//!
//! Three things follow from "part of its record", and this module is where
//! each is defined once:
//!
//! - **The version covers the files.** [`record_version`] extends the record
//!   hash with a manifest of every supporting file's content hash, so a
//!   conditional write naming a version fails when any file changed, and a
//!   direct edit to any file is visible to `cr status` as a modified record.
//!   A bundle with no supporting files has exactly the version a file-layout
//!   record with the same Markdown would.
//! - **Every file change is in the record's audit event.** [`file_changes`]
//!   describes a change as the content hashes before and after and, for small
//!   UTF-8 text, a unified diff; [`apply_file_changes`] is how replay holds an
//!   event to it, applying each diff and requiring the result to hash to what
//!   the event claims.
//! - **A write of several files is still recoverable.** One rename is atomic
//!   and several are not, so [`BundlePlan`] records every file's state before
//!   and after. Recovery can tell a write that never started from one that
//!   finished or stopped halfway, and completes the last from contents staged
//!   before the first file was touched.
//!
//! Supporting-file paths are relative, `/`-separated, and UTF-8, with no empty,
//! `.`, or `..` component, no backslash or control character, and nothing
//! named like a staged write. The folder is read through the same
//! symlink-refusing walk as every other database path, so a symbolic link
//! anywhere inside a bundle is refused rather than followed.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    audit::{AuditFileChange, AuditFileOperation, digest, record_hash},
    database::{CollectionEntry, collection_entry, validate_component},
    error::{DomainError, conflict, invalid, is_missing},
    paths::{self, EntryKind},
};

/// The largest file an audit event carries as a diff. Larger files, and any
/// file that is not UTF-8 text, are recorded by their hashes alone.
pub(crate) const TEXT_DIFF_LIMIT: usize = 256 * 1024;

/// The entry file of a bundle collection that does not name one, after Hugo.
pub(crate) const DEFAULT_ENTRY: &str = "index.md";

/// The longest supporting-file path accepted, in bytes.
const MAX_FILE_PATH_BYTES: usize = 1024;

/// The longest name one component of a supporting-file path may have, in
/// bytes: what common filesystems store, so a write is refused before it
/// starts rather than failing partway through a folder.
const MAX_FILE_NAME_BYTES: usize = 255;

/// Separates a bundle version from a plain record version and from every other
/// digest `cr` records.
const BUNDLE_HASH_DOMAIN: &[u8] = b"cr:bundle:v1\0";

/// Lines of unchanged context around each change in a diff.
const DIFF_CONTEXT: usize = 3;

/// The most changed lines a diff aligns line by line. Beyond it, the changed
/// region is recorded as removed and then added, which is still an exact and
/// replayable diff, so a pathological file cannot make a write slow and the
/// diff never depends on how long anything took.
const MAX_ALIGNED_LINES: usize = 10_000;

/// Marks a diff line whose content has no final newline.
const NO_NEWLINE: &str = "\\ No newline at end of file\n";

/// One requested change to a bundle record's supporting files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileChange {
    /// Create the file, or replace it, with exactly these bytes.
    Write { path: String, contents: Vec<u8> },
    /// Remove the file. Removing a file the record does not have is refused.
    Remove { path: String },
}

impl FileChange {
    /// The supporting-file path this change is about.
    pub fn path(&self) -> &str {
        match self {
            Self::Write { path, .. } | Self::Remove { path } => path,
        }
    }
}

/// How one collection stores its records, as `.cr/config.yaml` declares it.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CollectionConfig {
    #[serde(default)]
    pub layout: LayoutKind,
    /// The entry file's name, for the bundle layout only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
}

/// Whether a collection's record is a Markdown file or a folder.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LayoutKind {
    #[default]
    File,
    Bundle,
}

/// Which collections store records as bundles, and under which entry name.
///
/// Every collection not named here stores a record as one Markdown file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RecordLayout {
    bundles: BTreeMap<String, String>,
}

impl RecordLayout {
    /// Validate the `collections` section of a configuration.
    pub(crate) fn from_config(collections: &BTreeMap<String, CollectionConfig>) -> Result<Self> {
        let mut bundles = BTreeMap::new();
        for (collection, config) in collections {
            validate_component(collection, "collection")?;
            if collection == crate::access::USERS_COLLECTION {
                return Err(invalid(
                    "the users collection stores one Markdown file per principal, so its layout cannot be configured",
                ));
            }
            match config.layout {
                LayoutKind::File => {
                    if config.entry.is_some() {
                        return Err(invalid(format!(
                            "collections.{collection}.entry applies only to the bundle layout"
                        )));
                    }
                }
                LayoutKind::Bundle => {
                    let entry = config.entry.as_deref().unwrap_or(DEFAULT_ENTRY);
                    validate_entry_name(collection, entry)?;
                    bundles.insert(collection.clone(), entry.to_owned());
                }
            }
        }
        Ok(Self { bundles })
    }

    /// The entry file's name when `collection` stores records as bundles.
    pub(crate) fn entry(&self, collection: &str) -> Option<&str> {
        self.bundles.get(collection).map(String::as_str)
    }

    /// Where a record's Markdown lives: its file, or its bundle's entry.
    ///
    /// Callers validate `collection` and `id` first.
    pub(crate) fn record_path(&self, records_dir: &Path, collection: &str, id: &str) -> PathBuf {
        match self.entry(collection) {
            Some(entry) => records_dir.join(collection).join(id).join(entry),
            None => records_dir.join(collection).join(format!("{id}.md")),
        }
    }

    /// Decide what the collection-directory entry `name`, of kind `kind`, is.
    ///
    /// The file layout's rule is [`collection_entry`]: a Markdown file whose
    /// stem is an ID. In a bundle collection every entry that is not a
    /// regular file claims to be a record, and its name must be an ID; a
    /// regular file is ignored, except a Markdown one, which is refused —
    /// it is a record written for the wrong layout, and ignoring it would hide
    /// it from every command. Callers then require [`Self::stores_record_as`].
    pub(crate) fn collection_entry(
        &self,
        collection: &str,
        name: &OsStr,
        kind: EntryKind,
    ) -> Result<CollectionEntry> {
        let Some(entry) = self.entry(collection) else {
            return collection_entry(collection, name);
        };
        if kind.is_file() {
            if Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "md")
            {
                return Err(anyhow::Error::new(DomainError::Conflict(format!(
                    "collection '{collection}' stores each record as a folder holding '{entry}', but contains a Markdown file named '{}'",
                    name.to_string_lossy()
                ))));
            }
            return Ok(CollectionEntry::Ignored);
        }
        let Some(id) = name.to_str() else {
            return Err(anyhow::Error::new(DomainError::Conflict(format!(
                "collection '{collection}' contains a folder named '{}' whose name is not valid UTF-8",
                name.to_string_lossy()
            ))));
        };
        if validate_component(id, "id").is_err() {
            return Err(anyhow::Error::new(DomainError::Conflict(format!(
                "collection '{collection}' contains a folder named '{id}' whose name cannot be a record ID"
            ))));
        }
        Ok(CollectionEntry::Record(id.to_owned()))
    }

    /// Whether a directory entry of kind `kind` is how `collection` stores a
    /// record: a regular file for the file layout, a directory for bundles.
    pub(crate) fn stores_record_as(&self, collection: &str, kind: EntryKind) -> bool {
        match self.entry(collection) {
            Some(_) => kind.is_directory(),
            None => kind.is_file(),
        }
    }
}

fn validate_entry_name(collection: &str, entry: &str) -> Result<()> {
    let usable = validate_component(entry, "entry").is_ok()
        && !paths::is_temporary_name(OsStr::new(entry))
        && !entry.chars().any(char::is_control)
        && Path::new(entry)
            .extension()
            .is_some_and(|extension| extension == "md")
        && entry.len() > ".md".len();
    if usable {
        return Ok(());
    }
    Err(invalid(format!(
        "collections.{collection}.entry must be a single file name ending in '.md'"
    )))
}

/// Refuse a supporting-file path a record cannot hold.
pub(crate) fn validate_file_path(path: &str) -> Result<()> {
    let refuse = |reason: &str| invalid(format!("file path '{}' {reason}", path.escape_default()));
    if path.is_empty() {
        return Err(invalid("a file path cannot be empty"));
    }
    if path.len() > MAX_FILE_PATH_BYTES {
        return Err(refuse(&format!(
            "is longer than {MAX_FILE_PATH_BYTES} bytes"
        )));
    }
    if path.starts_with('/') {
        return Err(refuse("must be relative to the record's folder"));
    }
    for component in path.split('/') {
        match component {
            "" => return Err(refuse("cannot contain an empty component")),
            "." | ".." => return Err(refuse("cannot contain '.' or '..'")),
            _ => {}
        }
        if component.len() > MAX_FILE_NAME_BYTES {
            return Err(refuse(&format!(
                "has a name longer than {MAX_FILE_NAME_BYTES} bytes"
            )));
        }
        if component.contains('\\') {
            return Err(refuse("cannot contain a backslash"));
        }
        if component.chars().any(char::is_control) {
            return Err(refuse("cannot contain a control character"));
        }
        if paths::is_temporary_name(OsStr::new(component)) {
            return Err(refuse("uses a name reserved for staged writes"));
        }
    }
    Ok(())
}

/// A supporting file as `cr` knows it: its content hash, and its text when an
/// audit event can carry its changes as a diff.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct BundleFile {
    /// `sha256:` and the plain SHA-256 of the exact bytes, so `sha256sum`
    /// agrees with it.
    pub hash: String,
    /// The contents, when they are UTF-8 text of at most [`TEXT_DIFF_LIMIT`]
    /// bytes without a NUL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// A bundle's supporting files by path, in byte order.
pub(crate) type BundleFiles = BTreeMap<String, BundleFile>;

impl BundleFile {
    pub(crate) fn of(contents: &[u8]) -> Self {
        Self {
            hash: content_hash(contents),
            text: text_of(contents),
        }
    }

    /// Hash one file through a verified descriptor, keeping its contents only
    /// when they are text an audit event can diff.
    fn read(root: &Path, relative: &Path, label: &str) -> Result<Self> {
        let mut file = paths::open_file(root, relative, label)?;
        let mut hasher = Sha256::new();
        let mut kept = Vec::new();
        let mut textual = true;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .with_context(|| format!("could not read {label}"))?;
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            hasher.update(chunk);
            if textual {
                if kept.len() + read > TEXT_DIFF_LIMIT || chunk.contains(&0) {
                    textual = false;
                    kept = Vec::new();
                } else {
                    kept.extend_from_slice(chunk);
                }
            }
        }
        Ok(Self {
            hash: hex_hash(hasher),
            text: textual.then(|| String::from_utf8(kept).ok()).flatten(),
        })
    }
}

/// `sha256:` and the plain SHA-256 of `contents`.
pub(crate) fn content_hash(contents: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(contents);
    hex_hash(hasher)
}

fn hex_hash(hasher: Sha256) -> String {
    use std::fmt::Write as _;
    let mut value = String::from("sha256:");
    for byte in hasher.finalize() {
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

fn text_of(contents: &[u8]) -> Option<String> {
    if contents.len() > TEXT_DIFF_LIMIT || contents.contains(&0) {
        return None;
    }
    std::str::from_utf8(contents).ok().map(str::to_owned)
}

/// A record's version: the record hash of its Markdown when it has no
/// supporting files, and otherwise a digest over that hash and every
/// supporting file's content hash and path.
///
/// The manifest is one line for the Markdown, then `<hash> <path>` per file in
/// byte order of the path. Paths cannot contain a newline, so it is
/// unambiguous, and anybody holding the files can recompute it.
pub(crate) fn record_version(entry: &[u8], files: &BundleFiles) -> String {
    if files.is_empty() {
        return record_hash(entry);
    }
    manifest_version(Some(entry), files)
}

/// The version of a folder that holds supporting files and no entry. No
/// audited state is ever such a folder, so it can never match one, which is
/// what makes it visible as a divergence rather than as a missing record.
fn incomplete_version(files: &BundleFiles) -> String {
    manifest_version(None, files)
}

fn manifest_version(entry: Option<&[u8]>, files: &BundleFiles) -> String {
    let mut manifest = match entry {
        Some(entry) => record_hash(entry),
        None => "-".to_owned(),
    };
    manifest.push('\n');
    for (path, file) in files {
        manifest.push_str(&file.hash);
        manifest.push(' ');
        manifest.push_str(path);
        manifest.push('\n');
    }
    digest(BUNDLE_HASH_DOMAIN, manifest.as_bytes())
}

/// What a read of a record's folder makes of a file named like a write `cr`
/// stages before publishing it.
///
/// A write stages each file beside its target and renames it into place, so a
/// read that does not hold the audit lock can see one mid-write and skips it,
/// as it treats a file that vanished between listing and reading as absent.
/// Under the lock no write is in progress, the only such file a crash leaves
/// is removed by recovering that write, and anything else named like one is
/// refused: skipping it there would hide a file from the audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Staged {
    Skip,
    Refuse,
}

/// Every file in a record's folder, by path, without reading any of them.
pub(crate) struct BundleListing {
    pub has_entry: bool,
    pub files: Vec<String>,
}

/// A record's folder as it is on disk.
pub(crate) struct StoredBundle {
    pub entry: Option<Vec<u8>>,
    pub files: BundleFiles,
}

impl StoredBundle {
    /// The version of what is on disk, including a folder without an entry.
    pub(crate) fn version(&self) -> String {
        match &self.entry {
            Some(entry) => record_version(entry, &self.files),
            None => incomplete_version(&self.files),
        }
    }
}

/// List the files in the record folder `directory`, refusing anything a
/// bundle cannot hold. `None` when the folder does not exist or holds no file
/// at all: a folder a deletion emptied is not a record.
pub(crate) fn list_bundle(
    root: &Path,
    directory: &Path,
    entry: &str,
    label: &str,
    staged: Staged,
) -> Result<Option<BundleListing>> {
    let mut has_entry = false;
    let mut files = Vec::new();
    let mut pending = vec![String::new()];
    let mut first = true;
    while let Some(prefix) = pending.pop() {
        let relative = if prefix.is_empty() {
            directory.to_path_buf()
        } else {
            directory.join(&prefix)
        };
        let listed = match paths::list_directory(root, &relative, label) {
            // Opened and then removed before it could be read.
            Err(error) if staged == Staged::Skip && is_missing(&error) => None,
            listed => listed?,
        };
        let Some(entries) = listed else {
            if first {
                return Ok(None);
            }
            // Removed while it was being listed; there is nothing in it.
            continue;
        };
        first = false;
        for item in entries {
            let Some(name) = item.name.to_str() else {
                return Err(anyhow::Error::new(DomainError::Conflict(format!(
                    "{label} holds a file whose name is not valid UTF-8"
                ))));
            };
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            if paths::is_temporary_name(&item.name) {
                if staged == Staged::Skip && item.kind.is_file() {
                    continue;
                }
                return Err(conflict(format!(
                    "{label} holds '{}', named like a write cr stages; remove it",
                    path.escape_default()
                )));
            }
            if validate_file_path(&path).is_err() {
                return Err(conflict(format!(
                    "{label} holds '{}', which cannot be a file path of a record",
                    path.escape_default()
                )));
            }
            let file_label = file_label(label, &path);
            match item.kind {
                EntryKind::Directory => {
                    if prefix.is_empty() && name == entry {
                        return Err(conflict(format!(
                            "{label} has a directory where its entry '{entry}' belongs"
                        )));
                    }
                    pending.push(path);
                }
                EntryKind::File => {
                    if prefix.is_empty() && name == entry {
                        has_entry = true;
                    } else {
                        files.push(path);
                    }
                }
                kind => return Err(paths::refuse_entry(&file_label, kind)),
            }
        }
    }
    files.sort();
    Ok((has_entry || !files.is_empty()).then_some(BundleListing { has_entry, files }))
}

/// Remove what a write interrupted inside the record folder `directory` left
/// staged beside its target: files named like [`paths`] names a write before
/// publishing it. Only recovery calls this, under the audit lock, when the
/// pending write is the one that could have left them.
pub(crate) fn remove_staged_leftovers(root: &Path, directory: &Path, label: &str) -> Result<()> {
    let mut pending = vec![directory.to_path_buf()];
    while let Some(folder) = pending.pop() {
        let Some(entries) = paths::list_directory(root, &folder, label)? else {
            continue;
        };
        for item in entries {
            let path = folder.join(&item.name);
            match item.kind {
                EntryKind::Directory => pending.push(path),
                EntryKind::File if paths::is_temporary_name(&item.name) => {
                    paths::remove_file(root, &path, label)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Read and hash everything in the record folder `directory`. `None` exactly
/// when [`list_bundle`] finds no record there.
pub(crate) fn read_bundle(
    root: &Path,
    directory: &Path,
    entry: &str,
    label: &str,
    staged: Staged,
) -> Result<Option<StoredBundle>> {
    let Some(listing) = list_bundle(root, directory, entry, label, staged)? else {
        return Ok(None);
    };
    // Without the lock a write can remove a listed file, or put a folder in
    // its place, before it is read; under it nothing can, and a file that is
    // no longer there is a real failure.
    let vanished = |relative: &Path, error: &anyhow::Error| {
        staged == Staged::Skip && (is_missing(error) || !is_regular_file(root, relative, label))
    };
    let entry_path = directory.join(entry);
    let entry = match listing
        .has_entry
        .then(|| paths::read(root, &entry_path, label))
        .transpose()
    {
        Ok(entry) => entry,
        Err(error) if vanished(&entry_path, &error) => None,
        Err(error) => return Err(error),
    };
    let mut files = BundleFiles::new();
    for path in listing.files {
        let relative = directory.join(&path);
        match BundleFile::read(root, &relative, &file_label(label, &path)) {
            Ok(file) => {
                files.insert(path, file);
            }
            Err(error) if vanished(&relative, &error) => {}
            Err(error) => return Err(error),
        }
    }
    if entry.is_none() && files.is_empty() {
        return Ok(None);
    }
    Ok(Some(StoredBundle { entry, files }))
}

/// Whether `relative` is, right now, a regular file reached without a link.
pub(crate) fn is_regular_file(root: &Path, relative: &Path, label: &str) -> bool {
    matches!(
        paths::entry_kind(root, relative, label),
        Ok(Some(EntryKind::File))
    )
}

/// How a supporting file is named in a message: by path within its record,
/// never by location on disk.
pub(crate) fn file_label(record: &str, path: &str) -> String {
    format!("file '{}' of {record}", path.escape_default())
}

/// Apply requested changes to a record's supporting files, returning the
/// complete set of files it will hold. `entry` is the collection's entry
/// name, which no supporting file may shadow.
pub(crate) fn edit_files(
    current: &BundleFiles,
    changes: &[FileChange],
    entry: &str,
    label: &str,
) -> Result<BundleFiles> {
    let mut files = current.clone();
    let mut touched = BTreeSet::new();
    for change in changes {
        let path = change.path();
        validate_file_path(path)?;
        if !touched.insert(path.to_owned()) {
            return Err(invalid(format!(
                "file '{}' is changed more than once in one request",
                path.escape_default()
            )));
        }
        if path.to_lowercase() == entry.to_lowercase() {
            return Err(invalid(format!(
                "'{entry}' is the record itself; change its front matter and body instead"
            )));
        }
        match change {
            FileChange::Write { contents, .. } => {
                files.insert(path.to_owned(), BundleFile::of(contents));
            }
            FileChange::Remove { .. } => {
                if files.remove(path).is_none() {
                    return Err(anyhow::Error::new(DomainError::NotFound(format!(
                        "{} does not exist",
                        file_label(label, path)
                    ))));
                }
            }
        }
    }
    // Only paths this request adds are judged: a folder written by hand on a
    // case-sensitive filesystem may already hold both spellings. Every level
    // of a path is compared, so `Scripts/b` cannot join `scripts/a` either.
    let added: Vec<&String> = files
        .keys()
        .filter(|path| !current.contains_key(*path))
        .collect();
    let mut spellings: BTreeMap<String, String> = BTreeMap::new();
    for path in files
        .keys()
        .filter(|path| !added.contains(path))
        .chain(std::iter::once(&entry.to_owned()))
    {
        for prefix in prefixes(path) {
            spellings
                .entry(prefix.to_lowercase())
                .or_insert_with(|| prefix.to_owned());
        }
    }
    for path in &added {
        for prefix in prefixes(path) {
            let spelled = spellings
                .entry(prefix.to_lowercase())
                .or_insert_with(|| prefix.to_owned());
            if spelled != prefix {
                return Err(invalid(format!(
                    "file '{}' differs from '{}' only by letter case, which some filesystems cannot keep apart",
                    path.escape_default(),
                    spelled.escape_default()
                )));
            }
        }
        let mut ancestor = path.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            if files.contains_key(parent) || parent == entry {
                return Err(invalid(format!(
                    "file '{}' would need '{}' to be a folder, but it is a file",
                    path.escape_default(),
                    parent.escape_default()
                )));
            }
            ancestor = parent;
        }
        let folder = format!("{path}/");
        if files.keys().any(|other| other.starts_with(&folder)) {
            return Err(invalid(format!(
                "file '{}' would replace a folder of the record",
                path.escape_default()
            )));
        }
    }
    Ok(files)
}

/// Every folder `path` lies in, outermost first, and then `path` itself.
fn prefixes(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/')
        .map(|(index, _)| &path[..index])
        .chain(std::iter::once(path))
}

/// Describe the difference between two sets of supporting files as an audit
/// event records it, in path order.
///
/// A diff is carried whenever the new contents are text: against the old text,
/// or against nothing when the file is new or was binary. Replay applies the
/// same rule, which is why `before` must be the *audited* files — their text
/// is exactly what replay will hold.
pub(crate) fn file_changes(before: &BundleFiles, after: &BundleFiles) -> Vec<AuditFileChange> {
    let paths: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let mut changes = Vec::new();
    for path in paths {
        let change = match (before.get(path), after.get(path)) {
            (None, Some(added)) => AuditFileChange {
                operation: AuditFileOperation::Add,
                path: path.clone(),
                before: None,
                after: Some(added.hash.clone()),
                diff: added.text.as_deref().map(|text| diff_text("", text)),
            },
            (Some(removed), None) => AuditFileChange {
                operation: AuditFileOperation::Remove,
                path: path.clone(),
                before: Some(removed.hash.clone()),
                after: None,
                diff: removed.text.as_deref().map(|text| diff_text(text, "")),
            },
            (Some(old), Some(new)) if old.hash != new.hash => AuditFileChange {
                operation: AuditFileOperation::Replace,
                path: path.clone(),
                before: Some(old.hash.clone()),
                after: Some(new.hash.clone()),
                diff: new
                    .text
                    .as_deref()
                    .map(|text| diff_text(old.text.as_deref().unwrap_or(""), text)),
            },
            _ => continue,
        };
        changes.push(change);
    }
    changes
}

/// Replay one event's file changes onto a record's audited files, proving
/// that every before-hash matches the replayed state and that every diff
/// produces the after-hash it claims.
pub(crate) fn apply_file_changes(
    files: &mut BundleFiles,
    changes: &[AuditFileChange],
) -> Result<()> {
    let mut previous: Option<&str> = None;
    for change in changes {
        let path = change.path.as_str();
        if previous.is_some_and(|previous| previous >= path) {
            bail!("file changes must name each path once, in order");
        }
        previous = Some(path);
        validate_file_path(path).context("file change names an unusable path")?;
        for hash in change.before.iter().chain(change.after.iter()) {
            if !valid_content_hash(hash) {
                bail!("file change for '{path}' has a malformed hash");
            }
        }
        let current = files.get(path);
        let text = match change.operation {
            AuditFileOperation::Add => {
                if current.is_some() || change.before.is_some() || change.after.is_none() {
                    bail!("file change adds '{path}', which is not how the record stood");
                }
                change
                    .diff
                    .as_deref()
                    .map(|diff| apply_diff("", diff))
                    .transpose()?
            }
            AuditFileOperation::Remove => {
                if current.map(|file| &file.hash) != change.before.as_ref()
                    || change.after.is_some()
                {
                    bail!("file change removes '{path}' from a state the record was not in");
                }
                if let Some(diff) = change.diff.as_deref() {
                    let old = current
                        .and_then(|file| file.text.as_deref())
                        .with_context(|| {
                            format!("file change diffs '{path}', which was not text")
                        })?;
                    if !apply_diff(old, diff)?.is_empty() {
                        bail!("file change for removed '{path}' does not remove all of it");
                    }
                }
                files.remove(path);
                continue;
            }
            AuditFileOperation::Replace => {
                if current.map(|file| &file.hash) != change.before.as_ref()
                    || change.after.is_none()
                    || change.before == change.after
                {
                    bail!("file change replaces '{path}' from a state the record was not in");
                }
                let old = current.and_then(|file| file.text.as_deref()).unwrap_or("");
                change
                    .diff
                    .as_deref()
                    .map(|diff| apply_diff(old, diff))
                    .transpose()?
            }
        };
        let after = change.after.clone().expect("checked above");
        if let Some(text) = &text
            && content_hash(text.as_bytes()) != after
        {
            bail!("file change diff for '{path}' does not produce its after hash");
        }
        files.insert(path.to_owned(), BundleFile { hash: after, text });
    }
    Ok(())
}

fn valid_content_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// A line of text with its terminator, as diffs count lines.
fn lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

#[derive(Clone, Copy)]
enum Edit<'a> {
    Keep(&'a str),
    Delete(&'a str),
    Insert(&'a str),
}

/// A unified diff from `before` to `after`: hunks only, without file headers,
/// with [`DIFF_CONTEXT`] lines of context. A line without a final newline is
/// followed by the conventional `\ No newline at end of file` marker, so the
/// diff reproduces both texts exactly. Identical texts produce no hunks.
pub(crate) fn diff_text(before: &str, after: &str) -> String {
    let old = lines(before);
    let new = lines(after);
    let prefix = old
        .iter()
        .zip(&new)
        .take_while(|(left, right)| left == right)
        .count();
    let suffix = old[prefix..]
        .iter()
        .rev()
        .zip(new[prefix..].iter().rev())
        .take_while(|(left, right)| left == right)
        .count();
    let old_middle = &old[prefix..old.len() - suffix];
    let new_middle = &new[prefix..new.len() - suffix];

    let mut edits: Vec<Edit<'_>> = old[..prefix].iter().map(|line| Edit::Keep(line)).collect();
    if old_middle.len() + new_middle.len() <= MAX_ALIGNED_LINES {
        for op in similar::capture_diff_slices(similar::Algorithm::Myers, old_middle, new_middle) {
            for change in op.iter_changes(old_middle, new_middle) {
                edits.push(match change.tag() {
                    similar::ChangeTag::Equal => Edit::Keep(change.value()),
                    similar::ChangeTag::Delete => Edit::Delete(change.value()),
                    similar::ChangeTag::Insert => Edit::Insert(change.value()),
                });
            }
        }
    } else {
        edits.extend(old_middle.iter().map(|line| Edit::Delete(line)));
        edits.extend(new_middle.iter().map(|line| Edit::Insert(line)));
    }
    edits.extend(
        old[old.len() - suffix..]
            .iter()
            .map(|line| Edit::Keep(line)),
    );
    render_hunks(&edits)
}

fn render_hunks(edits: &[Edit<'_>]) -> String {
    let changed: Vec<usize> = edits
        .iter()
        .enumerate()
        .filter(|(_, edit)| !matches!(edit, Edit::Keep(_)))
        .map(|(index, _)| index)
        .collect();
    let mut output = String::new();
    let mut position = 0;
    while position < changed.len() {
        // Extend the hunk while the next change is close enough that the
        // context between them would overlap.
        let mut last = position;
        while last + 1 < changed.len() && changed[last + 1] - changed[last] <= 2 * DIFF_CONTEXT + 1
        {
            last += 1;
        }
        let start = changed[position].saturating_sub(DIFF_CONTEXT);
        let end = (changed[last] + DIFF_CONTEXT + 1).min(edits.len());
        let (mut old_line, mut new_line) = (0, 0);
        for edit in &edits[..start] {
            match edit {
                Edit::Keep(_) => {
                    old_line += 1;
                    new_line += 1;
                }
                Edit::Delete(_) => old_line += 1,
                Edit::Insert(_) => new_line += 1,
            }
        }
        let hunk = &edits[start..end];
        let old_count = hunk
            .iter()
            .filter(|edit| !matches!(edit, Edit::Insert(_)))
            .count();
        let new_count = hunk
            .iter()
            .filter(|edit| !matches!(edit, Edit::Delete(_)))
            .count();
        output.push_str(&format!(
            "@@ -{} +{} @@\n",
            hunk_range(old_line, old_count),
            hunk_range(new_line, new_count)
        ));
        for edit in hunk {
            let (tag, line) = match edit {
                Edit::Keep(line) => (' ', *line),
                Edit::Delete(line) => ('-', *line),
                Edit::Insert(line) => ('+', *line),
            };
            output.push(tag);
            output.push_str(line);
            if !line.ends_with('\n') {
                output.push('\n');
                output.push_str(NO_NEWLINE);
            }
        }
        position = last + 1;
    }
    output
}

/// A hunk range the way `diff -u` writes it: the count is omitted when it is
/// one, and an empty range names the line before it.
fn hunk_range(lines_before: usize, count: usize) -> String {
    match count {
        0 => format!("{lines_before},0"),
        1 => format!("{}", lines_before + 1),
        _ => format!("{},{count}", lines_before + 1),
    }
}

/// Apply a diff written by [`diff_text`] to `before`, refusing one that does
/// not describe `before` exactly: a context or removed line that differs, a
/// hunk out of order or out of range, or a count that disagrees with its
/// lines.
pub(crate) fn apply_diff(before: &str, diff: &str) -> Result<String> {
    let old = lines(before);
    let mut output = String::with_capacity(before.len() + diff.len());
    let mut cursor = 0;
    let mut written = 0;
    let mut rest = lines(diff).into_iter().peekable();
    while let Some(header) = rest.next() {
        let (old_start, old_count, new_start, new_count) = parse_hunk_header(header)?;
        // An empty range names the line before it; any other its first line.
        let old_index = if old_count == 0 {
            old_start
        } else {
            old_start
                .checked_sub(1)
                .context("diff hunk starts before the first line")?
        };
        let new_index = if new_count == 0 {
            new_start
        } else {
            new_start
                .checked_sub(1)
                .context("diff hunk starts before the first line")?
        };
        if old_index < cursor || old_index > old.len() {
            bail!("diff hunks are out of order or out of range");
        }
        for line in &old[cursor..old_index] {
            output.push_str(line);
            written += 1;
        }
        cursor = old_index;
        if written != new_index {
            bail!("diff hunk does not start where the new text is");
        }
        let (mut seen_old, mut seen_new) = (0, 0);
        while seen_old < old_count || seen_new < new_count {
            let line = rest
                .next()
                .context("diff hunk is shorter than its header")?;
            let mut characters = line.chars();
            let tag = characters.next().context("diff line is empty")?;
            let mut content = characters.as_str().to_owned();
            if rest.peek() == Some(&NO_NEWLINE) {
                rest.next();
                if content.pop() != Some('\n') {
                    bail!("diff marks a line without a newline incorrectly");
                }
            } else if !content.ends_with('\n') {
                bail!("diff line is missing its terminator");
            }
            match tag {
                ' ' | '-' => {
                    if old.get(cursor) != Some(&content.as_str()) {
                        bail!("diff does not match the text it is applied to");
                    }
                    cursor += 1;
                    seen_old += 1;
                    if tag == ' ' {
                        output.push_str(&content);
                        written += 1;
                        seen_new += 1;
                    }
                }
                '+' => {
                    output.push_str(&content);
                    written += 1;
                    seen_new += 1;
                }
                _ => bail!("diff line has an unknown prefix"),
            }
            if seen_old > old_count || seen_new > new_count {
                bail!("diff hunk is longer than its header");
            }
        }
    }
    for line in &old[cursor..] {
        output.push_str(line);
    }
    Ok(output)
}

fn parse_hunk_header(line: &str) -> Result<(usize, usize, usize, usize)> {
    let inner = line
        .strip_prefix("@@ -")
        .and_then(|rest| rest.strip_suffix(" @@\n"))
        .context("diff hunk header is malformed")?;
    let (old, new) = inner
        .split_once(" +")
        .context("diff hunk header is malformed")?;
    let range = |range: &str| -> Result<(usize, usize)> {
        let parse = |value: &str| {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                bail!("diff hunk header is malformed");
            }
            value
                .parse::<usize>()
                .context("diff hunk header is malformed")
        };
        match range.split_once(',') {
            Some((start, count)) => Ok((parse(start)?, parse(count)?)),
            None => Ok((parse(range)?, 1)),
        }
    };
    let (old_start, old_count) = range(old)?;
    let (new_start, new_count) = range(new)?;
    if old_count == 0 && new_count == 0 {
        bail!("diff hunk changes nothing");
    }
    Ok((old_start, old_count, new_start, new_count))
}

/// Every file of one record's folder before and after a write, so that
/// recovery can tell which of the two states the folder is in, or that it
/// stopped between them.
///
/// Stored in the pending mutation beside the event. The contents of every
/// file the write changes are staged under `.cr/audit/staged/` before the
/// first file is touched, which is what lets recovery finish a write that
/// stopped partway rather than only recognize it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundlePlan {
    /// The record's folder, relative to the database root.
    pub directory: PathBuf,
    /// The entry file's name inside it.
    pub entry: String,
    /// Every file in the folder on either side of the write, the entry
    /// included, in path order.
    pub files: Vec<PlannedFile>,
}

/// One file of a [`BundlePlan`]: its content hash before and after, `None`
/// where it does not exist.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlannedFile {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

/// Where a record's folder stands relative to a [`BundlePlan`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlanState {
    /// Every file is as it was before the write.
    Before,
    /// Every file is as the write leaves it.
    After,
    /// Every file is in one of its two states, and not all in the same one.
    Partial,
    /// Some file is in neither state, or a file the plan does not name exists.
    Neither,
}

impl BundlePlan {
    /// The plan for moving a folder from `before` to `after`. Each side is the
    /// entry's exact bytes, absent when the record does not exist on that
    /// side, and its supporting files.
    pub(crate) fn new(
        directory: PathBuf,
        entry: &str,
        before: (Option<&[u8]>, &BundleFiles),
        after: (Option<&[u8]>, &BundleFiles),
    ) -> Self {
        let mut files: BTreeMap<String, PlannedFile> = BTreeMap::new();
        let mut side = |entry_bytes: Option<&[u8]>, supporting: &BundleFiles, is_after: bool| {
            let hashes = entry_bytes
                .map(|bytes| (entry.to_owned(), content_hash(bytes)))
                .into_iter()
                .chain(
                    supporting
                        .iter()
                        .map(|(path, file)| (path.clone(), file.hash.clone())),
                );
            for (path, hash) in hashes {
                let planned = files.entry(path.clone()).or_insert_with(|| PlannedFile {
                    path,
                    before: None,
                    after: None,
                });
                if is_after {
                    planned.after = Some(hash);
                } else {
                    planned.before = Some(hash);
                }
            }
        };
        side(before.0, before.1, false);
        side(after.0, after.1, true);
        Self {
            directory,
            entry: entry.to_owned(),
            files: files.into_values().collect(),
        }
    }

    /// Refuse a plan whose folder or entry is not the record's, or that names
    /// a path a bundle cannot hold. Recovery reads plans back from disk.
    pub(crate) fn validate(&self, directory: &Path, entry: &str) -> Result<()> {
        if self.directory != directory || self.entry != entry {
            bail!("pending bundle write does not match its record identity");
        }
        let mut previous: Option<&str> = None;
        for file in &self.files {
            if previous.is_some_and(|previous| previous >= file.path.as_str()) {
                bail!("pending bundle write names a file twice or out of order");
            }
            previous = Some(&file.path);
            if file.path != self.entry {
                validate_file_path(&file.path)?;
            }
            for hash in file.before.iter().chain(file.after.iter()) {
                if !valid_content_hash(hash) {
                    bail!("pending bundle write has a malformed hash");
                }
            }
        }
        Ok(())
    }

    /// Every file this write changes.
    pub(crate) fn changed(&self) -> impl Iterator<Item = &PlannedFile> {
        self.files.iter().filter(|file| file.before != file.after)
    }

    /// The same write in the other direction. Applying it puts back a folder
    /// that a write which failed partway left between its two states, from
    /// the before-contents staged with it.
    pub(crate) fn reversed(&self) -> Self {
        Self {
            directory: self.directory.clone(),
            entry: self.entry.clone(),
            files: self
                .files
                .iter()
                .map(|file| PlannedFile {
                    path: file.path.clone(),
                    before: file.after.clone(),
                    after: file.before.clone(),
                })
                .collect(),
        }
    }

    /// Where the folder stands relative to this plan.
    pub(crate) fn state(&self, root: &Path, label: &str) -> Result<PlanState> {
        let current = self.current(root, label)?;
        let planned: BTreeSet<&str> = self.files.iter().map(|file| file.path.as_str()).collect();
        if current.keys().any(|path| !planned.contains(path.as_str())) {
            return Ok(PlanState::Neither);
        }
        let (mut before, mut after) = (true, true);
        for file in &self.files {
            let hash = current.get(&file.path);
            let at_before = hash == file.before.as_ref();
            let at_after = hash == file.after.as_ref();
            if !at_before && !at_after {
                return Ok(PlanState::Neither);
            }
            before &= at_before;
            after &= at_after;
        }
        Ok(match (before, after) {
            (_, true) => PlanState::After,
            (true, false) => PlanState::Before,
            (false, false) => PlanState::Partial,
        })
    }

    fn current(&self, root: &Path, label: &str) -> Result<BTreeMap<String, String>> {
        // A staged file here is this write's own, mid-publication or left by
        // a crash that recovery clears first; either way not part of a state.
        let Some(stored) = read_bundle(root, &self.directory, &self.entry, label, Staged::Skip)?
        else {
            return Ok(BTreeMap::new());
        };
        let mut current: BTreeMap<String, String> = stored
            .files
            .into_iter()
            .map(|(path, file)| (path, file.hash))
            .collect();
        if let Some(entry) = stored.entry {
            current.insert(self.entry.clone(), content_hash(&entry));
        }
        Ok(current)
    }

    /// Move every file that is still in its before-state to its after-state.
    ///
    /// Removals come first, and then the folders they emptied, so a file can
    /// take the place of a folder and a folder the place of a file. Then the
    /// supporting files are written, and the entry last, so a created or
    /// updated record never appears before its files do, and a deleted one
    /// keeps its entry until its files are gone. A file already in its
    /// after-state is left alone, which is what lets recovery run this again
    /// on a write that stopped partway. `contents` returns the staged bytes
    /// for a content hash.
    pub(crate) fn apply(
        &self,
        root: &Path,
        label: &str,
        contents: impl Fn(&str) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let supporting = |file: &&PlannedFile| file.path != self.entry;
        for file in self
            .files
            .iter()
            .filter(supporting)
            .filter(|file| file.after.is_none())
        {
            self.move_file(root, label, file, &contents)?;
        }

        let mut emptied: BTreeSet<&str> = BTreeSet::new();
        for file in self.files.iter().filter(|file| file.after.is_none()) {
            let mut path = file.path.as_str();
            while let Some((parent, _)) = path.rsplit_once('/') {
                emptied.insert(parent);
                path = parent;
            }
        }
        // Deepest first, so a parent is tried only after its children. An
        // empty folder is no part of a record, so one left behind is untidy
        // rather than wrong, and a write that needs its name clears it.
        let mut emptied: Vec<&str> = emptied.into_iter().collect();
        emptied.sort_by_key(|path| std::cmp::Reverse(path.matches('/').count()));
        for folder in emptied {
            let _ = paths::remove_empty_directory(root, &self.directory.join(folder), label);
        }

        for file in self
            .files
            .iter()
            .filter(supporting)
            .filter(|file| file.after.is_some())
        {
            self.move_file(root, label, file, &contents)?;
        }
        for file in self.files.iter().filter(|file| file.path == self.entry) {
            self.move_file(root, label, file, &contents)?;
        }
        if self.files.iter().all(|file| file.after.is_none()) {
            let _ = paths::remove_empty_directory(root, &self.directory, label);
        }
        Ok(())
    }

    fn move_file(
        &self,
        root: &Path,
        label: &str,
        file: &PlannedFile,
        contents: &impl Fn(&str) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let relative = self.directory.join(&file.path);
        let file_label = if file.path == self.entry {
            label.to_owned()
        } else {
            file_label(label, &file.path)
        };
        // A file in one of this path's folders means the path cannot exist:
        // the shape of the folder has already changed around it.
        let mut blocked = false;
        for folder in prefixes(&file.path).filter(|prefix| *prefix != file.path) {
            match paths::entry_kind(root, &self.directory.join(folder), &file_label)? {
                None | Some(EntryKind::Directory) => {}
                Some(EntryKind::File) => {
                    blocked = true;
                    break;
                }
                Some(kind) => return Err(paths::refuse_entry(&file_label, kind)),
            }
        }
        let current = match (blocked, paths::entry_kind(root, &relative, &file_label)) {
            (true, _) => None,
            (false, kind) => match kind? {
                None => None,
                Some(EntryKind::File) => Some(BundleFile::read(root, &relative, &file_label)?.hash),
                // A folder holding no file is no part of the record: nothing
                // to remove, and a file to be written may take its place.
                Some(EntryKind::Directory) => {
                    if file.after.is_some() {
                        remove_empty_tree(root, &relative, &file_label)?;
                    }
                    None
                }
                Some(kind) => return Err(paths::refuse_entry(&file_label, kind)),
            },
        };
        if current == file.after {
            return Ok(());
        }
        if current != file.before {
            return Err(conflict(format!(
                "{label} changed while it was being written"
            )));
        }
        match (&file.after, current) {
            (Some(hash), None) => {
                let bytes = contents(hash)?;
                paths::write_new(root, &relative, &bytes, &file_label)
            }
            (Some(hash), Some(_)) => {
                let bytes = contents(hash)?;
                paths::write_replace(root, &relative, &bytes, &file_label)
            }
            (None, Some(_)) => paths::remove_file(root, &relative, &file_label),
            (None, None) => Ok(()),
        }
    }
}

/// Remove a folder that holds nothing but folders, refusing one that holds a
/// file of any kind.
fn remove_empty_tree(root: &Path, directory: &Path, label: &str) -> Result<()> {
    for item in paths::list_directory(root, directory, label)?.unwrap_or_default() {
        if !item.kind.is_directory() {
            return Err(conflict(format!(
                "{label} is a folder holding files, where a file is to be written"
            )));
        }
        remove_empty_tree(root, &directory.join(&item.name), label)?;
    }
    paths::remove_empty_directory(root, directory, label)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BundleFile, BundleFiles, BundlePlan, FileChange, PlanState, apply_diff, apply_file_changes,
        content_hash, diff_text, edit_files, file_changes, record_version, validate_file_path,
    };
    use crate::audit::record_hash;
    use std::{collections::HashMap, path::Path};

    fn round_trip(before: &str, after: &str) -> String {
        let diff = diff_text(before, after);
        assert_eq!(apply_diff(before, &diff).unwrap(), after, "diff:\n{diff}");
        diff
    }

    #[test]
    fn diffs_reproduce_both_texts_exactly() {
        round_trip("", "");
        round_trip("", "one\ntwo\n");
        round_trip("one\ntwo\n", "");
        round_trip("one\ntwo", "one\ntwo\n");
        round_trip("one\ntwo\n", "one\ntwo");
        round_trip("a\r\nb\r\n", "a\r\nc\r\n");
        round_trip("a\rb\rc", "a\rB\rc");
        round_trip("x", "y");
        let long: String = (0..100).map(|line| format!("line {line}\n")).collect();
        let edited = long
            .replace("line 10\n", "line ten\n")
            .replace("line 90\n", "");
        let diff = round_trip(&long, &edited);
        assert_eq!(
            diff.matches("@@ -").count(),
            2,
            "two separate hunks:\n{diff}"
        );
        let appended = format!("{long}tail");
        round_trip(&long, &appended);
    }

    #[test]
    fn a_diff_uses_the_familiar_unified_format() {
        assert_eq!(
            diff_text("a\nb\nc\n", "a\nB\nc\n"),
            "@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"
        );
        assert_eq!(
            diff_text("", "print('hi')"),
            "@@ -0,0 +1 @@\n+print('hi')\n\\ No newline at end of file\n"
        );
        assert_eq!(diff_text("same\n", "same\n"), "");
    }

    #[test]
    fn a_changed_region_too_large_to_align_is_still_exact() {
        let before: String = (0..6000).map(|line| format!("{line}\n")).collect();
        let after: String = (0..6000).map(|line| format!("{}\n", line * 7)).collect();
        round_trip(&before, &after);
    }

    #[test]
    fn a_diff_is_refused_against_text_it_does_not_describe() {
        let diff = diff_text("a\nb\nc\n", "a\nB\nc\n");
        assert!(apply_diff("a\nx\nc\n", &diff).is_err());
        assert!(apply_diff("a\nb\nc\n", "@@ -1 +1 @@\n").is_err());
        assert!(apply_diff("a\n", "@@ -1 +1 @@\n?a\n").is_err());
        assert!(apply_diff("a\n", "garbage\n").is_err());
        // Hunks out of order.
        let long: String = (0..40).map(|line| format!("{line}\n")).collect();
        let edited = long.replace("5\n", "five\n").replace("30\n", "thirty\n");
        let diff = diff_text(&long, &edited);
        let hunks: Vec<&str> = diff.split_inclusive("@@ -").collect();
        assert!(hunks.len() >= 3);
    }

    #[test]
    fn file_paths_are_relative_and_plain() {
        for accepted in [
            "scripts/run.py",
            "references/api.md",
            ".hidden",
            "a b/ç.txt",
        ] {
            validate_file_path(accepted).unwrap();
        }
        for refused in [
            "",
            "/etc/passwd",
            "../escape",
            "a/../b",
            "a/./b",
            "a//b",
            "a/",
            "a\\b",
            "line\nbreak",
            "tab\there",
            ".cr-tmp-0123",
            "dir/.cr-tmp-0123",
        ] {
            assert!(validate_file_path(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn a_bundle_without_files_has_its_markdown_s_record_version() {
        let entry = b"---\nname: pdf\n---\nBody\n";
        assert_eq!(
            record_version(entry, &BundleFiles::new()),
            record_hash(entry)
        );
        let mut files = BundleFiles::new();
        files.insert("a.txt".to_owned(), BundleFile::of(b"a"));
        let with_file = record_version(entry, &files);
        assert_ne!(with_file, record_hash(entry));
        files.insert("a.txt".to_owned(), BundleFile::of(b"b"));
        assert_ne!(record_version(entry, &files), with_file);
    }

    #[test]
    fn content_hashes_are_plain_sha256() {
        assert_eq!(
            content_hash(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn file_changes_replay_onto_the_state_they_were_written_against() {
        let mut before = BundleFiles::new();
        before.insert("keep.txt".to_owned(), BundleFile::of(b"same\n"));
        before.insert("script.py".to_owned(), BundleFile::of(b"print(1)\n"));
        before.insert("font.ttf".to_owned(), BundleFile::of(&[0, 1, 2]));
        before.insert("gone.md".to_owned(), BundleFile::of(b"bye\n"));
        let changes = [
            FileChange::Write {
                path: "script.py".to_owned(),
                contents: b"print(2)\n".to_vec(),
            },
            FileChange::Write {
                path: "font.ttf".to_owned(),
                contents: b"now text\n".to_vec(),
            },
            FileChange::Remove {
                path: "gone.md".to_owned(),
            },
            FileChange::Write {
                path: "new/image.png".to_owned(),
                contents: vec![0x89, 0x50, 0, 0],
            },
        ];
        let after = edit_files(&before, &changes, "SKILL.md", "record skills/pdf").unwrap();
        let recorded = file_changes(&before, &after);
        assert_eq!(recorded.len(), 4);
        let binary = recorded
            .iter()
            .find(|change| change.path == "new/image.png")
            .unwrap();
        assert!(binary.diff.is_none());
        let script = recorded
            .iter()
            .find(|change| change.path == "script.py")
            .unwrap();
        assert_eq!(
            script.diff.as_deref(),
            Some("@@ -1 +1 @@\n-print(1)\n+print(2)\n")
        );

        let mut replayed = before.clone();
        apply_file_changes(&mut replayed, &recorded).unwrap();
        assert_eq!(replayed, after);

        let mut forged = recorded.clone();
        let script = forged
            .iter_mut()
            .find(|change| change.path == "script.py")
            .unwrap();
        script.diff = Some("@@ -1 +1 @@\n-print(1)\n+print(3)\n".to_owned());
        assert!(apply_file_changes(&mut before.clone(), &forged).is_err());
    }

    #[test]
    fn requested_file_changes_cannot_shadow_the_entry_or_collide() {
        let current = BundleFiles::new();
        let write = |path: &str| FileChange::Write {
            path: path.to_owned(),
            contents: b"x".to_vec(),
        };
        let edit = |changes: &[FileChange]| edit_files(&current, changes, "SKILL.md", "record");
        assert!(edit(&[write("SKILL.md")]).is_err());
        assert!(edit(&[write("skill.md")]).is_err());
        assert!(edit(&[write("SKILL.md/x")]).is_err());
        assert!(edit(&[write("a"), write("a/b")]).is_err());
        assert!(edit(&[write("Read.me"), write("read.me")]).is_err());
        assert!(edit(&[write("x"), write("x")]).is_err());
        assert!(
            edit(&[FileChange::Remove {
                path: "missing".to_owned()
            }])
            .is_err()
        );
        assert!(edit(&[write("nested/SKILL.md")]).is_ok());
    }

    #[test]
    fn a_plan_moves_a_folder_either_way_between_a_file_and_a_folder() {
        let root = tempfile::tempdir().unwrap();
        let directory = Path::new("records/skills/pdf");
        let skill = root.path().join(directory);
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(skill.join("SKILL.md"), b"one").unwrap();
        std::fs::write(skill.join("d"), b"file").unwrap();
        let label = "record skills/pdf";
        let staged: HashMap<String, Vec<u8>> = [b"file".as_slice(), b"nested".as_slice()]
            .into_iter()
            .map(|bytes| (content_hash(bytes), bytes.to_vec()))
            .collect();
        let contents = |hash: &str| Ok(staged[hash].clone());

        let mut as_file = BundleFiles::new();
        as_file.insert("d".to_owned(), BundleFile::of(b"file"));
        let mut as_folder = BundleFiles::new();
        as_folder.insert("d/x".to_owned(), BundleFile::of(b"nested"));
        let plan = BundlePlan::new(
            directory.to_path_buf(),
            "SKILL.md",
            (Some(b"one"), &as_file),
            (Some(b"one"), &as_folder),
        );
        plan.apply(root.path(), label, contents).unwrap();
        assert_eq!(plan.state(root.path(), label).unwrap(), PlanState::After);
        plan.reversed().apply(root.path(), label, contents).unwrap();
        assert_eq!(plan.state(root.path(), label).unwrap(), PlanState::Before);

        // A write from folder to file that stopped after the file took the
        // folder's place but before the entry: the folder's file cannot exist
        // any more, so finishing counts it as removed rather than failing.
        std::fs::write(skill.join("d"), b"file").unwrap();
        let staged = {
            let mut staged = staged.clone();
            staged.insert(content_hash(b"two"), b"two".to_vec());
            staged
        };
        let to_file = BundlePlan::new(
            directory.to_path_buf(),
            "SKILL.md",
            (Some(b"one"), &as_folder),
            (Some(b"two"), &as_file),
        );
        assert_eq!(
            to_file.state(root.path(), label).unwrap(),
            PlanState::Partial
        );
        to_file
            .apply(root.path(), label, |hash| Ok(staged[hash].clone()))
            .unwrap();
        assert_eq!(to_file.state(root.path(), label).unwrap(), PlanState::After);
    }

    #[test]
    fn a_plan_finishes_a_write_that_stopped_partway() {
        let root = tempfile::tempdir().unwrap();
        let directory = Path::new("records/skills/pdf");
        std::fs::create_dir_all(root.path().join(directory).join("old")).unwrap();
        std::fs::write(root.path().join(directory).join("SKILL.md"), b"one").unwrap();
        std::fs::write(root.path().join(directory).join("old/a.txt"), b"a").unwrap();

        let mut before = BundleFiles::new();
        before.insert("old/a.txt".to_owned(), BundleFile::of(b"a"));
        let mut after = BundleFiles::new();
        after.insert("new/b.txt".to_owned(), BundleFile::of(b"b"));
        let plan = BundlePlan::new(
            directory.to_path_buf(),
            "SKILL.md",
            (Some(b"one"), &before),
            (Some(b"two"), &after),
        );
        let label = "record skills/pdf";
        assert_eq!(plan.state(root.path(), label).unwrap(), PlanState::Before);

        // Only the new file lands before the "crash".
        std::fs::create_dir_all(root.path().join(directory).join("new")).unwrap();
        std::fs::write(root.path().join(directory).join("new/b.txt"), b"b").unwrap();
        assert_eq!(plan.state(root.path(), label).unwrap(), PlanState::Partial);

        let staged: HashMap<String, Vec<u8>> = [b"two".as_slice(), b"b".as_slice()]
            .into_iter()
            .map(|bytes| (content_hash(bytes), bytes.to_vec()))
            .collect();
        plan.apply(root.path(), label, |hash| Ok(staged[hash].clone()))
            .unwrap();
        assert_eq!(plan.state(root.path(), label).unwrap(), PlanState::After);
        assert!(!root.path().join(directory).join("old").exists());
        assert_eq!(
            std::fs::read(root.path().join(directory).join("SKILL.md")).unwrap(),
            b"two"
        );

        std::fs::write(root.path().join(directory).join("stray"), b"?").unwrap();
        assert_eq!(plan.state(root.path(), label).unwrap(), PlanState::Neither);
    }
}
