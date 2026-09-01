//! Typed domain errors shared by the CLI and the HTTP server.
//!
//! Domain code keeps returning [`anyhow::Result`] so that no diagnostic context
//! is ever discarded, and attaches a [`DomainError`] whenever a failure has a
//! stable meaning that a caller must be able to act on. Consumers classify with
//! [`DomainError::of`], which walks the error chain and downcasts, rather than
//! matching on message text.
//!
//! The variants deliberately carry an authored message instead of one field per
//! failure site. The message is written where the failure happens, so it names
//! records, views, collections, and fields, and never a filesystem path or an
//! operating-system error. That makes a variant's [`Display`] output the one
//! part of an error chain that is safe to return to a remote caller, while the
//! chain underneath it stays available for logs.

use std::fmt::{self, Display, Formatter};

/// Stable classification for failures that the CLI and the HTTP layer share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainError {
    /// The caller named something that does not exist.
    NotFound(String),
    /// The caller asked to create something that already exists.
    AlreadyExists(String),
    /// The request conflicts with durable record or audit state.
    Conflict(String),
    /// The request is well formed but is not valid for this database.
    Invalid(String),
    /// A change set does not match the digest that was approved for it.
    ///
    /// Deliberately its own variant rather than a [`Self::Conflict`]. It is the
    /// one integrity finding in `cr` that is not about the journal being
    /// damaged, and an auditor has to be able to tell "the change that was
    /// applied is not the change that was approved" apart from "the chain is
    /// corrupt". Sharing a code with every other conflict would bury exactly
    /// the distinction the digest exists to make.
    ApprovalMismatch(String),
}

impl DomainError {
    /// The domain classification carried anywhere in `error`'s chain, if it
    /// has one. This is a typed downcast, never a match on message text.
    pub fn of(error: &anyhow::Error) -> Option<&Self> {
        error.downcast_ref::<Self>()
    }

    /// A stable machine-readable code for this classification.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "not_found",
            Self::AlreadyExists(_) => "already_exists",
            Self::Conflict(_) => "conflict",
            Self::Invalid(_) => "validation_failed",
            Self::ApprovalMismatch(_) => "approval_mismatch",
        }
    }

    /// The safe, caller-facing message for this classification.
    pub fn message(&self) -> &str {
        match self {
            Self::NotFound(message)
            | Self::AlreadyExists(message)
            | Self::Conflict(message)
            | Self::Invalid(message)
            | Self::ApprovalMismatch(message) => message,
        }
    }

    /// A record was requested but is not stored in the database.
    pub fn record_not_found(collection: &str, id: &str) -> Self {
        Self::NotFound(format!("record {collection}/{id} does not exist"))
    }

    /// A record cannot be created because that identity is already taken.
    pub fn record_exists(collection: &str, id: &str) -> Self {
        Self::AlreadyExists(format!("record {collection}/{id} already exists"))
    }

    /// A saved view was requested but is not defined.
    pub fn view_not_found(name: &str) -> Self {
        Self::NotFound(format!("view '{name}' does not exist"))
    }

    /// A saved view cannot be created because that name is already taken.
    pub fn view_exists(name: &str) -> Self {
        Self::AlreadyExists(format!("view '{name}' already exists"))
    }

    /// A Markdown file in a collection's directory cannot be a record, because
    /// its name is not a usable record ID.
    ///
    /// A named constructor rather than a message per call site, because four
    /// paths enumerate a collection directory and the whole point of this
    /// error is that they refuse the same file in the same words. It names the
    /// collection and the filename — the two facts needed to find and fix the
    /// file — and neither is a filesystem path.
    ///
    /// [`Self::Conflict`], not [`Self::Invalid`]: the request is well formed
    /// and it is the database's stored state that is not usable, exactly as
    /// for the entry kinds `paths::refuse_entry` rejects a few lines away. A
    /// client asking for `GET /api/v1/records/deals` did nothing wrong, so
    /// answering `422` would blame the wrong side.
    pub fn invalid_record_name(collection: &str, file_name: &str) -> Self {
        Self::Conflict(format!(
            "collection '{collection}' contains a Markdown file named '{file_name}' whose name cannot be a record ID"
        ))
    }

    /// A Markdown file in a collection's directory has a name that is not
    /// valid UTF-8, so it cannot be a record ID.
    ///
    /// `file_name` is rendered lossily by the caller: the name is by
    /// definition unprintable, and a replacement character in the right place
    /// still tells somebody which file is meant.
    pub fn non_utf8_record_name(collection: &str, file_name: &str) -> Self {
        Self::Conflict(format!(
            "collection '{collection}' contains a Markdown file named '{file_name}' whose name is not valid UTF-8"
        ))
    }

    /// A directory inside the records directory cannot be a collection,
    /// because its name is not a usable path component.
    pub fn invalid_collection_name(directory_name: &str) -> Self {
        Self::Conflict(format!(
            "the records directory contains a directory named '{directory_name}' whose name cannot be a collection"
        ))
    }

    /// A directory inside the records directory has a name that is not valid
    /// UTF-8, so it cannot be a collection.
    pub fn non_utf8_collection_name(directory_name: &str) -> Self {
        Self::Conflict(format!(
            "the records directory contains a directory named '{directory_name}' whose name is not valid UTF-8"
        ))
    }
}

impl Display for DomainError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for DomainError {}

/// Build an invalid-request failure for `bail!`-style returns.
pub(crate) fn invalid(message: impl Display) -> anyhow::Error {
    anyhow::Error::new(DomainError::Invalid(message.to_string()))
}

/// Build a conflicting-state failure for `bail!`-style returns.
pub(crate) fn conflict(message: impl Display) -> anyhow::Error {
    anyhow::Error::new(DomainError::Conflict(message.to_string()))
}

/// Build an approved-change-digest mismatch for `bail!`-style returns.
pub(crate) fn approval_mismatch(message: impl Display) -> anyhow::Error {
    anyhow::Error::new(DomainError::ApprovalMismatch(message.to_string()))
}

/// True when `error` was caused by a missing filesystem entry.
pub(crate) fn is_missing(error: &anyhow::Error) -> bool {
    io_kind_matches(error, std::io::ErrorKind::NotFound)
}

/// True when `error` was caused by a filesystem entry that already exists.
pub(crate) fn is_already_exists(error: &anyhow::Error) -> bool {
    io_kind_matches(error, std::io::ErrorKind::AlreadyExists)
}

fn io_kind_matches(error: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == kind)
    })
}

#[cfg(test)]
mod tests {
    use super::{DomainError, approval_mismatch, conflict, invalid, is_already_exists, is_missing};
    use anyhow::anyhow;

    #[test]
    fn classification_survives_additional_context() {
        let error = anyhow!("could not read /private/records/people/ada.md")
            .context(DomainError::record_not_found("people", "ada"))
            .context("while rendering a view");

        let domain = DomainError::of(&error).expect("classification is preserved");
        assert_eq!(domain.code(), "not_found");
        assert_eq!(domain.message(), "record people/ada does not exist");
        assert!(format!("{error:#}").contains("could not read /private/records/people/ada.md"));
    }

    #[test]
    fn untagged_errors_have_no_classification() {
        assert!(DomainError::of(&anyhow!("could not sync directory")).is_none());
    }

    #[test]
    fn codes_and_messages_are_stable_per_variant() {
        assert_eq!(
            DomainError::record_exists("people", "ada").code(),
            "already_exists"
        );
        assert_eq!(DomainError::view_not_found("board").code(), "not_found");
        assert_eq!(
            DomainError::view_exists("board").message(),
            "view 'board' already exists"
        );
        assert_eq!(conflict("stale").to_string(), "stale");
        assert_eq!(
            DomainError::of(&approval_mismatch("not approved")).map(DomainError::code),
            Some("approval_mismatch")
        );
        assert_eq!(
            DomainError::of(&invalid("bad field")).map(DomainError::code),
            Some("validation_failed")
        );
    }

    #[test]
    fn unusable_stored_names_are_conflicts_naming_the_file_and_its_collection() {
        let bad_id = DomainError::invalid_record_name("deals", "..md");
        assert_eq!(bad_id.code(), "conflict");
        assert_eq!(
            bad_id.message(),
            "collection 'deals' contains a Markdown file named '..md' whose name cannot be a record ID"
        );
        assert!(!bad_id.message().contains('/'), "{bad_id}");

        let bad_utf8 = DomainError::non_utf8_record_name("deals", "bad\u{fffd}.md");
        assert_eq!(bad_utf8.code(), "conflict");
        assert!(bad_utf8.message().contains("not valid UTF-8"), "{bad_utf8}");

        assert_eq!(
            DomainError::invalid_collection_name("..").message(),
            "the records directory contains a directory named '..' whose name cannot be a collection"
        );
        assert_eq!(
            DomainError::non_utf8_collection_name("bad\u{fffd}").code(),
            "conflict"
        );
    }

    #[test]
    fn filesystem_causes_are_detected_by_kind_not_message() {
        let missing = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("could not read record");
        assert!(is_missing(&missing));
        assert!(!is_already_exists(&missing));

        let taken = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
        assert!(is_already_exists(&taken));
        assert!(!is_missing(&taken));
    }
}
