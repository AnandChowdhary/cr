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
        }
    }

    /// The safe, caller-facing message for this classification.
    pub fn message(&self) -> &str {
        match self {
            Self::NotFound(message)
            | Self::AlreadyExists(message)
            | Self::Conflict(message)
            | Self::Invalid(message) => message,
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
    use super::{conflict, invalid, is_already_exists, is_missing, DomainError};
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
            DomainError::of(&invalid("bad field")).map(DomainError::code),
            Some("validation_failed")
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
