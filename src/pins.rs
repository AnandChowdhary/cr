//! Filesystem locations a database owner pins to the file browser's sidebar.
//!
//! Pins are configuration, like saved views: a Git-friendly file under `.cr/`
//! that people may edit by hand, not records with audit history. They exist so
//! the handful of places an owner keeps returning to — a log directory, a skill
//! folder, one configuration file — are one click away instead of a walk down
//! from the database root every time.

use std::{
    fs::File,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    AccessResource, Database,
    error::{DomainError, invalid},
    paths::{self, EntryKind},
};

/// Where pins live beneath the database root.
pub(crate) const PINS_PATH: &str = ".cr/pins.yaml";
const PINS_LABEL: &str = "the pinned locations";

/// Serializes read-modify-write of the pins file.
///
/// The pins are one ordered list in one file, so two concurrent pins would
/// otherwise both read the old list and the second write would silently drop
/// the first. Views avoid this by being one file each; a list whose order is
/// the sidebar's order cannot.
const PINS_LOCK_PATH: &str = ".cr/pins.lock";
const PINS_LOCK_LABEL: &str = "the pinned locations lock";

const PINS_FORMAT_VERSION: u32 = 1;

/// A sidebar is navigation, not a bookmark manager. Past this many entries it
/// stops being quicker than browsing, and every page render pays for each one.
const MAX_PINS: usize = 50;
const MAX_LABEL_CHARS: usize = 80;

/// One pinned filesystem location.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// The location as stored: relative to the database root when it lies
    /// inside it, absolute otherwise. See [`Database::pin`].
    pub path: String,
    /// What the sidebar shows instead of the location's own name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Pin {
    /// The absolute location this pin names, without touching the filesystem.
    pub fn location(&self, root: &Path) -> PathBuf {
        normalize(&root.join(&self.path))
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredPins {
    version: u32,
    #[serde(default)]
    pins: Vec<Pin>,
}

impl Database {
    /// The pinned locations, in sidebar order.
    ///
    /// Owner-only, like the file browser itself: the list is a map of where on
    /// this host an administrator looks, which is not something a collection
    /// grant should reveal.
    pub fn pins(&self) -> Result<Vec<Pin>> {
        self.authorize_owner(&AccessResource::Database)?;
        self.read_pins()
    }

    /// Pin a location, or relabel it if it is already pinned.
    ///
    /// `path` may be absolute or relative to the database root, and is
    /// normalized lexically — `.` and `..` resolved without consulting the
    /// filesystem — so `docs/../logs` and `logs` are one pin, and a location
    /// that does not exist yet can still be pinned. A location inside the
    /// database is stored relative to it. `.cr/` travels with the database in
    /// Git, and a pin written as `/home/alice/crm/docs` would point nowhere in
    /// anyone else's clone, where `docs` points at the same folder.
    pub fn pin(&self, path: &str, label: Option<&str>) -> Result<Pin> {
        self.authorize_owner(&AccessResource::Database)?;
        let pin = Pin {
            path: self.stored_pin_path(path)?,
            label: pin_label(label)?,
        };
        let _lock = self.lock_pins()?;
        let mut pins = self.read_pins()?;
        if let Some(existing) = pins.iter_mut().find(|existing| existing.path == pin.path) {
            // Pinning again is how a label is changed, and pinning again with no
            // label keeps the one it has rather than erasing it by accident.
            if pin.label.is_none() || existing.label == pin.label {
                return Ok(existing.clone());
            }
            existing.label = pin.label.clone();
        } else {
            if pins.len() >= MAX_PINS {
                return Err(invalid(format!(
                    "at most {MAX_PINS} locations can be pinned; unpin one first"
                )));
            }
            pins.push(pin.clone());
        }
        self.write_pins(&pins)?;
        Ok(pin)
    }

    /// Unpin a location, reporting whether it was pinned.
    ///
    /// The location is normalized exactly as [`Self::pin`] normalizes it, so
    /// whatever spelling pinned it also unpins it.
    pub fn unpin(&self, path: &str) -> Result<bool> {
        self.authorize_owner(&AccessResource::Database)?;
        let stored = self.stored_pin_path(path)?;
        let _lock = self.lock_pins()?;
        let mut pins = self.read_pins()?;
        let before = pins.len();
        pins.retain(|pin| pin.path != stored);
        if pins.len() == before {
            return Ok(false);
        }
        self.write_pins(&pins)?;
        Ok(true)
    }

    fn stored_pin_path(&self, requested: &str) -> Result<String> {
        let requested = requested.trim();
        if requested.is_empty() {
            return Err(invalid("a pinned path cannot be empty"));
        }
        if requested.contains('\0') {
            return Err(invalid("a pinned path cannot contain a NUL byte"));
        }
        let location = normalize(&self.root().join(requested));
        let stored = match self.inside_database(&location) {
            Some(relative) if relative.as_os_str().is_empty() => Path::new("."),
            Some(relative) => relative,
            None => location.as_path(),
        };
        // The browser addresses locations by URL, which has no spelling for a
        // path that is not UTF-8; a pin that could never be opened is refused
        // here rather than listed as a link that goes nowhere.
        stored
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("a pinned path must be valid UTF-8"))
    }

    /// Where `location` lies inside the database, if it does.
    ///
    /// The root is canonical, but the path someone types need not spell it that
    /// way: macOS reaches every temporary directory through `/var`, a link to
    /// `/private/var`, and a home directory can sit behind a link too. So after
    /// the plain prefix test, each ancestor is canonicalized in turn and the
    /// first that *is* the root marks where the in-database part begins. Only
    /// that prefix is resolved; a link inside the database stays a link.
    fn inside_database<'a>(&self, location: &'a Path) -> Option<&'a Path> {
        if let Ok(relative) = location.strip_prefix(self.root()) {
            return Some(relative);
        }
        location.ancestors().find_map(|ancestor| {
            let canonical = std::fs::canonicalize(ancestor).ok()?;
            if canonical == self.root() {
                location.strip_prefix(ancestor).ok()
            } else {
                None
            }
        })
    }

    fn read_pins(&self) -> Result<Vec<Pin>> {
        let Some(serialized) =
            paths::read_to_string_optional(self.root(), Path::new(PINS_PATH), PINS_LABEL)?
        else {
            return Ok(Vec::new());
        };
        let stored: StoredPins = yaml_serde::from_str(&serialized).with_context(|| {
            DomainError::Invalid(format!("{PINS_PATH} is not a valid pins file"))
        })?;
        if stored.version != PINS_FORMAT_VERSION {
            return Err(invalid(format!(
                "{PINS_PATH} uses unsupported format version {} (expected {PINS_FORMAT_VERSION})",
                stored.version
            )));
        }
        Ok(stored.pins)
    }

    fn write_pins(&self, pins: &[Pin]) -> Result<()> {
        let stored = StoredPins {
            version: PINS_FORMAT_VERSION,
            pins: pins.to_vec(),
        };
        let serialized = yaml_serde::to_string(&stored).context("could not serialize pins")?;
        let path = Path::new(PINS_PATH);
        match paths::entry_kind(self.root(), path, PINS_LABEL)? {
            Some(EntryKind::File) => {
                paths::write_replace(self.root(), path, serialized.as_bytes(), PINS_LABEL)
            }
            Some(kind) => Err(paths::refuse_entry(PINS_LABEL, kind)),
            None => paths::write_new(self.root(), path, serialized.as_bytes(), PINS_LABEL),
        }
    }

    fn lock_pins(&self) -> Result<File> {
        let lock = paths::open_lock_file(self.root(), Path::new(PINS_LOCK_PATH), PINS_LOCK_LABEL)?;
        lock.lock().context("could not lock the pinned locations")?;
        Ok(lock)
    }
}

fn pin_label(label: Option<&str>) -> Result<Option<String>> {
    let Some(label) = label.map(str::trim).filter(|label| !label.is_empty()) else {
        return Ok(None);
    };
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err(invalid(format!(
            "a pin label can be at most {MAX_LABEL_CHARS} characters"
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(invalid("a pin label cannot contain control characters"));
    }
    Ok(Some(label.to_owned()))
}

/// Resolve `.` and `..` lexically.
///
/// Deliberately not `canonicalize`: a pin names a location, which may not
/// exist yet and may be a symbolic link the owner wants to keep following
/// rather than have frozen to today's target.
fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}
