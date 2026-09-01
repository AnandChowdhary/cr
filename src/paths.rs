//! Symlink-safe access to files beneath a database root.
//!
//! Every file `cr` reads or writes lives beneath one canonicalized database
//! root. Anybody who can create an entry inside that directory—a sync adapter,
//! a synchronized checkout, an editor, or a hostile local process—must not be
//! able to make the database follow a symbolic link out of it. A path is
//! therefore never handed to the operating system as a single string. Each
//! component is opened relative to its already-verified parent with
//! `O_NOFOLLOW`, and the file itself is opened, replaced, or removed through
//! that parent's descriptor.
//!
//! Two properties follow. A planted symbolic link anywhere between the root and
//! the target is refused instead of followed, whatever it points at. And
//! because reads and writes use the descriptor the walk produced, a link
//! swapped in after the walk cannot redirect them: the check and the operation
//! are the same act rather than two racing ones.
//!
//! Directory *listings* still use the resolved path, because a listing is never
//! trusted on its own—every name it yields is reopened through this module
//! before it is read.
//!
//! Platforms without `openat` fall back to checking each component with
//! `symlink_metadata` before descending. That refuses the same planted links but
//! keeps a check-then-use window, so the strong guarantee above is a Unix one.

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};

use crate::error::{DomainError, is_missing};

/// Names of files this module writes before publishing them under their final
/// name. The prefix keeps them out of every extension-filtered listing.
const TEMPORARY_PREFIX: &str = ".cr-tmp-";

/// What a directory entry is, determined without following symbolic links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

impl EntryKind {
    pub(crate) fn is_directory(self) -> bool {
        self == Self::Directory
    }

    pub(crate) fn is_file(self) -> bool {
        self == Self::File
    }
}

/// One entry of a verified directory.
pub(crate) struct DirectoryEntry {
    pub name: OsString,
    pub kind: EntryKind,
}

/// Open the directory `relative` beneath `root`, refusing to traverse a
/// symbolic link at any depth.
///
/// `label` names the thing the caller wanted in words a remote caller may see;
/// it must never contain a filesystem path.
pub(crate) fn open_directory(root: &Path, relative: &Path, label: &str) -> Result<Directory> {
    let mut directory =
        Directory::open_root(root).with_context(|| format!("could not open {label}"))?;
    for name in components(relative)? {
        directory = match directory.open_child_directory(name) {
            Ok(child) => child,
            Err(error) => return Err(directory_failure(&directory, name, error, label)),
        };
    }
    Ok(directory)
}

/// Like [`open_directory`], reporting a directory that does not exist as
/// `None` while still refusing a symbolic link.
pub(crate) fn open_directory_optional(
    root: &Path,
    relative: &Path,
    label: &str,
) -> Result<Option<Directory>> {
    match open_directory(root, relative, label) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if is_missing(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Create every missing component of `relative` beneath `root` and open it,
/// refusing to traverse a symbolic link at any depth.
pub(crate) fn create_directory_all(root: &Path, relative: &Path, label: &str) -> Result<Directory> {
    let mut directory =
        Directory::open_root(root).with_context(|| format!("could not open {label}"))?;
    for name in components(relative)? {
        directory = match directory.open_child_directory(name) {
            Ok(child) => child,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match directory.create_child_directory(name) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(anyhow!(error).context(format!("could not create {label}")));
                    }
                }
                directory
                    .open_child_directory(name)
                    .map_err(|error| directory_failure(&directory, name, error, label))?
            }
            Err(error) => return Err(directory_failure(&directory, name, error, label)),
        };
    }
    Ok(directory)
}

/// The kind of `relative` beneath `root`, or `None` when nothing is there.
///
/// A symbolic link is reported as [`EntryKind::Symlink`] rather than refused,
/// so callers can decide whether its presence is an error or a missing entry.
pub(crate) fn entry_kind(root: &Path, relative: &Path, label: &str) -> Result<Option<EntryKind>> {
    let (parent, name) = split_parent(relative)?;
    let Some(directory) = open_directory_optional(root, parent, label)? else {
        return Ok(None);
    };
    match directory.child_kind(name) {
        Ok(kind) => Ok(Some(kind)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(anyhow!(error).context(format!("could not inspect {label}"))),
    }
}

/// List a verified directory, or report `None` when it does not exist.
///
/// Entry kinds come from the directory itself and never follow a symbolic
/// link, so a linked entry is visible as [`EntryKind::Symlink`] instead of
/// masquerading as the thing it points at.
pub(crate) fn list_directory(
    root: &Path,
    relative: &Path,
    label: &str,
) -> Result<Option<Vec<DirectoryEntry>>> {
    let Some(directory) = open_directory_optional(root, relative, label)? else {
        return Ok(None);
    };
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(directory.resolved())
        .with_context(|| format!("could not read {label}"))?
    {
        let entry = entry.with_context(|| format!("could not read {label}"))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("could not inspect an entry of {label}"))?;
        let kind = if file_type.is_symlink() {
            EntryKind::Symlink
        } else if file_type.is_dir() {
            EntryKind::Directory
        } else if file_type.is_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        };
        entries.push(DirectoryEntry {
            name: entry.file_name(),
            kind,
        });
    }
    Ok(Some(entries))
}

/// Open `relative` beneath `root` for reading, refusing a symbolic link at any
/// depth and refusing anything that is not a regular file.
pub(crate) fn open_file(root: &Path, relative: &Path, label: &str) -> Result<File> {
    let (parent, name) = split_parent(relative)?;
    let directory = open_directory(root, parent, label)?;
    open_regular_file(&directory, name, label)
}

/// Read `relative` beneath `root` exactly, through a verified descriptor.
pub(crate) fn read(root: &Path, relative: &Path, label: &str) -> Result<Vec<u8>> {
    let mut file = open_file(root, relative, label)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .with_context(|| format!("could not read {label}"))?;
    Ok(contents)
}

/// The exact size of `relative` beneath `root`, measured on the descriptor the
/// safe walk produced rather than on a path that could be swapped.
pub(crate) fn file_length(root: &Path, relative: &Path, label: &str) -> Result<u64> {
    Ok(open_file(root, relative, label)?
        .metadata()
        .with_context(|| format!("could not inspect {label}"))?
        .len())
}

/// Like [`read`], reporting a missing file as `None`.
pub(crate) fn read_optional(root: &Path, relative: &Path, label: &str) -> Result<Option<Vec<u8>>> {
    match read(root, relative, label) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if is_missing(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Read `relative` beneath `root` as UTF-8, through a verified descriptor.
pub(crate) fn read_to_string(root: &Path, relative: &Path, label: &str) -> Result<String> {
    let contents = read(root, relative, label)?;
    String::from_utf8(contents)
        .with_context(|| DomainError::Invalid(format!("{label} is not valid UTF-8")))
}

/// Like [`read_to_string`], reporting a missing file as `None`.
pub(crate) fn read_to_string_optional(
    root: &Path,
    relative: &Path,
    label: &str,
) -> Result<Option<String>> {
    match read_to_string(root, relative, label) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if is_missing(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Publish `contents` as `relative` beneath `root` without ever replacing an
/// existing entry, creating missing parent directories safely.
///
/// The failure for an entry that already exists carries an
/// [`io::ErrorKind::AlreadyExists`] cause so callers can classify it.
pub(crate) fn write_new(root: &Path, relative: &Path, contents: &[u8], label: &str) -> Result<()> {
    let (parent, name) = split_parent(relative)?;
    let directory = create_directory_all(root, parent, label)?;
    let (temporary, _staged) = staged_file(&directory, contents, label)?;
    let result = directory
        .link_child(&temporary, name)
        .map_err(|error| anyhow!(error).context(format!("could not create {label}")));
    let _ = directory.unlink_child(&temporary);
    result?;
    directory
        .sync()
        .with_context(|| format!("could not sync the directory holding {label}"))
}

/// Replace an existing regular file `relative` beneath `root` atomically,
/// preserving its permissions.
pub(crate) fn write_replace(
    root: &Path,
    relative: &Path,
    contents: &[u8],
    label: &str,
) -> Result<()> {
    let (parent, name) = split_parent(relative)?;
    let directory = open_directory(root, parent, label)?;
    let permissions = open_regular_file(&directory, name, label)?
        .metadata()
        .with_context(|| format!("could not inspect {label}"))?
        .permissions();
    let (temporary, staged) = staged_file(&directory, contents, label)?;
    let result = staged
        .set_permissions(permissions)
        .with_context(|| format!("could not preserve permissions for {label}"))
        .and_then(|()| {
            directory
                .rename_child(&temporary, name)
                .map_err(|error| anyhow!(error).context(format!("could not replace {label}")))
        });
    if result.is_err() {
        let _ = directory.unlink_child(&temporary);
    }
    result?;
    directory
        .sync()
        .with_context(|| format!("could not sync the directory holding {label}"))
}

/// Remove a regular file `relative` beneath `root`, refusing a symbolic link.
pub(crate) fn remove_file(root: &Path, relative: &Path, label: &str) -> Result<()> {
    let (parent, name) = split_parent(relative)?;
    let directory = open_directory(root, parent, label)?;
    match directory.child_kind(name) {
        Ok(EntryKind::File) => {}
        Ok(kind) => {
            return Err(located(
                refuse_entry(label, kind),
                &directory.path().join(name),
            ));
        }
        Err(error) => return Err(anyhow!(error).context(format!("could not inspect {label}"))),
    }
    directory
        .unlink_child(name)
        .map_err(|error| anyhow!(error).context(format!("could not delete {label}")))?;
    directory
        .sync()
        .with_context(|| format!("could not sync the directory holding {label}"))
}

/// Open, creating if needed, a lock file beneath `root` without following a
/// symbolic link and without truncating existing content.
pub(crate) fn open_lock_file(root: &Path, relative: &Path, label: &str) -> Result<File> {
    let (parent, name) = split_parent(relative)?;
    let directory = create_directory_all(root, parent, label)?;
    let lock = directory
        .open_or_create_child_file(name)
        .map_err(|error| lock_failure(&directory, name, error, label))?;
    if !lock
        .metadata()
        .with_context(|| format!("could not inspect {label}"))?
        .file_type()
        .is_file()
    {
        return Err(refuse_not_regular(label));
    }
    Ok(lock)
}

/// Refuse an entry that exists but is not the regular file it must be,
/// naming a symbolic link as such so the operator can find the cause.
pub(crate) fn refuse_entry(label: &str, kind: EntryKind) -> anyhow::Error {
    match kind {
        EntryKind::Symlink => refuse_symlink(label),
        _ => refuse_not_regular(label),
    }
}

/// Write `contents` into a fresh uniquely named file inside `directory`,
/// returning its name and its still-open descriptor.
fn staged_file(directory: &Directory, contents: &[u8], label: &str) -> Result<(OsString, File)> {
    let name = temporary_name()?;
    let mut file = directory
        .create_child_file(&name)
        .map_err(|error| anyhow!(error).context(format!("could not stage {label}")))?;
    let staged = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("could not stage {label}"));
    if staged.is_err() {
        let _ = directory.unlink_child(&name);
    }
    staged?;
    Ok((name, file))
}

fn open_regular_file(directory: &Directory, name: &OsStr, label: &str) -> Result<File> {
    let file = directory
        .open_child_file(name)
        .map_err(|error| file_failure(directory, name, error, label))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect {label}"))?;
    if !metadata.file_type().is_file() {
        return Err(located(
            refuse_not_regular(label),
            &directory.path().join(name),
        ));
    }
    Ok(file)
}

/// The components of a database-relative path, rejecting anything that is not
/// a plain name.
fn components(relative: &Path) -> Result<Vec<&OsStr>> {
    relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(anyhow!(
                "a database path must be relative and contain no '.' or '..'"
            )),
        })
        .collect()
}

fn split_parent(relative: &Path) -> Result<(&Path, &OsStr)> {
    let names = components(relative)?;
    let name = *names.last().context("a database path must name a file")?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    Ok((parent, name))
}

fn temporary_name() -> Result<OsString> {
    use std::fmt::Write as _;

    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow!("could not generate a temporary filename: {error}"))?;
    let mut name = String::from(TEMPORARY_PREFIX);
    for byte in bytes {
        write!(&mut name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(OsString::from(name))
}

/// A refusal to follow a symbolic link. The classified message a caller sees
/// names only the record, view, or directory; the resolved location stays
/// underneath it in the chain, for the server log and the CLI.
fn refuse_symlink(label: &str) -> anyhow::Error {
    anyhow::Error::new(DomainError::Conflict(format!(
        "{label} is stored behind a symbolic link, which the database refuses to follow"
    )))
}

fn refuse_not_directory(label: &str) -> anyhow::Error {
    anyhow::Error::new(DomainError::Conflict(format!(
        "{label} is not stored under a directory inside the database"
    )))
}

fn refuse_not_regular(label: &str) -> anyhow::Error {
    anyhow::Error::new(DomainError::Conflict(format!(
        "{label} is not a regular file"
    )))
}

/// Attach where a refusal happened without letting it reach a caller.
fn located(error: anyhow::Error, location: &Path) -> anyhow::Error {
    let Some(domain) = DomainError::of(&error).cloned() else {
        return error;
    };
    anyhow!("at {}", location.display()).context(domain)
}

/// Explain why descending into `name` failed, naming a refused symbolic link
/// where that is the reason and otherwise keeping the operating-system cause.
fn directory_failure(
    parent: &Directory,
    name: &OsStr,
    error: io::Error,
    label: &str,
) -> anyhow::Error {
    let location = parent.path().join(name);
    match parent.child_kind(name) {
        Ok(EntryKind::Symlink) => located(refuse_symlink(label), &location),
        Ok(EntryKind::File | EntryKind::Other) => located(refuse_not_directory(label), &location),
        _ => anyhow!(error).context(format!("could not read {label} at {}", location.display())),
    }
}

fn file_failure(parent: &Directory, name: &OsStr, error: io::Error, label: &str) -> anyhow::Error {
    let location = parent.path().join(name);
    match parent.child_kind(name) {
        Ok(EntryKind::Symlink) => located(refuse_symlink(label), &location),
        Ok(EntryKind::Directory | EntryKind::Other) => {
            located(refuse_not_regular(label), &location)
        }
        _ => anyhow!(error).context(format!("could not read {label} at {}", location.display())),
    }
}

fn lock_failure(parent: &Directory, name: &OsStr, error: io::Error, label: &str) -> anyhow::Error {
    let location = parent.path().join(name);
    match parent.child_kind(name) {
        Ok(EntryKind::Symlink) => located(refuse_symlink(label), &location),
        Ok(EntryKind::Directory | EntryKind::Other) => {
            located(refuse_not_regular(label), &location)
        }
        _ => anyhow!(error).context(format!("could not open {label} at {}", location.display())),
    }
}

impl Directory {
    /// The resolved path of this directory, for listings and diagnostics.
    pub(crate) fn path(&self) -> &Path {
        self.resolved()
    }
}

/// A directory that has been reached without following a symbolic link.
///
/// On Unix this owns the directory's descriptor, so every operation performed
/// through it acts on the directory the walk verified rather than on whatever a
/// path would resolve to now.
#[cfg(unix)]
pub(crate) struct Directory {
    descriptor: std::os::fd::OwnedFd,
    path: PathBuf,
}

#[cfg(unix)]
mod unix {
    use std::{
        ffi::{CString, OsStr},
        fs::File,
        io,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::ffi::OsStrExt,
        },
        path::Path,
    };

    use super::{Directory, EntryKind};

    /// Flags shared by every open: never follow a final symbolic link, never
    /// leak the descriptor across an exec, and never block on a named pipe.
    const SAFE_FLAGS: libc::c_int = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    const PRIVATE_MODE: libc::mode_t = 0o600;

    fn terminated(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::other("a database path cannot contain a NUL byte"))
    }

    fn checked(result: libc::c_int) -> io::Result<libc::c_int> {
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }

    impl Directory {
        pub(super) fn open_root(path: &Path) -> io::Result<Self> {
            let name = terminated(path.as_os_str())?;
            // SAFETY: `name` is a valid NUL-terminated string that outlives the
            // call, and the returned descriptor is immediately owned.
            let descriptor = checked(unsafe {
                libc::open(
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            })?;
            // SAFETY: `descriptor` is a fresh, valid, unowned descriptor.
            let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
            Ok(Self {
                descriptor,
                path: path.to_path_buf(),
            })
        }

        fn open_child(
            &self,
            name: &OsStr,
            flags: libc::c_int,
            mode: libc::mode_t,
        ) -> io::Result<OwnedFd> {
            let terminated = terminated(name)?;
            // SAFETY: `terminated` outlives the call and `self.descriptor` is a
            // valid open directory descriptor; the result is immediately owned.
            let descriptor = checked(unsafe {
                libc::openat(
                    self.descriptor.as_raw_fd(),
                    terminated.as_ptr(),
                    flags | SAFE_FLAGS,
                    mode as libc::c_int,
                )
            })?;
            // SAFETY: `descriptor` is a fresh, valid, unowned descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
        }

        pub(super) fn open_child_directory(&self, name: &OsStr) -> io::Result<Self> {
            let descriptor = self.open_child(name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            Ok(Self {
                descriptor,
                path: self.path.join(name),
            })
        }

        pub(super) fn create_child_directory(&self, name: &OsStr) -> io::Result<()> {
            let terminated = terminated(name)?;
            // SAFETY: `terminated` outlives the call and `self.descriptor` is a
            // valid open directory descriptor.
            checked(unsafe {
                libc::mkdirat(self.descriptor.as_raw_fd(), terminated.as_ptr(), 0o777)
            })
            .map(|_| ())
        }

        pub(super) fn open_child_file(&self, name: &OsStr) -> io::Result<File> {
            self.open_child(name, libc::O_RDONLY, 0).map(File::from)
        }

        pub(super) fn create_child_file(&self, name: &OsStr) -> io::Result<File> {
            self.open_child(
                name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                PRIVATE_MODE,
            )
            .map(File::from)
        }

        pub(super) fn open_or_create_child_file(&self, name: &OsStr) -> io::Result<File> {
            self.open_child(name, libc::O_RDWR | libc::O_CREAT, PRIVATE_MODE)
                .map(File::from)
        }

        pub(super) fn child_kind(&self, name: &OsStr) -> io::Result<EntryKind> {
            let terminated = terminated(name)?;
            let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: `terminated` outlives the call, `self.descriptor` is a
            // valid open directory descriptor, and `status` is writable and
            // correctly sized for one `struct stat`.
            checked(unsafe {
                libc::fstatat(
                    self.descriptor.as_raw_fd(),
                    terminated.as_ptr(),
                    status.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })?;
            // SAFETY: `fstatat` succeeded, so `status` is initialized.
            let status = unsafe { status.assume_init() };
            Ok(match status.st_mode & libc::S_IFMT {
                libc::S_IFDIR => EntryKind::Directory,
                libc::S_IFREG => EntryKind::File,
                libc::S_IFLNK => EntryKind::Symlink,
                _ => EntryKind::Other,
            })
        }

        pub(super) fn rename_child(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
            let from = terminated(from)?;
            let to = terminated(to)?;
            // SAFETY: both names outlive the call and `self.descriptor` is a
            // valid open directory descriptor.
            checked(unsafe {
                libc::renameat(
                    self.descriptor.as_raw_fd(),
                    from.as_ptr(),
                    self.descriptor.as_raw_fd(),
                    to.as_ptr(),
                )
            })
            .map(|_| ())
        }

        pub(super) fn link_child(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
            let from = terminated(from)?;
            let to = terminated(to)?;
            // SAFETY: both names outlive the call and `self.descriptor` is a
            // valid open directory descriptor.
            checked(unsafe {
                libc::linkat(
                    self.descriptor.as_raw_fd(),
                    from.as_ptr(),
                    self.descriptor.as_raw_fd(),
                    to.as_ptr(),
                    0,
                )
            })
            .map(|_| ())
        }

        pub(super) fn unlink_child(&self, name: &OsStr) -> io::Result<()> {
            let terminated = terminated(name)?;
            // SAFETY: `terminated` outlives the call and `self.descriptor` is a
            // valid open directory descriptor.
            checked(unsafe { libc::unlinkat(self.descriptor.as_raw_fd(), terminated.as_ptr(), 0) })
                .map(|_| ())
        }

        pub(super) fn sync(&self) -> io::Result<()> {
            // SAFETY: `self.descriptor` is a valid open directory descriptor.
            checked(unsafe { libc::fsync(self.descriptor.as_raw_fd()) }).map(|_| ())
        }

        pub(super) fn resolved(&self) -> &Path {
            &self.path
        }
    }
}

/// The portable fallback used where `openat` is unavailable.
///
/// It refuses the same planted symbolic links by checking every component
/// before descending, but the check and the use are separate acts, so it does
/// not close the race that the Unix implementation closes.
#[cfg(not(unix))]
pub(crate) struct Directory {
    path: PathBuf,
}

#[cfg(not(unix))]
mod portable {
    use std::{
        ffi::OsStr,
        fs::{File, OpenOptions},
        io,
        path::{Path, PathBuf},
    };

    use super::{Directory, EntryKind};

    fn kind_of(path: &Path) -> io::Result<EntryKind> {
        let metadata = std::fs::symlink_metadata(path)?;
        let file_type = metadata.file_type();
        Ok(if file_type.is_symlink() {
            EntryKind::Symlink
        } else if file_type.is_dir() {
            EntryKind::Directory
        } else if file_type.is_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        })
    }

    impl Directory {
        pub(super) fn open_root(path: &Path) -> io::Result<Self> {
            match kind_of(path)? {
                EntryKind::Directory => Ok(Self {
                    path: path.to_path_buf(),
                }),
                _ => Err(io::Error::other("the database root is not a directory")),
            }
        }

        pub(super) fn open_child_directory(&self, name: &OsStr) -> io::Result<Self> {
            let path = self.path.join(name);
            match kind_of(&path)? {
                EntryKind::Directory => Ok(Self { path }),
                EntryKind::Symlink => Err(io::Error::other("component is a symbolic link")),
                _ => Err(io::Error::other("component is not a directory")),
            }
        }

        pub(super) fn create_child_directory(&self, name: &OsStr) -> io::Result<()> {
            std::fs::create_dir(self.path.join(name))
        }

        fn checked_child(&self, name: &OsStr) -> io::Result<PathBuf> {
            let path = self.path.join(name);
            match kind_of(&path) {
                Ok(EntryKind::Symlink) => Err(io::Error::other("entry is a symbolic link")),
                Ok(_) => Ok(path),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
                Err(error) => Err(error),
            }
        }

        pub(super) fn open_child_file(&self, name: &OsStr) -> io::Result<File> {
            File::open(self.checked_child(name)?)
        }

        pub(super) fn create_child_file(&self, name: &OsStr) -> io::Result<File> {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.checked_child(name)?)
        }

        pub(super) fn open_or_create_child_file(&self, name: &OsStr) -> io::Result<File> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(self.checked_child(name)?)
        }

        pub(super) fn child_kind(&self, name: &OsStr) -> io::Result<EntryKind> {
            kind_of(&self.path.join(name))
        }

        pub(super) fn rename_child(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
            std::fs::rename(self.checked_child(from)?, self.checked_child(to)?)
        }

        pub(super) fn link_child(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
            std::fs::hard_link(self.checked_child(from)?, self.checked_child(to)?)
        }

        pub(super) fn unlink_child(&self, name: &OsStr) -> io::Result<()> {
            std::fs::remove_file(self.checked_child(name)?)
        }

        pub(super) fn sync(&self) -> io::Result<()> {
            Ok(())
        }

        pub(super) fn resolved(&self) -> &Path {
            &self.path
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EntryKind, create_directory_all, list_directory, open_directory, read_to_string,
        read_to_string_optional, remove_file, write_new, write_replace,
    };
    use crate::error::DomainError;
    use std::path::Path;

    fn classification(error: &anyhow::Error) -> Option<&'static str> {
        DomainError::of(error).map(DomainError::code)
    }

    #[test]
    fn plain_files_round_trip_through_verified_directories() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        write_new(root, Path::new("a/b/note.md"), b"first", "the note").unwrap();
        assert_eq!(
            read_to_string(root, Path::new("a/b/note.md"), "the note").unwrap(),
            "first"
        );

        write_replace(root, Path::new("a/b/note.md"), b"second", "the note").unwrap();
        assert_eq!(
            read_to_string(root, Path::new("a/b/note.md"), "the note").unwrap(),
            "second"
        );

        let entries = list_directory(root, Path::new("a/b"), "the directory")
            .unwrap()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "note.md");
        assert_eq!(entries[0].kind, EntryKind::File);

        remove_file(root, Path::new("a/b/note.md"), "the note").unwrap();
        assert_eq!(
            read_to_string_optional(root, Path::new("a/b/note.md"), "the note").unwrap(),
            None
        );
    }

    #[test]
    fn creation_never_replaces_an_existing_entry() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        write_new(root, Path::new("note.md"), b"first", "the note").unwrap();
        let error = write_new(root, Path::new("note.md"), b"second", "the note").unwrap_err();
        assert!(crate::error::is_already_exists(&error));
        assert_eq!(
            read_to_string(root, Path::new("note.md"), "the note").unwrap(),
            "first"
        );
    }

    #[test]
    fn staged_writes_leave_no_temporary_files_behind() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        write_new(root, Path::new("note.md"), b"first", "the note").unwrap();
        write_replace(root, Path::new("note.md"), b"second", "the note").unwrap();
        let entries = list_directory(root, Path::new(""), "the directory")
            .unwrap()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "note.md");
    }

    #[test]
    fn a_failed_replacement_leaves_the_destination_alone() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        create_directory_all(root, Path::new("destination"), "the destination").unwrap();
        assert!(write_replace(root, Path::new("destination"), b"x", "the destination").is_err());
        assert!(root.join("destination").is_dir());
    }

    #[test]
    fn relative_paths_may_not_escape_with_dot_segments() {
        let root = tempfile::tempdir().unwrap();
        assert!(open_directory(root.path(), Path::new("../elsewhere"), "the directory").is_err());
        assert!(read_to_string(root.path(), Path::new("/etc/passwd"), "the file").is_err());
    }

    #[cfg(unix)]
    mod symlinks {
        use super::super::{
            EntryKind, create_directory_all, entry_kind, open_directory, read_to_string,
            remove_file, write_new, write_replace,
        };
        use super::classification;
        use std::{os::unix::fs::symlink, path::Path};

        #[test]
        fn an_intermediate_symbolic_link_is_refused_on_every_operation() {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("root");
            let outside = temporary.path().join("outside");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("secret.md"), "secret").unwrap();
            symlink(&outside, root.join("escape")).unwrap();

            let target = Path::new("escape/secret.md");
            let error = read_to_string(&root, target, "the secret").unwrap_err();
            assert_eq!(classification(&error), Some("conflict"));
            assert!(error.to_string().contains("symbolic link"));

            assert!(write_new(&root, Path::new("escape/new.md"), b"x", "the file").is_err());
            assert!(write_replace(&root, target, b"x", "the secret").is_err());
            assert!(remove_file(&root, target, "the secret").is_err());
            assert!(open_directory(&root, Path::new("escape"), "the directory").is_err());
            assert!(
                create_directory_all(&root, Path::new("escape/deeper"), "the directory").is_err()
            );
            assert_eq!(
                std::fs::read_to_string(outside.join("secret.md")).unwrap(),
                "secret"
            );
            assert!(!outside.join("new.md").exists());
            assert!(!outside.join("deeper").exists());
        }

        #[test]
        fn a_symbolic_link_in_place_of_the_file_itself_is_refused() {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("root");
            std::fs::create_dir_all(&root).unwrap();
            let outside = temporary.path().join("secret.md");
            std::fs::write(&outside, "secret").unwrap();
            symlink(&outside, root.join("note.md")).unwrap();

            let target = Path::new("note.md");
            let error = read_to_string(&root, target, "the note").unwrap_err();
            assert_eq!(classification(&error), Some("conflict"));
            assert!(write_replace(&root, target, b"x", "the note").is_err());
            assert!(remove_file(&root, target, "the note").is_err());
            assert!(write_new(&root, target, b"x", "the note").is_err());
            assert_eq!(
                entry_kind(&root, target, "the note").unwrap(),
                Some(EntryKind::Symlink)
            );
            assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret");
        }

        #[test]
        fn a_dangling_symbolic_link_is_refused_rather_than_created_through() {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("root");
            std::fs::create_dir_all(&root).unwrap();
            let outside = temporary.path().join("absent");
            symlink(&outside, root.join("link")).unwrap();

            assert!(open_directory(&root, Path::new("link"), "the directory").is_err());
            assert!(create_directory_all(&root, Path::new("link"), "the directory").is_err());
            assert!(write_new(&root, Path::new("link/note.md"), b"x", "the note").is_err());
            assert!(!outside.exists());
        }

        #[test]
        fn permissions_survive_a_replacement() {
            use std::os::unix::fs::PermissionsExt;

            let root = tempfile::tempdir().unwrap();
            write_new(root.path(), Path::new("note.md"), b"first", "the note").unwrap();
            std::fs::set_permissions(
                root.path().join("note.md"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            write_replace(root.path(), Path::new("note.md"), b"second", "the note").unwrap();
            assert_eq!(
                std::fs::metadata(root.path().join("note.md"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o640
            );
        }
    }
}
