//! Ed25519-signed audit checkpoints.
//!
//! The anchor at the database root is worth exactly as much as the place it
//! is committed to: anybody who can rewrite `.cr/audit/` can rewrite it in the
//! same pass. A signed checkpoint is the same statement — this database's
//! journal had this event at this sequence — made with a key that lives
//! outside the database and checked against public keys that come from outside
//! it too. Someone who can rewrite every file under the root still cannot
//! produce a signature, so the forgery the anchor cannot catch, a rewritten
//! head with the anchor re-derived to match, fails here.
//!
//! Keys are loaded from the environment at the point of use, exactly as the
//! encryption keyring is. Neither the database configuration nor the journal
//! ever names a key file, because a key the database pointed at would be one
//! an attacker with write access could repoint.
//!
//! This module holds the key formats, the signed message, and the checkpoint
//! file's shape. Judging a checkpoint against the journal is position logic
//! and lives beside the anchor's in `audit.rs`.

use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    audit::digest,
    error::{DomainError, conflict, invalid},
};

/// Names the private key file `cr` signs with. Set it only where signing
/// should happen; every command that appends an event then signs.
pub(crate) const SIGNING_KEY_ENV: &str = "CR_AUDIT_SIGNING_KEY";
/// Public keys a verifier trusts, as inline keys or files of them.
pub(crate) const TRUSTED_KEYS_ENV: &str = "CR_AUDIT_TRUSTED_KEYS";

/// The prefix of every rendered key and signature, naming the algorithm so a
/// later format can add another without ambiguity.
const ALGORITHM_PREFIX: &str = "ed25519:";
const KEY_FILE_VERSION: u32 = 1;
/// Format version of the signed checkpoint file. The signed message's own
/// version is its domain separator below.
pub(crate) const CHECKPOINT_VERSION: u32 = 1;
/// Domain separator for a public key's fingerprint.
const KEY_ID_DOMAIN: &[u8] = b"cr:audit:signing-key:v1\0";
/// Domain separator for the signed checkpoint message.
///
/// Distinct from every hash domain, so a signature over a checkpoint can never
/// be presented as a signature over an event, a record, or a change set.
const CHECKPOINT_DOMAIN: &[u8] = b"cr:audit:checkpoint:v1\0";
const SECRET_LENGTH: usize = 32;

/// An Ed25519 public key and the fingerprint signatures name it by.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    key: VerifyingKey,
    id: String,
}

impl PublicKey {
    /// Parse the `ed25519:<base64url>` form `cr audit key generate` prints.
    ///
    /// Strict about the spelling: the encoding must be the canonical unpadded
    /// one, so a key has exactly one written form and two spellings can never
    /// name different keys. Small-order points are refused too, because a
    /// weak key is one a signature can be forged for without its secret.
    pub fn parse(text: &str) -> Result<Self> {
        let refuse = || {
            invalid(
                "a trusted audit key must be written as ed25519: followed by 43 base64url characters",
            )
        };
        let encoded = text.strip_prefix(ALGORITHM_PREFIX).ok_or_else(refuse)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| refuse())?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| refuse())?;
        if URL_SAFE_NO_PAD.encode(bytes) != encoded {
            return Err(refuse());
        }
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| refuse())?;
        if key.is_weak() {
            return Err(invalid(
                "a trusted audit key is not a usable Ed25519 public key",
            ));
        }
        Ok(Self::from_verifying(key))
    }

    fn from_verifying(key: VerifyingKey) -> Self {
        Self {
            id: digest(KEY_ID_DOMAIN, key.as_bytes()),
            key,
        }
    }

    /// `sha256:` over the key-ID domain and the 32 public key bytes.
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{ALGORITHM_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(self.key.as_bytes())
        )
    }
}

/// The public keys a verification trusts, by key ID.
///
/// Every source is outside the database: a command-line flag, the
/// environment, a request parameter, or a file the caller names. There is
/// deliberately no way to make `cr` read a trusted key from the database
/// itself. A key file committed beside the journal proves nothing against
/// someone who can rewrite the journal, since they can rewrite the file too.
#[derive(Clone, Debug, Default)]
pub struct TrustedKeys {
    keys: BTreeMap<String, PublicKey>,
    files: Vec<PathBuf>,
}

impl TrustedKeys {
    /// Keys given on a command line or in the environment. Each value is an
    /// inline `ed25519:` key or the path of a file with one key per line.
    pub fn parse<I, S>(values: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut trusted = Self::default();
        for value in values {
            let value = value.as_ref().trim();
            if value.starts_with(ALGORITHM_PREFIX) {
                trusted.insert(PublicKey::parse(value)?);
            } else {
                trusted.read_file(Path::new(value))?;
            }
        }
        trusted.require_some()
    }

    /// Keys given in a request, which may only be keys.
    ///
    /// A remote caller naming a file would make the server read a path of the
    /// caller's choosing, and even a refusal would say whether it exists.
    pub fn parse_inline<I, S>(values: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut trusted = Self::default();
        for value in values {
            let value = value.as_ref().trim();
            if !value.starts_with(ALGORITHM_PREFIX) {
                return Err(invalid(
                    "a trusted key must be given inline as an ed25519: public key; a key file cannot be named in a request",
                ));
            }
            trusted.insert(PublicKey::parse(value)?);
        }
        trusted.require_some()
    }

    /// The keys `CR_AUDIT_TRUSTED_KEYS` names, or `None` when it is unset or
    /// empty. Values are separated by commas, so a key file whose path holds
    /// a comma has to be given with `--trusted-key` instead.
    pub fn from_environment() -> Result<Option<Self>> {
        let Some(value) = std::env::var_os(TRUSTED_KEYS_ENV) else {
            return Ok(None);
        };
        let value = value
            .into_string()
            .map_err(|_| invalid(format!("{TRUSTED_KEYS_ENV} is not valid UTF-8")))?;
        let values = value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if values.is_empty() {
            return Ok(None);
        }
        Self::parse(values)
            .map(Some)
            .map_err(|error| error.context(format!("{TRUSTED_KEYS_ENV} could not be used")))
    }

    /// Every key file these keys were read from, canonicalized, so a caller
    /// can warn when one sits inside the database it is about to verify.
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// The fingerprint of every trusted key, in order.
    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    pub(crate) fn get(&self, key_id: &str) -> Option<&PublicKey> {
        self.keys.get(key_id)
    }

    /// These keys and one more: a signer trusts its own key's earlier
    /// checkpoints beside whatever the environment says to trust.
    pub(crate) fn with(mut self, key: PublicKey) -> Self {
        self.insert(key);
        self
    }

    fn insert(&mut self, key: PublicKey) {
        self.keys.insert(key.id.clone(), key);
    }

    fn require_some(self) -> Result<Self> {
        if self.keys.is_empty() {
            return Err(invalid("no trusted audit keys were given"));
        }
        Ok(self)
    }

    /// Read one key per line. Blank lines and `#` comments are skipped, and
    /// anything after the key on its line is a free-text label, so a file can
    /// say whose key each one is.
    fn read_file(&mut self, path: &Path) -> Result<()> {
        let contents = fs::read_to_string(path)
            .map_err(|error| {
                anyhow!(error).context(format!(
                    "could not read trusted key file {}",
                    path.display()
                ))
            })
            .map_err(|error| {
                error.context(DomainError::Invalid(
                    "a trusted key file cannot be read".to_owned(),
                ))
            })?;
        if serde_json::from_str::<KeyFile>(&contents).is_ok() {
            return Err(invalid(
                "a trusted key file holds a private signing key; trust its public key instead, which 'cr audit key show' prints",
            ));
        }
        let mut found = false;
        for (index, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let key = line.split_whitespace().next().unwrap_or_default();
            let key = PublicKey::parse(key).map_err(|error| {
                error.context(DomainError::Invalid(format!(
                    "line {} of a trusted key file is not an ed25519: public key",
                    index + 1
                )))
            })?;
            self.insert(key);
            found = true;
        }
        if !found {
            return Err(invalid("a trusted key file names no keys"));
        }
        self.files
            .push(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
        Ok(())
    }
}

/// The stored form of a private signing key.
///
/// A small versioned JSON object, like every other file `cr` writes, rather
/// than a bare secret, so a later format can be told apart from this one.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    version: u32,
    secret_key: String,
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// A loaded private signing key. Its secret is wiped when it is dropped.
pub(crate) struct CheckpointSigner {
    key: SigningKey,
    public: PublicKey,
}

impl fmt::Debug for CheckpointSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointSigner")
            .field("key_id", &self.public.id)
            .finish_non_exhaustive()
    }
}

impl CheckpointSigner {
    /// The key `CR_AUDIT_SIGNING_KEY` names, or `None` when it is unset or
    /// empty, in which case nothing is signed and nothing is different.
    pub(crate) fn from_environment() -> Result<Option<Self>> {
        let Some(path) = signing_key_path_from_environment() else {
            return Ok(None);
        };
        Self::load(&path)
            .map(Some)
            .map_err(|error| error.context(format!("{SIGNING_KEY_ENV} could not be used")))
    }

    fn load(path: &Path) -> Result<Self> {
        let contents = Zeroizing::new(
            fs::read_to_string(path)
                .map_err(|error| {
                    anyhow!(error).context(format!("could not read signing key {}", path.display()))
                })
                .map_err(|error| {
                    error.context(DomainError::Invalid(
                        "the audit signing key file cannot be read".to_owned(),
                    ))
                })?,
        );
        let not_a_key =
            || invalid("the audit signing key file does not hold a cr audit signing key");
        let file: KeyFile = serde_json::from_str(contents.as_str()).map_err(|_| not_a_key())?;
        if file.version != KEY_FILE_VERSION {
            return Err(invalid(format!(
                "the audit signing key file has format version {}, and this build understands version {KEY_FILE_VERSION}",
                file.version
            )));
        }
        let encoded = file
            .secret_key
            .strip_prefix(ALGORITHM_PREFIX)
            .ok_or_else(not_a_key)?;
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded.as_bytes())
                .map_err(|_| not_a_key())?,
        );
        let mut secret = Zeroizing::new([0_u8; SECRET_LENGTH]);
        if decoded.len() != SECRET_LENGTH {
            return Err(not_a_key());
        }
        secret.copy_from_slice(&decoded);
        Ok(Self::from_secret(&secret))
    }

    fn from_secret(secret: &[u8; SECRET_LENGTH]) -> Self {
        let key = SigningKey::from_bytes(secret);
        let public = PublicKey::from_verifying(key.verifying_key());
        Self { key, public }
    }

    pub(crate) fn public(&self) -> &PublicKey {
        &self.public
    }
}

/// The path `CR_AUDIT_SIGNING_KEY` names, when it names one.
fn signing_key_path_from_environment() -> Option<PathBuf> {
    std::env::var_os(SIGNING_KEY_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// What `cr audit key generate` and `cr audit key show` report: never the
/// secret, only what a verifier needs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SigningKeySummary {
    /// The fingerprint every checkpoint signed with this key names.
    pub key_id: String,
    /// The public key, in the form `--trusted-key` accepts.
    pub public_key: String,
    /// Where the private key is stored.
    pub path: PathBuf,
}

impl SigningKeySummary {
    fn of(signer: &CheckpointSigner, path: &Path) -> Self {
        Self {
            key_id: signer.public.id.clone(),
            public_key: signer.public.to_string(),
            path: path.to_path_buf(),
        }
    }
}

/// Create a new private signing key at `path`.
///
/// The file is created, never replaced: overwriting a signing key would
/// orphan every checkpoint it signed. On Unix it is created readable and
/// writable by its owner only, before any secret byte is written to it.
pub fn generate_signing_key(path: &Path) -> Result<SigningKeySummary> {
    let mut secret = Zeroizing::new([0_u8; SECRET_LENGTH]);
    getrandom::fill(secret.as_mut_slice())
        .map_err(|_| conflict("secure randomness is unavailable"))?;
    let signer = CheckpointSigner::from_secret(&secret);
    let file = KeyFile {
        version: KEY_FILE_VERSION,
        secret_key: format!(
            "{ALGORITHM_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(secret.as_slice())
        ),
    };
    let mut bytes = Zeroizing::new(
        serde_json::to_vec_pretty(&file).context("could not serialize the audit signing key")?,
    );
    bytes.push(b'\n');
    write_private_file(path, &bytes)?;
    Ok(SigningKeySummary::of(&signer, path))
}

/// Describe the private key stored at `path` without revealing it.
pub fn describe_signing_key(path: &Path) -> Result<SigningKeySummary> {
    let signer = CheckpointSigner::load(path)?;
    Ok(SigningKeySummary::of(&signer, path))
}

/// Describe the key `CR_AUDIT_SIGNING_KEY` names, or `None` when it is unset.
/// Loading it is the whole check, so this is also how a long-lived process
/// learns at launch that every write it would sign is going to fail.
pub fn describe_signing_key_from_environment() -> Result<Option<SigningKeySummary>> {
    let Some(path) = signing_key_path_from_environment() else {
        return Ok(None);
    };
    describe_signing_key(&path)
        .map(Some)
        .map_err(|error| error.context(format!("{SIGNING_KEY_ENV} could not be used")))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        let exists = error.kind() == std::io::ErrorKind::AlreadyExists;
        let error =
            anyhow!(error).context(format!("could not create signing key {}", path.display()));
        if exists {
            error.context(DomainError::AlreadyExists(
                "a file already exists where the signing key would be written, and cr never overwrites one".to_owned(),
            ))
        } else {
            error
        }
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("could not write signing key {}", path.display()))
}

/// A checkpoint signed with a key held outside the database, stored at the
/// database root beside the anchor.
///
/// Self-contained on purpose. It repeats the position it signs rather than
/// pointing at the anchor, so it can lag the anchor, and be judged, on its
/// own: a crash between writing the anchor and writing this file leaves a
/// signature one position behind, which reads as lagging exactly as a lagging
/// anchor does. Ed25519 signatures are deterministic, so like the anchor the
/// file is a pure function of the journal and the key, and two copies of one
/// journal signed with one key are byte-identical.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    /// Format version of this file.
    pub version: u32,
    /// The stored hash of the journal's first event, which identifies the
    /// database: independently created journals never share one, and it
    /// cannot change without every later event hash changing with it.
    pub database: String,
    /// The audit sequence this checkpoint attests to.
    pub sequence: u64,
    /// The stored hash of the event at `sequence`.
    pub hash: String,
    /// That event's own timestamp, never the time of signing.
    pub timestamp: String,
    /// The fingerprint of the key that signed.
    pub key_id: String,
    /// `ed25519:` and the unpadded base64url signature over [`Self::message`].
    pub signature: String,
}

impl SignedCheckpoint {
    /// Sign the position of one event with `signer`.
    pub(crate) fn sign(
        signer: &CheckpointSigner,
        database: &str,
        sequence: u64,
        hash: &str,
        timestamp: &str,
    ) -> Self {
        let signature = signer
            .key
            .sign(&checkpoint_message(database, sequence, hash, timestamp));
        Self {
            version: CHECKPOINT_VERSION,
            database: database.to_owned(),
            sequence,
            hash: hash.to_owned(),
            timestamp: timestamp.to_owned(),
            key_id: signer.public.id.clone(),
            signature: format!(
                "{ALGORITHM_PREFIX}{}",
                URL_SAFE_NO_PAD.encode(signature.to_bytes())
            ),
        }
    }

    /// Whether `key` signed exactly the position this file states.
    ///
    /// Strict verification: a non-canonical signature encoding or a
    /// malleable signature is refused rather than accepted as equivalent.
    pub(crate) fn verifies_under(&self, key: &PublicKey) -> bool {
        if self.key_id != key.id {
            return false;
        }
        let Some(encoded) = self.signature.strip_prefix(ALGORITHM_PREFIX) else {
            return false;
        };
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded.as_bytes()) else {
            return false;
        };
        let Ok(bytes) = <[u8; 64]>::try_from(bytes) else {
            return false;
        };
        if URL_SAFE_NO_PAD.encode(bytes) != encoded {
            return false;
        }
        let message =
            checkpoint_message(&self.database, self.sequence, &self.hash, &self.timestamp);
        key.key
            .verify_strict(&message, &Signature::from_bytes(&bytes))
            .is_ok()
    }

    /// The exact bytes the file is stored as: stable field order, one field
    /// per line, newline-terminated, like the anchor.
    pub(crate) fn serialize(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .context("could not serialize the signed audit checkpoint")?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// The message a checkpoint signature covers.
///
/// The checkpoint domain, then the database identity, the sequence in decimal,
/// the event hash, and the event timestamp, each as a big-endian `u64` length
/// followed by its UTF-8 bytes. Length prefixes make the encoding injective,
/// so no two different positions can ever produce the same message, whatever
/// the fields contain. The file's own `version`, `key_id`, and `signature` are
/// not covered: the domain carries the message version, and Ed25519 already
/// binds a signature to the public key that verifies it.
pub(crate) fn checkpoint_message(
    database: &str,
    sequence: u64,
    hash: &str,
    timestamp: &str,
) -> Vec<u8> {
    let sequence = sequence.to_string();
    let mut message = CHECKPOINT_DOMAIN.to_vec();
    for component in [database, sequence.as_str(), hash, timestamp] {
        message.extend_from_slice(&(component.len() as u64).to_be_bytes());
        message.extend_from_slice(component.as_bytes());
    }
    message
}

#[cfg(test)]
mod tests {
    use super::{
        CHECKPOINT_DOMAIN, CheckpointSigner, KEY_ID_DOMAIN, PublicKey, SignedCheckpoint,
        TrustedKeys, checkpoint_message, describe_signing_key, generate_signing_key,
    };
    use crate::{audit::digest, error::DomainError};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    const DATABASE: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000001";
    const HASH: &str = "sha256:00000000000000000000000000000000000000000000000000000000000000ff";
    const TIMESTAMP: &str = "2026-09-27T10:11:12.123456789Z";

    fn signer(seed: u8) -> CheckpointSigner {
        CheckpointSigner::from_secret(&[seed; 32])
    }

    #[test]
    fn the_message_is_domain_separated_and_length_prefixed() {
        let message = checkpoint_message("ab", 7, "c", "d");
        let mut expected = CHECKPOINT_DOMAIN.to_vec();
        for part in ["ab", "7", "c", "d"] {
            expected.extend_from_slice(&(part.len() as u64).to_be_bytes());
            expected.extend_from_slice(part.as_bytes());
        }
        assert_eq!(message, expected);
        // Moving a byte from one field to the next is a different message.
        assert_ne!(
            checkpoint_message("ab", 7, "c", "d"),
            checkpoint_message("a", 7, "bc", "d")
        );
    }

    #[test]
    fn key_ids_are_a_domain_separated_fingerprint_of_the_public_key() {
        let signer = signer(1);
        assert_eq!(
            signer.public().id(),
            digest(KEY_ID_DOMAIN, signer.public().key.as_bytes())
        );
        assert_ne!(signer.public().id(), signer_id(2));
        // The rendered key parses back to the same key and ID.
        let parsed = PublicKey::parse(&signer.public().to_string()).unwrap();
        assert_eq!(&parsed, signer.public());
    }

    fn signer_id(seed: u8) -> String {
        signer(seed).public().id().to_owned()
    }

    #[test]
    fn a_signature_verifies_only_under_its_key_and_over_its_position() {
        let signer = signer(3);
        let checkpoint = SignedCheckpoint::sign(&signer, DATABASE, 42, HASH, TIMESTAMP);
        assert!(checkpoint.verifies_under(signer.public()));
        // Deterministic, so the file is a function of journal and key.
        assert_eq!(
            checkpoint,
            SignedCheckpoint::sign(&signer, DATABASE, 42, HASH, TIMESTAMP)
        );

        let other = self::signer(4);
        assert!(!checkpoint.verifies_under(other.public()));
        let mut relabelled = checkpoint.clone();
        relabelled.key_id = other.public().id().to_owned();
        assert!(!relabelled.verifies_under(other.public()));

        for edit in [
            |checkpoint: &mut SignedCheckpoint| checkpoint.sequence += 1,
            |checkpoint: &mut SignedCheckpoint| checkpoint.hash.push('0'),
            |checkpoint: &mut SignedCheckpoint| checkpoint.timestamp.push('0'),
            |checkpoint: &mut SignedCheckpoint| checkpoint.database.push('0'),
            |checkpoint: &mut SignedCheckpoint| checkpoint.signature.push('A'),
        ] {
            let mut edited = checkpoint.clone();
            edit(&mut edited);
            assert!(!edited.verifies_under(signer.public()), "{edited:?}");
        }
    }

    #[test]
    fn public_keys_have_exactly_one_spelling() {
        let rendered = signer(5).public().to_string();
        assert!(rendered.starts_with("ed25519:"));
        assert_eq!(rendered.len(), "ed25519:".len() + 43);
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        for refused in [
            rendered.trim_start_matches("ed25519:").to_owned(),
            format!("{rendered}="),
            format!("{}!", &rendered[..rendered.len() - 1]),
            "ed25519:".to_owned(),
            // The identity point is small-order, so it is a weak key.
            format!("ed25519:{}", URL_SAFE_NO_PAD.encode(identity)),
        ] {
            let error = PublicKey::parse(&refused).expect_err(&refused);
            assert_eq!(
                DomainError::of(&error).map(DomainError::code),
                Some("validation_failed")
            );
        }
    }

    #[test]
    fn requests_may_only_name_keys_inline() {
        let key = signer(6).public().to_string();
        let trusted = TrustedKeys::parse_inline([key.as_str()]).unwrap();
        assert_eq!(trusted.key_ids().count(), 1);
        let error = TrustedKeys::parse_inline(["/etc/passwd"]).unwrap_err();
        assert!(!error.to_string().contains("passwd"), "{error}");
        assert!(TrustedKeys::parse_inline(Vec::<String>::new()).is_err());
    }

    #[test]
    fn generated_keys_round_trip_and_trusted_key_files_accept_labels() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.key");
        let generated = generate_signing_key(&path).unwrap();
        assert_eq!(describe_signing_key(&path).unwrap(), generated);
        let error = generate_signing_key(&path).unwrap_err();
        assert_eq!(
            DomainError::of(&error).map(DomainError::code),
            Some("already_exists")
        );

        let keys = directory.path().join("trusted");
        std::fs::write(
            &keys,
            format!(
                "# the release signer\n\n{} alice@laptop\n",
                generated.public_key
            ),
        )
        .unwrap();
        let trusted = TrustedKeys::parse([keys.to_str().unwrap()]).unwrap();
        assert_eq!(
            trusted.key_ids().collect::<Vec<_>>(),
            [generated.key_id.as_str()]
        );
        assert_eq!(trusted.files().len(), 1);

        // A private key handed over as a trusted key is refused by name.
        let error = TrustedKeys::parse([path.to_str().unwrap()]).unwrap_err();
        assert!(error.to_string().contains("private signing key"), "{error}");
    }
}
