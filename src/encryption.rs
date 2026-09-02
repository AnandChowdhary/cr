//! Schema-directed, transparent encryption for stored record values.
//!
//! JSON Schema continues to describe the logical plaintext document. The two
//! `x-cr-*` annotations in this module only change its representation at rest.
//! Keys are deliberately loaded from the process environment at the point of
//! use; neither the database configuration nor the audit journal ever receives
//! key material.

use std::collections::{BTreeSet, HashMap};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use yaml_serde::{Mapping, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    error::{conflict, invalid},
    frontmatter::Document,
};

pub(crate) const FIELD_EXTENSION: &str = "x-cr-encrypted";
pub(crate) const BODY_EXTENSION: &str = "x-cr-encrypted-body";
pub(crate) const CONTEXT_PATH: &str = ".cr/encryption.json";
pub(crate) const CONTEXT_LABEL: &str = "the database encryption context";

const ACTIVE_KEY_ENV: &str = "CR_ENCRYPTION_ACTIVE_KEY";
const KEYRING_ENV: &str = "CR_ENCRYPTION_KEYS";
const ENVELOPE_KEY: &str = "$cr_encrypted";
const MANIFEST_KEY: &str = "$cr_encryption";
const BODY_PREFIX: &str = "cr-encrypted:v1:";
const AAD_DOMAIN: &[u8] = b"cr:encryption:xchacha20poly1305:v1\0";
const ENVELOPE_VERSION: u64 = 1;
const CONTEXT_VERSION: u32 = 1;
const NONCE_LENGTH: usize = 24;
const KEY_LENGTH: usize = 32;

/// Portable, non-secret identity bound into every authenticated ciphertext.
///
/// The file containing this value moves with a database and is copied by a
/// clone, but independently initialized databases receive different IDs. That
/// is the stable boundary an absolute filesystem path cannot provide.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EncryptionContext {
    version: u32,
    id: String,
}

impl EncryptionContext {
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new(vec![0_u8; KEY_LENGTH]);
        getrandom::fill(bytes.as_mut_slice())
            .map_err(|_| conflict("secure randomness is unavailable"))?;
        Ok(Self {
            version: CONTEXT_VERSION,
            id: URL_SAFE_NO_PAD.encode(bytes.as_slice()),
        })
    }

    pub fn parse(serialized: &str) -> Result<Self> {
        let context: Self = serde_json::from_str(serialized)
            .map_err(|_| conflict("database encryption context is invalid"))?;
        if context.version != CONTEXT_VERSION {
            return Err(conflict(
                "database encryption context version is unsupported",
            ));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(context.id.as_bytes())
            .map_err(|_| conflict("database encryption context is invalid"))?;
        if decoded.len() != KEY_LENGTH || URL_SAFE_NO_PAD.encode(decoded) != context.id {
            return Err(conflict("database encryption context is invalid"));
        }
        Ok(context)
    }

    pub fn render(&self) -> Result<Vec<u8>> {
        let mut serialized = serde_json::to_vec_pretty(self)
            .context("could not serialize database encryption context")?;
        serialized.push(b'\n');
        Ok(serialized)
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

/// The storage policy compiled from one collection's JSON Schema.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct EncryptionPolicy {
    fields: Vec<Vec<String>>,
    body: bool,
}

/// Storage meaning proven by an exact per-record manifest in one reconstructed
/// audit state. The policy is deliberately retained, not reduced to a boolean:
/// a later schema marker move must never reinterpret an older envelope under a
/// different authenticated path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EncryptionStorageMetadata {
    pub policy: EncryptionPolicy,
    pub has_envelopes: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ProtectedDocument {
    pub document: Document,
    /// True when this operation created at least one new envelope. Callers use
    /// it to decide whether an approval preview needs an opaque nonce plan.
    pub encrypted_new_value: bool,
}

#[derive(Debug)]
struct Keyring {
    active: String,
    keys: HashMap<String, Zeroizing<Vec<u8>>>,
}

#[derive(Debug)]
struct Envelope {
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredBlobEnvelope {
    version: u64,
    key_id: String,
    nonce: String,
    ciphertext: String,
}

impl EncryptionPolicy {
    pub fn from_schema(schema: Option<&JsonValue>) -> Result<Self> {
        let Some(schema) = schema else {
            return Ok(Self::default());
        };
        let object = schema
            .as_object()
            .context("collection JSON Schema must be an object")?;
        let body = extension_bool(object.get(BODY_EXTENSION), BODY_EXTENSION)?;
        let mut fields = Vec::new();
        collect_fields(schema, &mut Vec::new(), &mut fields, false)?;
        let field_markers = count_enabled_extensions(schema, FIELD_EXTENSION)?;
        if field_markers != fields.len() {
            return Err(invalid(format!(
                "'{FIELD_EXTENSION}' is supported only on schemas reached through the root 'properties' tree; mark an enclosing property to protect arrays or composed schemas"
            )));
        }
        let body_markers = count_enabled_extensions(schema, BODY_EXTENSION)?;
        if body_markers != usize::from(body) {
            return Err(invalid(format!(
                "'{BODY_EXTENSION}' is supported only on the collection schema root"
            )));
        }
        fields.sort();
        fields.dedup();
        Ok(Self { fields, body })
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && !self.body
    }

    pub fn would_encrypt_on_create(&self, logical: &Document) -> bool {
        self.body
            || self
                .fields
                .iter()
                .any(|path| yaml_get(&logical.attributes, path).is_some())
    }

    #[cfg(test)]
    pub fn protects_body(&self) -> bool {
        self.body
    }

    #[cfg(test)]
    pub fn field_paths(&self) -> &[Vec<String>] {
        &self.fields
    }

    /// Convert a logical document into its exact stored representation.
    ///
    /// An unchanged protected value reuses its previous envelope. Besides
    /// avoiding noisy diffs, this is what keeps unrelated writes from changing
    /// a record's encrypted bytes. A changed value always receives a new nonce.
    pub fn protect(
        &self,
        context: Option<&str>,
        collection: &str,
        id: &str,
        logical: &Document,
        previous_stored: Option<&Document>,
    ) -> Result<ProtectedDocument> {
        self.validate_logical_for_write(logical)?;
        if self.is_empty() {
            return Ok(ProtectedDocument {
                document: logical.clone(),
                encrypted_new_value: false,
            });
        }
        if let Some(previous) = previous_stored {
            self.assert_manifest(previous)?;
        }
        let keyring = Keyring::from_environment(true)?;
        let mut stored = logical.clone();
        let mut encrypted_new_value = false;

        for path in &self.fields {
            let Some(plaintext) = yaml_get(&logical.attributes, path).cloned() else {
                continue;
            };
            let prior = previous_stored.and_then(|document| yaml_get(&document.attributes, path));
            let stored_value = if let Some(prior) = prior {
                let envelope = field_envelope(prior)?;
                let prior_plaintext = decrypt_value(
                    &keyring,
                    &envelope,
                    &record_aad(context, collection, id, path, "attribute")?,
                )?;
                if prior_plaintext == plaintext {
                    prior.clone()
                } else {
                    encrypted_new_value = true;
                    encrypt_value(
                        &keyring,
                        &plaintext,
                        &record_aad(context, collection, id, path, "attribute")?,
                    )?
                }
            } else {
                encrypted_new_value = true;
                encrypt_value(
                    &keyring,
                    &plaintext,
                    &record_aad(context, collection, id, path, "attribute")?,
                )?
            };
            yaml_set(&mut stored.attributes, path, stored_value)?;
        }

        if self.body {
            let prior = previous_stored.map(|document| document.body.as_str());
            stored.body = if let Some(prior) = prior {
                let envelope = body_envelope(prior)?;
                let prior_plaintext = decrypt_bytes(
                    &keyring,
                    &envelope,
                    &record_aad(context, collection, id, &[], "body")?,
                )?;
                if prior_plaintext == logical.body.as_bytes() {
                    prior.to_owned()
                } else {
                    encrypted_new_value = true;
                    render_body_envelope(&encrypt_bytes(
                        &keyring,
                        logical.body.as_bytes(),
                        &record_aad(context, collection, id, &[], "body")?,
                    )?)
                }
            } else {
                encrypted_new_value = true;
                render_body_envelope(&encrypt_bytes(
                    &keyring,
                    logical.body.as_bytes(),
                    &record_aad(context, collection, id, &[], "body")?,
                )?)
            };
        }
        stored.attributes.insert(
            Value::String(MANIFEST_KEY.to_owned()),
            self.render_manifest(),
        );

        Ok(ProtectedDocument {
            document: stored,
            encrypted_new_value,
        })
    }

    /// Convert exact stored representation into the logical plaintext document.
    pub fn reveal(
        &self,
        context: Option<&str>,
        collection: &str,
        id: &str,
        stored: &Document,
    ) -> Result<Document> {
        if self.is_empty() {
            if stored
                .attributes
                .get(Value::String(MANIFEST_KEY.to_owned()))
                .is_some_and(|manifest| manifest_has_envelopes(stored, manifest))
            {
                return Err(conflict(
                    "stored protected data is no longer declared by the collection schema",
                ));
            }
            return Ok(stored.clone());
        }
        self.assert_manifest(stored)?;
        let mut logical = stored.clone();
        logical
            .attributes
            .remove(Value::String(MANIFEST_KEY.to_owned()));
        let mut keyring = None;
        for path in &self.fields {
            let Some(value) = yaml_get(&stored.attributes, path) else {
                continue;
            };
            let envelope = field_envelope(value)?;
            let keys = keyring
                .get_or_insert_with(|| Keyring::from_environment(false))
                .as_ref()
                .map_err(clone_public_error)?;
            let plaintext = decrypt_value(
                keys,
                &envelope,
                &record_aad(context, collection, id, path, "attribute")?,
            )?;
            yaml_set(&mut logical.attributes, path, plaintext)?;
        }
        if self.body {
            let envelope = body_envelope(&stored.body)?;
            let keys = keyring
                .get_or_insert_with(|| Keyring::from_environment(false))
                .as_ref()
                .map_err(clone_public_error)?;
            let plaintext = decrypt_bytes(
                keys,
                &envelope,
                &record_aad(context, collection, id, &[], "body")?,
            )?;
            logical.body = String::from_utf8(plaintext).map_err(|_| decryption_failed())?;
        }
        Ok(logical)
    }

    pub fn validate_logical_for_write(&self, logical: &Document) -> Result<()> {
        if logical
            .attributes
            .contains_key(Value::String(MANIFEST_KEY.to_owned()))
        {
            return Err(invalid(format!(
                "front matter field '{MANIFEST_KEY}' is reserved"
            )));
        }
        Ok(())
    }

    /// Reveal a full audit document value. Field-level changes are handled by
    /// [`Self::reveal_audit_value`] below.
    pub fn reveal_audit_document(
        &self,
        context: Option<&str>,
        collection: &str,
        id: &str,
        value: &mut JsonValue,
    ) -> Result<()> {
        let stored = Document::from_audit_value(value)?;
        let logical = self.reveal(context, collection, id, &stored)?;
        *value = document_json(&logical)?;
        Ok(())
    }

    /// Reveal one audit value when its JSON Pointer names a protected logical
    /// field or the body. Non-protected values are left unchanged.
    pub fn reveal_audit_value(
        &self,
        context: Option<&str>,
        collection: &str,
        id: &str,
        pointer: &str,
        value: &mut JsonValue,
    ) -> Result<()> {
        if pointer.is_empty() {
            return self.reveal_audit_document(context, collection, id, value);
        }
        if pointer == "/body" && self.body {
            let stored = value.as_str().ok_or_else(decryption_failed)?;
            let envelope = body_envelope(stored)?;
            let keyring = Keyring::from_environment(false)?;
            let plaintext = decrypt_bytes(
                &keyring,
                &envelope,
                &record_aad(context, collection, id, &[], "body")?,
            )?;
            *value =
                JsonValue::String(String::from_utf8(plaintext).map_err(|_| decryption_failed())?);
            return Ok(());
        }
        let Some(changed_path) = pointer_attribute_path(pointer)? else {
            return Ok(());
        };
        let protected = self
            .fields
            .iter()
            .filter(|candidate| candidate.starts_with(&changed_path))
            .cloned()
            .collect::<Vec<_>>();
        if protected.is_empty() {
            return Ok(());
        }
        let mut yaml: Value =
            serde_json::from_value(value.clone()).map_err(|_| decryption_failed())?;
        let mut keyring = None;
        for path in protected {
            let relative = &path[changed_path.len()..];
            let encrypted = if relative.is_empty() {
                yaml.clone()
            } else {
                let Some(encrypted) = yaml_value_get(&yaml, relative).cloned() else {
                    // A schema-marked descendant may be optional. Adding or
                    // removing its parent without that descendant is still a
                    // valid ordinary audit change and has nothing to decrypt.
                    continue;
                };
                encrypted
            };
            let envelope = field_envelope(&encrypted)?;
            let keys = keyring
                .get_or_insert_with(|| Keyring::from_environment(false))
                .as_ref()
                .map_err(clone_public_error)?;
            let plaintext = decrypt_value(
                keys,
                &envelope,
                &record_aad(context, collection, id, &path, "attribute")?,
            )?;
            if relative.is_empty() {
                yaml = plaintext;
            } else {
                let Value::Mapping(mapping) = &mut yaml else {
                    return Err(decryption_failed());
                };
                yaml_set(mapping, relative, plaintext)?;
            }
        }
        *value = serde_json::to_value(yaml).map_err(|_| decryption_failed())?;
        Ok(())
    }

    fn render_manifest(&self) -> Value {
        let mut manifest = Mapping::new();
        manifest.insert("version".into(), ENVELOPE_VERSION.into());
        manifest.insert(
            "fields".into(),
            self.fields
                .iter()
                .map(|path| {
                    Value::Sequence(path.iter().cloned().map(Value::String).collect::<Vec<_>>())
                })
                .collect::<Vec<_>>()
                .into(),
        );
        manifest.insert("body".into(), self.body.into());
        Value::Mapping(manifest)
    }

    fn assert_manifest(&self, stored: &Document) -> Result<()> {
        let manifest = stored
            .attributes
            .get(Value::String(MANIFEST_KEY.to_owned()))
            .ok_or_else(migration_required)?;
        if manifest != &self.render_manifest() {
            return Err(conflict(
                "stored encryption metadata does not match the collection schema",
            ));
        }
        Ok(())
    }
}

/// True only for the exact storage-manifest type, not merely for an ordinary
/// application field that happens to use the same top-level name.
pub(crate) fn document_has_encrypted_storage(document: &Document) -> bool {
    document
        .attributes
        .get(Value::String(MANIFEST_KEY.to_owned()))
        .is_some_and(|manifest| manifest_has_envelopes(document, manifest))
}

fn parse_storage_manifest(value: &Value) -> Option<(Vec<Vec<String>>, bool)> {
    let Value::Mapping(manifest) = value else {
        return None;
    };
    let expected = BTreeSet::from(["version", "fields", "body"]);
    let actual = manifest
        .keys()
        .map(|key| match key {
            Value::String(key) => Some(key.as_str()),
            _ => None,
        })
        .collect::<Option<BTreeSet<_>>>();
    if actual.as_ref() != Some(&expected)
        || manifest
            .get(Value::String("version".into()))
            .and_then(Value::as_u64)
            != Some(ENVELOPE_VERSION)
        || !matches!(
            manifest.get(Value::String("body".into())),
            Some(Value::Bool(_))
        )
    {
        return None;
    }
    let Some(Value::Sequence(paths)) = manifest.get(Value::String("fields".into())) else {
        return None;
    };
    let fields = paths
        .iter()
        .map(|path| match path {
            Value::Sequence(parts) => parts
                .iter()
                .map(|part| match part {
                    Value::String(part) => Some(part.clone()),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let Value::Bool(body) = manifest.get(Value::String("body".into()))? else {
        return None;
    };
    Some((fields, *body))
}

fn manifest_has_envelopes(document: &Document, manifest: &Value) -> bool {
    let Some((fields, body)) = parse_storage_manifest(manifest) else {
        return false;
    };
    fields.iter().any(|path| {
        yaml_get(&document.attributes, path)
            .is_some_and(|value| parse_field_envelope(value).is_some())
    }) || (body && parse_body_envelope(&document.body).is_some())
}

/// Recover the exact historical policy owned by a stored manifest.
///
/// Standalone envelope-shaped application values have no manifest and remain
/// ordinary data. `has_envelopes` distinguishes an all-optional empty storage
/// state from ciphertext that requires the original database context.
pub(crate) fn audit_document_encryption_metadata(
    value: &JsonValue,
) -> Option<EncryptionStorageMetadata> {
    let document = Document::from_audit_value(value).ok()?;
    let manifest = document
        .attributes
        .get(Value::String(MANIFEST_KEY.to_owned()))?;
    let (fields, body) = parse_storage_manifest(manifest)?;
    Some(EncryptionStorageMetadata {
        policy: EncryptionPolicy { fields, body },
        has_envelopes: manifest_has_envelopes(&document, manifest),
    })
}

/// JSON pointers owned by an exact storage manifest in a complete audit
/// document. Audit diffing uses these coordinates—not envelope syntax—to keep
/// real ciphertext atomic while ordinary lookalike objects diff normally.
pub(crate) fn audit_document_encrypted_pointers(value: &JsonValue) -> BTreeSet<String> {
    let Some(document) = Document::from_audit_value(value).ok() else {
        return BTreeSet::new();
    };
    let Some(manifest) = document
        .attributes
        .get(Value::String(MANIFEST_KEY.to_owned()))
    else {
        return BTreeSet::new();
    };
    let Some((fields, body)) = parse_storage_manifest(manifest) else {
        return BTreeSet::new();
    };
    let mut pointers = fields
        .into_iter()
        .map(|path| {
            let suffix = path
                .iter()
                .map(|part| part.replace('~', "~0").replace('/', "~1"))
                .collect::<Vec<_>>()
                .join("/");
            format!("/attributes/{suffix}")
        })
        .collect::<BTreeSet<_>>();
    if body {
        pointers.insert("/body".to_owned());
    }
    pointers
}

/// Encrypt the durable operation stream of a sync that carries schema-marked
/// values. The complete stream is one authenticated blob because recovery
/// must reproduce its exact validated sequence rather than edit it in place.
pub(crate) fn protect_sync_stream(
    context: &str,
    name: &str,
    run_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let keyring = Keyring::from_environment(true)?;
    let envelope = encrypt_bytes(&keyring, plaintext, &sync_aad(context, name, run_id))?;
    let stored = StoredBlobEnvelope {
        version: ENVELOPE_VERSION,
        key_id: envelope.key_id,
        nonce: URL_SAFE_NO_PAD.encode(envelope.nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(envelope.ciphertext),
    };
    let mut serialized = serde_json::to_vec(&stored)
        .context("could not serialize protected sync operation stream")?;
    serialized.push(b'\n');
    Ok(serialized)
}

pub(crate) fn reveal_sync_stream(
    context: &str,
    name: &str,
    run_id: &str,
    stored: &[u8],
) -> Result<Vec<u8>> {
    let envelope = parse_stored_blob_envelope(stored).ok_or_else(decryption_failed)?;
    let keyring = Keyring::from_environment(false)?;
    decrypt_bytes(&keyring, &envelope, &sync_aad(context, name, run_id))
}

/// Check the public shape of a protected sync stream without opening it.
///
/// Lazy context creation uses this together with the run ledger's exact-byte
/// digest. It cannot authenticate ciphertext without the missing keyring, but
/// it can refuse to treat arbitrary or orphaned JSON as evidence that a
/// database context already owns durable protected bytes.
pub(crate) fn protected_sync_stream_is_well_formed(stored: &[u8]) -> bool {
    parse_stored_blob_envelope(stored).is_some()
}

fn parse_stored_blob_envelope(stored: &[u8]) -> Option<Envelope> {
    let stored: StoredBlobEnvelope = serde_json::from_slice(stored).ok()?;
    if stored.version != ENVELOPE_VERSION || validate_key_id(&stored.key_id).is_err() {
        return None;
    }
    let nonce = URL_SAFE_NO_PAD.decode(stored.nonce.as_bytes()).ok()?;
    let ciphertext = URL_SAFE_NO_PAD.decode(stored.ciphertext.as_bytes()).ok()?;
    if nonce.len() != NONCE_LENGTH || ciphertext.len() < 16 {
        return None;
    }
    Some(Envelope {
        key_id: stored.key_id,
        nonce,
        ciphertext,
    })
}

fn collect_fields(
    schema: &JsonValue,
    path: &mut Vec<String>,
    fields: &mut Vec<Vec<String>>,
    ancestor_encrypted: bool,
) -> Result<()> {
    let Some(object) = schema.as_object() else {
        return Ok(());
    };
    let encrypted = extension_bool(object.get(FIELD_EXTENSION), FIELD_EXTENSION)?;
    if encrypted {
        if path.is_empty() {
            return Err(invalid(format!(
                "{FIELD_EXTENSION} belongs on a property; use {BODY_EXTENSION} for Markdown"
            )));
        }
        if ancestor_encrypted {
            return Err(invalid(
                "an encrypted schema property cannot contain another encrypted property",
            ));
        }
        fields.push(path.clone());
    }
    if let Some(properties) = object.get("properties") {
        let properties = properties
            .as_object()
            .context("JSON Schema 'properties' must be an object")?;
        for (name, child) in properties {
            path.push(name.clone());
            collect_fields(child, path, fields, ancestor_encrypted || encrypted)?;
            path.pop();
        }
    }
    Ok(())
}

fn extension_bool(value: Option<&JsonValue>, name: &str) -> Result<bool> {
    match value {
        None => Ok(false),
        Some(JsonValue::Bool(value)) => Ok(*value),
        Some(_) => Err(invalid(format!(
            "JSON Schema extension '{name}' must be boolean"
        ))),
    }
}

fn count_enabled_extensions(value: &JsonValue, name: &str) -> Result<usize> {
    let Some(object) = value.as_object() else {
        // Boolean schemas contain no annotations.
        return Ok(0);
    };
    let mut count = usize::from(extension_bool(object.get(name), name)?);

    // Traverse only standard keywords whose values are themselves schemas.
    // Arbitrary instance-valued JSON under `const`, `default`, `examples`, or
    // a property-name map must never be mistaken for an extension placement.
    for keyword in [
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    ] {
        if let Some(child) = object.get(keyword) {
            count += count_enabled_extensions(child, name)?;
        }
    }
    if let Some(items) = object.get("items") {
        match items {
            JsonValue::Array(children) => {
                for child in children {
                    count += count_enabled_extensions(child, name)?;
                }
            }
            child => count += count_enabled_extensions(child, name)?,
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = object.get(keyword).and_then(JsonValue::as_array) {
            for child in children {
                count += count_enabled_extensions(child, name)?;
            }
        }
    }
    for keyword in [
        "$defs",
        "definitions",
        "dependentSchemas",
        "patternProperties",
        "properties",
    ] {
        if let Some(children) = object.get(keyword).and_then(JsonValue::as_object) {
            for child in children.values() {
                count += count_enabled_extensions(child, name)?;
            }
        }
    }
    Ok(count)
}

impl Keyring {
    fn from_environment(require_active: bool) -> Result<Self> {
        let serialized = Zeroizing::new(std::env::var(KEYRING_ENV).map_err(|_| keys_required())?);
        let encoded: HashMap<String, String> =
            serde_json::from_str(serialized.as_str()).map_err(|_| {
                invalid("CR_ENCRYPTION_KEYS must be a JSON object of key IDs to base64url keys")
            })?;
        let mut encoded = EncodedKeys(encoded);
        if encoded.0.is_empty() {
            return Err(invalid("CR_ENCRYPTION_KEYS must contain at least one key"));
        }
        let mut keys = HashMap::new();
        for (id, encoded) in &mut encoded.0 {
            validate_key_id(id)?;
            let decoded =
                Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| {
                    invalid("CR_ENCRYPTION_KEYS contains a key that is not unpadded base64url")
                })?);
            if decoded.len() != KEY_LENGTH {
                return Err(invalid(
                    "every CR_ENCRYPTION_KEYS value must decode to 32 bytes",
                ));
            }
            keys.insert(id.clone(), decoded);
        }
        let active = match std::env::var(ACTIVE_KEY_ENV) {
            Ok(active) if !active.trim().is_empty() => active,
            _ if require_active => {
                return Err(invalid(
                    "CR_ENCRYPTION_ACTIVE_KEY is required for encrypted writes",
                ));
            }
            _ => String::new(),
        };
        if !active.is_empty() {
            validate_key_id(&active)?;
            if !keys.contains_key(&active) {
                return Err(invalid(
                    "CR_ENCRYPTION_ACTIVE_KEY is not present in CR_ENCRYPTION_KEYS",
                ));
            }
        }
        Ok(Self { active, keys })
    }

    fn active_key(&self) -> Result<(&str, &[u8])> {
        let key = self.keys.get(&self.active).ok_or_else(|| {
            invalid("CR_ENCRYPTION_ACTIVE_KEY is not present in CR_ENCRYPTION_KEYS")
        })?;
        Ok((&self.active, key.as_slice()))
    }

    fn decryption_key(&self, key_id: &str) -> Result<&[u8]> {
        self.keys
            .get(key_id)
            .map(|key| key.as_slice())
            .ok_or_else(decryption_failed)
    }
}

struct EncodedKeys(HashMap<String, String>);

impl Drop for EncodedKeys {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

fn validate_key_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid(
            "encryption key IDs must be 1-64 ASCII letters, digits, '.', '-', or '_'",
        ));
    }
    Ok(())
}

fn encrypt_value(keyring: &Keyring, value: &Value, aad: &[u8]) -> Result<Value> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(value).context("protected value cannot be represented as JSON")?,
    );
    Ok(render_field_envelope(&encrypt_bytes(
        keyring,
        plaintext.as_slice(),
        aad,
    )?))
}

fn encrypt_bytes(keyring: &Keyring, plaintext: &[u8], aad: &[u8]) -> Result<Envelope> {
    let (key_id, key) = keyring.active_key()?;
    let mut nonce = vec![0_u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|_| conflict("secure randomness is unavailable"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| decryption_failed())?;
    let authenticated_context = keyed_aad(aad, key_id);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &authenticated_context,
            },
        )
        .map_err(|_| decryption_failed())?;
    Ok(Envelope {
        key_id: key_id.to_owned(),
        nonce,
        ciphertext,
    })
}

fn decrypt_value(keyring: &Keyring, envelope: &Envelope, aad: &[u8]) -> Result<Value> {
    let plaintext = Zeroizing::new(decrypt_bytes(keyring, envelope, aad)?);
    serde_json::from_slice(plaintext.as_slice()).map_err(|_| decryption_failed())
}

fn decrypt_bytes(keyring: &Keyring, envelope: &Envelope, aad: &[u8]) -> Result<Vec<u8>> {
    let key = keyring.decryption_key(&envelope.key_id)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| decryption_failed())?;
    let authenticated_context = keyed_aad(aad, &envelope.key_id);
    cipher
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &authenticated_context,
            },
        )
        .map_err(|_| decryption_failed())
}

fn render_field_envelope(envelope: &Envelope) -> Value {
    let mut fields = Mapping::new();
    fields.insert("version".into(), ENVELOPE_VERSION.into());
    fields.insert("key_id".into(), envelope.key_id.clone().into());
    fields.insert(
        "nonce".into(),
        URL_SAFE_NO_PAD.encode(&envelope.nonce).into(),
    );
    fields.insert(
        "ciphertext".into(),
        URL_SAFE_NO_PAD.encode(&envelope.ciphertext).into(),
    );
    let mut outer = Mapping::new();
    outer.insert(ENVELOPE_KEY.into(), Value::Mapping(fields));
    Value::Mapping(outer)
}

fn parse_field_envelope(value: &Value) -> Option<Envelope> {
    let Value::Mapping(outer) = value else {
        return None;
    };
    if outer.len() != 1 {
        return None;
    }
    let Value::Mapping(fields) = outer.get(Value::String(ENVELOPE_KEY.to_owned()))? else {
        return None;
    };
    parse_envelope_fields(fields)
}

fn field_envelope(value: &Value) -> Result<Envelope> {
    if let Some(envelope) = parse_field_envelope(value) {
        return Ok(envelope);
    }
    let envelope_like = matches!(
        value,
        Value::Mapping(mapping)
            if mapping.contains_key(Value::String(ENVELOPE_KEY.to_owned()))
    );
    if envelope_like {
        Err(decryption_failed())
    } else {
        Err(migration_required())
    }
}

fn render_body_envelope(envelope: &Envelope) -> String {
    format!(
        "{BODY_PREFIX}{}:{}:{}",
        envelope.key_id,
        URL_SAFE_NO_PAD.encode(&envelope.nonce),
        URL_SAFE_NO_PAD.encode(&envelope.ciphertext)
    )
}

fn parse_body_envelope(value: &str) -> Option<Envelope> {
    let encoded = value.strip_prefix(BODY_PREFIX)?;
    let mut parts = encoded.split(':');
    let key_id = parts.next()?.to_owned();
    let nonce = URL_SAFE_NO_PAD.decode(parts.next()?).ok()?;
    let ciphertext = URL_SAFE_NO_PAD.decode(parts.next()?).ok()?;
    if parts.next().is_some() || validate_key_id(&key_id).is_err() || nonce.len() != NONCE_LENGTH {
        return None;
    }
    Some(Envelope {
        key_id,
        nonce,
        ciphertext,
    })
}

fn body_envelope(value: &str) -> Result<Envelope> {
    if let Some(envelope) = parse_body_envelope(value) {
        return Ok(envelope);
    }
    if value.starts_with("cr-encrypted:") {
        Err(decryption_failed())
    } else {
        Err(migration_required())
    }
}

fn parse_envelope_fields(fields: &Mapping) -> Option<Envelope> {
    let expected = BTreeSet::from(["version", "key_id", "nonce", "ciphertext"]);
    let actual = fields
        .keys()
        .map(|key| match key {
            Value::String(key) => Some(key.as_str()),
            _ => None,
        })
        .collect::<Option<BTreeSet<_>>>()?;
    if actual != expected {
        return None;
    }
    let version = fields.get(Value::String("version".into()))?.as_u64()?;
    if version != ENVELOPE_VERSION {
        return None;
    }
    let key_id = fields
        .get(Value::String("key_id".into()))?
        .as_str()?
        .to_owned();
    validate_key_id(&key_id).ok()?;
    let nonce = URL_SAFE_NO_PAD
        .decode(fields.get(Value::String("nonce".into()))?.as_str()?)
        .ok()?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(fields.get(Value::String("ciphertext".into()))?.as_str()?)
        .ok()?;
    if nonce.len() != NONCE_LENGTH {
        return None;
    }
    Some(Envelope {
        key_id,
        nonce,
        ciphertext,
    })
}

fn yaml_get<'a>(mapping: &'a Mapping, path: &[String]) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    let mut value = mapping.get(Value::String(first.clone()))?;
    for part in rest {
        let Value::Mapping(mapping) = value else {
            return None;
        };
        value = mapping.get(Value::String(part.clone()))?;
    }
    Some(value)
}

fn yaml_value_get<'a>(value: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut value = value;
    for part in path {
        let Value::Mapping(mapping) = value else {
            return None;
        };
        value = mapping.get(Value::String(part.clone()))?;
    }
    Some(value)
}

fn yaml_set(mapping: &mut Mapping, path: &[String], value: Value) -> Result<()> {
    let (last, parents) = path.split_last().context("protected field path is empty")?;
    let mut current = mapping;
    for part in parents {
        let next = current
            .get_mut(Value::String(part.clone()))
            .context("protected field parent is absent")?;
        let Value::Mapping(next) = next else {
            return Err(invalid("protected field parent must be an object"));
        };
        current = next;
    }
    current.insert(Value::String(last.clone()), value);
    Ok(())
}

fn record_aad(
    context: Option<&str>,
    collection: &str,
    id: &str,
    path: &[String],
    purpose: &str,
) -> Result<Vec<u8>> {
    let context = context.ok_or_else(context_required)?;
    let mut result = Vec::new();
    result.extend_from_slice(AAD_DOMAIN);
    append_component(&mut result, context);
    append_component(&mut result, collection);
    append_component(&mut result, id);
    append_component(&mut result, purpose);
    for part in path {
        append_component(&mut result, part);
    }
    Ok(result)
}

fn sync_aad(context: &str, name: &str, run_id: &str) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(AAD_DOMAIN);
    append_component(&mut result, context);
    append_component(&mut result, "sync-run");
    append_component(&mut result, name);
    append_component(&mut result, run_id);
    result
}

fn keyed_aad(context: &[u8], key_id: &str) -> Vec<u8> {
    let mut result = context.to_vec();
    append_component(&mut result, key_id);
    result
}

fn append_component(target: &mut Vec<u8>, value: &str) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value.as_bytes());
}

fn pointer_attribute_path(pointer: &str) -> Result<Option<Vec<String>>> {
    let Some(path) = pointer.strip_prefix("/attributes/") else {
        return Ok(None);
    };
    path.split('/')
        .map(|part| Ok(part.replace("~1", "/").replace("~0", "~")))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn document_json(document: &Document) -> Result<JsonValue> {
    Ok(serde_json::json!({
        "attributes": serde_json::to_value(&document.attributes)
            .context("front matter cannot be represented as JSON")?,
        "body": document.body,
    }))
}

fn migration_required() -> anyhow::Error {
    conflict(
        "protected data is still plaintext; export it before enabling encryption and import it into a newly encrypted record",
    )
}

fn keys_required() -> anyhow::Error {
    invalid("CR_ENCRYPTION_KEYS is required to read protected data")
}

fn context_required() -> anyhow::Error {
    conflict("database encryption context is missing")
}

fn decryption_failed() -> anyhow::Error {
    conflict("protected data could not be decrypted")
}

fn clone_public_error(error: &anyhow::Error) -> anyhow::Error {
    match crate::DomainError::of(error) {
        Some(domain) => anyhow::Error::new(domain.clone()),
        None => conflict("protected data could not be decrypted"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_policy_collects_nested_fields_and_body() {
        let schema = serde_json::json!({
            "type": "object",
            "x-cr-encrypted-body": true,
            "properties": {
                "name": { "type": "string" },
                "contact": {
                    "type": "object",
                    "properties": {
                        "token": { "type": "string", "x-cr-encrypted": true }
                    }
                }
            }
        });
        let policy = EncryptionPolicy::from_schema(Some(&schema)).unwrap();
        assert!(policy.protects_body());
        assert_eq!(policy.field_paths(), &[vec!["contact", "token"]]);
    }

    #[test]
    fn malformed_extension_is_rejected() {
        let schema = serde_json::json!({
            "properties": { "secret": { "x-cr-encrypted": "yes" } }
        });
        let error = EncryptionPolicy::from_schema(Some(&schema)).unwrap_err();
        assert!(error.to_string().contains("must be boolean"));
    }

    #[test]
    fn annotations_outside_the_direct_properties_tree_are_rejected() {
        let schema = serde_json::json!({
            "type": "array",
            "items": { "type": "string", "x-cr-encrypted": true }
        });
        let error = EncryptionPolicy::from_schema(Some(&schema)).unwrap_err();
        assert!(error.to_string().contains("root 'properties' tree"));

        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "nested": { "type": "object", "x-cr-encrypted-body": true }
            }
        });
        let error = EncryptionPolicy::from_schema(Some(&schema)).unwrap_err();
        assert!(error.to_string().contains("collection schema root"));
    }

    #[test]
    fn instance_values_and_property_names_are_not_extension_placements() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "x-cr-encrypted": { "type": "string" },
                "x-cr-encrypted-body": { "type": "boolean" },
                "example": {
                    "type": "object",
                    "const": { "x-cr-encrypted": "ordinary application data" }
                }
            },
            "default": { "x-cr-encrypted-body": "also ordinary" }
        });
        assert!(
            EncryptionPolicy::from_schema(Some(&schema))
                .unwrap()
                .is_empty()
        );
    }
}
