# Encrypt selected values at rest

Encryption is opt-in and schema-directed. Declare it from the CLI while the
collection is new and empty:

```sh
cr schema encrypt accounts credentials.api_token
cr schema encrypt-body accounts
```

The first command creates `.cr/schemas/accounts.json` when needed, preserves
existing JSON Schema constraints, and puts `x-cr-encrypted: true` on the
selected property. Dotted paths create nested `properties`. The second puts
`x-cr-encrypted-body: true` on the schema root. Both are idempotent and require
collection ownership when RBAC is enabled.

A new marker is refused once the collection has a record or audit history.
Changing the marker would not erase plaintext history and would make existing
storage unreadable, so migrate by exporting the plaintext and importing it
into a newly encrypted collection instead. An already-present marker remains a
successful no-op regardless of collection age.

The two commands above produce the same policy as this hand-written schema:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "x-cr-encrypted-body": true,
  "properties": {
    "name": { "type": "string" },
    "credentials": {
      "type": "object",
      "properties": {
        "api_token": {
          "type": "string",
          "x-cr-encrypted": true
        }
      }
    }
  }
}
```

## How protected values are stored

The schema still describes plaintext. `create`, `get`, `list`, `search`,
`update`, sync, REST, and the local app accept and return the same logical
values as an unencrypted collection. Schema validation, filters, and search run
over decrypted values in memory. The Markdown file and audit change values use
versioned XChaCha20-Poly1305 envelopes instead, with a fresh random nonce and
authenticated context binding the collection, record ID, logical field path,
purpose, format version, and the random database identity stored in
`.cr/encryption.json`. Moving or cloning the complete database does not
invalidate that context, but copying an envelope into an independently
initialized database fails authentication even when both databases use the
same keyring. Losing the context file makes existing ciphertext unreadable; it
is not a secret and belongs in Git and backups. Databases created by an older
version receive one immediately before their first encrypted write, but CR
never regenerates it when protected records or history already exist.
`audit verify` checks stored ciphertext hashes without
keys; `audit log` needs the keys because it renders logical values.

## Keys and rotation

Keys stay outside the database and its Git history. Configure an active key for
writes and a JSON keyring for reads:

```sh
key=$(openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
export CR_ENCRYPTION_ACTIVE_KEY=primary
export CR_ENCRYPTION_KEYS="{\"primary\":\"$key\"}"
```

Each value must be an unpadded base64url encoding of exactly 32 random bytes.
Key IDs are stored with envelopes, so rotation means adding the old and new
keys to the keyring and selecting the new ID as active. New or changed protected
values use the active key; unchanged values keep their existing envelope.
Retain every old key needed to read audit history.

## Import secrets from the environment

Import a secret directly from an environment variable without placing its
value in `cr`'s process arguments:

```sh
export OPENAI_API_KEY='the-value-supplied-by-your-secret-manager'

cr schema encrypt secrets value
cr schema encrypt-body secrets
cr create secrets production-openai \
  --set name=OPENAI_API_KEY \
  --set environment=production \
  --set-env value=OPENAI_API_KEY

cr update secrets production-openai \
  --set-env value=OPENAI_API_KEY
```

`--set-env KEY=ENV` is available on `create` and `update`. The variable must
exist and contain UTF-8; its value is always stored as one exact YAML string,
so strings such as `true`, `null`, and values with newlines do not change type.
Assigning the same field through both `--set` and `--set-env` is rejected.
`--set-env` changes only how input is read: encrypted storage still requires
the schema marker above.

## The encryption manifest

The stored front matter also carries a reserved `$cr_encryption` manifest. New
writes reserve that name even in unencrypted collections. With no encryption
policy, an unrelated managed update or direct `save` may preserve an unchanged
legacy application value under that name; adding or changing it is rejected,
and removing it is allowed. This grandfathering never applies under an
encryption policy or when a valid manifest owns actual CR envelopes. The
manifest prevents removing or moving schema markers from silently exposing
ciphertext as ordinary application data. Existing plaintext does not become
protected merely because a marker was added: reads and `audit baseline` fail
with an explicit migration-required conflict. Export the plaintext before
enabling the marker, then import it into a newly encrypted record or database.
That boundary is deliberate—an in-place audit event would preserve the old
plaintext in history and falsely imply migration had removed it.

When the current schema declares no encryption, logical reads still consult
verified audit lifecycle state before trusting the mutable record bytes. A
present audited state owns protected storage only when its authenticated
manifest owns an actual envelope; deletion carries that ownership into the
tombstone, and a later audited ordinary create resets it. This prevents
removing or deforming both the manifest and envelope syntax—or copying a
stripped file back after deletion—from turning protected storage into ordinary
output. Standalone envelope-shaped application data and manifests whose
optional protected locations are all absent remain ordinary. The tradeoff is
fail-closed recovery: if audit history is corrupt or cannot be verified, CR
cannot prove that an empty-policy record is unprotected, so logical reads and
`check` report a redacted unreadable/conflict result until the history is
repaired. Healthy databases retain the same transparent logical UX.

## Direct edits and previews

Direct filesystem edits remain possible for unprotected values as long as the
envelopes and manifest are preserved; `cr save` refuses plaintext substituted
at a protected path. `cr get` renders encrypted records as canonical plaintext
Markdown, while unencrypted records retain their historical exact-byte output.
Preview approval is explicitly unavailable when a change needs fresh
ciphertext: reproducing the same preview digest would otherwise require nonce
reuse, deterministic encryption, or a larger stateful approval protocol.

## What encryption does not protect

This is at-rest confidentiality, not selective erasure. A process with the
keyring sees plaintext, filesystem paths and record identities remain visible,
and one retained key may decrypt many historical values. Per-record key
destruction, retention windows, redaction policy, and audited key management
remain roadmap work. The reserved `users` policy collection cannot opt its
authorization-critical fields into encryption.

## Audit history and retries

Audit history returned by the CLI, REST API, and local app is a logical
projection: protected values in `changes` are decrypted for the caller. The
event `hash` and any `authorization.approved_changes` digest still commit to the
exact stored ciphertext bytes, so they cannot be recomputed by serializing that
plaintext projection. `audit verify` always verifies the stored representation.

The same boundary applies to idempotent mutations. Their durable result keeps
the exact ciphertext Markdown and ciphertext-derived record version so a retry
does not generate a nonce or event. After current authorization succeeds, CR
decrypts that stored result in memory and returns the original logical record.
Authorized history likewise projects `changes`, version 3 `after_snapshot`
Markdown, and idempotency-result Markdown to plaintext, while the raw journal,
pending mutation, hashes, and record versions continue to commit to ciphertext.
The request identity is an HMAC-SHA-256 over canonical typed plaintext keyed by
the never-stored retry key, so the journal is not an offline dictionary oracle
for a protected request value.
