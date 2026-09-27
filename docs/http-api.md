# REST API

`cr serve` answers a JSON API under `/api/v1` beside the [web UI](web-ui.md),
on the same address. [Start the server](web-ui.md#start-the-server) first; the
examples below use the default `http://127.0.0.1:3000`.

## Authentication and identity

Local access has no token by default. Set `CR_API_TOKEN` before starting the server to require a bearer token for the HTML views, `/openapi.json`, and every `/api/v1` endpoint:

```sh
export CR_API_TOKEN='replace-with-a-long-random-token'
cr serve
```

Then include it in requests:

```sh
curl http://127.0.0.1:3000/api/v1/identity \
  -H "Authorization: Bearer $CR_API_TOKEN"
```

`GET /health` and `GET /ready` remain public so process supervisors and load
balancers can [probe them](#health-and-readiness), and so is
`GET /static/<name>` for the UI's embedded script: a `<script src>` tag has
no way to send a bearer header, and the file is part of the binary rather than
part of the database. For a database without RBAC, binding to a non-loopback address without a token prints
a warning. An RBAC-enabled server refuses every non-loopback bind because its
user switcher is an owner impersonation console, not a network authentication
boundary, unless `--require-token` or `--cloudflare-access` replaces that console with authenticated principals. The built-in server does not terminate TLS; use a trusted reverse
proxy for access across a network.

The token mechanism is an HTTP bearer header. A normal browser address-bar request cannot attach that header, so the built-in HTML UI is intended for the default loopback-without-token setup, for [Cloudflare Access](#sign-in-through-cloudflare-access), or for another trusted proxy that injects authentication. A browser login/session flow of cr's own is tracked in `TODO.md`.

`CR_API_TOKEN` is one shared secret, and whoever holds it acts as the owner who
launched the server. Under access control, a caller can instead present a
[principal token](access-control.md#authenticate-principals-to-a-server-with-tokens)
issued for its own registered user:

```sh
curl http://127.0.0.1:3000/api/v1/identity \
  -H "Authorization: Bearer $CR_TOKEN"
```

The request then acts as that principal, and `/api/v1/identity` reports how:

```json
{
  "actor": "Nightly <nightly@example.com>",
  "principal": "nightly@example.com",
  "impersonated_by": null,
  "authentication": { "method": "token", "credential": "1f0c9a7b3e2d4c65" },
  ...
}
```

A principal token that does not authenticate is answered `401 unauthorized`,
whatever else the server would accept. `cr serve --require-token` accepts
nothing else: every request but `/health`, `/ready`, and `/static` needs a
principal token, and the server may then bind beyond loopback.

### Sign in through Cloudflare Access

Behind Cloudflare Access, `cr serve --cloudflare-access <team-domain>
--cloudflare-access-aud <tag>` signs each request in as the user whose email
the signed `Cf-Access-Jwt-Assertion` header names; [access
control](access-control.md#sign-people-in-through-cloudflare-access) has the
checks it makes. Cloudflare adds the header, so a browser and a `curl` through
Access need nothing more, and `/api/v1/identity` reports who that is:

```json
{
  "actor": "Ada Lovelace <ada@example.com>",
  "principal": "ada@example.com",
  "impersonated_by": null,
  "authentication": { "method": "cloudflare-access", "credential": "7335d417-61da-459d-899c-0a01c76a2f94" },
  ...
}
```

| Answer | When |
| --- | --- |
| `401 unauthorized` | No assertion; one that does not verify, is for another team or application, has expired, or names no email (a service token); or an email that is not exactly one active user's. The message says which. Unsigned `Cf-Access-Authenticated-User-Email` headers and `CF_Authorization` cookies never count. |
| `403 cross_site_request` | A browser said another site started a request that changes data: `Sec-Fetch-Site` other than `same-origin`, or an `Origin` that is not this host. |
| `503 authentication_unavailable` | The team's signing keys could not be fetched, and the assertion's key is not already held. |

A principal token is refused under `--cloudflare-access` alone. With
`--require-token` as well, a request may present either, and a principal token
wins when both arrive — which is what a script reaching the server through
Access with a service token sends. HTML pages answer a refusal with a page
rather than the JSON envelope, since a person following a link reads it.

Set the audit actor for one request with `X-CR-Actor`:

```sh
curl -X POST http://127.0.0.1:3000/api/v1/collections/deals/records \
  -H 'Content-Type: application/json' \
  -H 'X-CR-Actor: jane@example.com' \
  -d '{
    "id": "acme-renewal",
    "front_matter": {
      "name": "Acme renewal",
      "status": "won",
      "value": 25000
    },
    "markdown": "Renewal signed."
  }'
```

Without the header, requests use the identity resolved when the server starts. As with `--actor`, this header provides attribution, not authenticated personal identity.

Three more headers carry the agent, the approval, and the intent, with exactly
the same trust boundary — the server records what it is told and authenticates
none of it:

```sh
curl -X PATCH http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal \
  -H 'Content-Type: application/json' \
  -H 'X-CR-Actor: anand@example.com' \
  -H 'X-CR-Agent: {"id":"claude-code","session":"6d1baa69"}' \
  -H 'X-CR-Authorization: {"mode":"delegated","grant":"acceptEdits"}' \
  -H 'X-CR-Intent: {"request":{"text":"mark it closed-won"},"rationale":{"text":"set status to closed-won"}}' \
  -d '{ "front_matter": { "status": "closed-won" } }'
```

Each accepts the same compact or JSON form as its command-line option, and is
recorded with `detected_from: header`. HTTP header values are visible ASCII, so
non-ASCII intent text must use JSON `\uXXXX` escapes. `GET /api/v1/identity`
returns the complete attribution a request would record.

`X-CR-Approved-Changes` is the approval header and can refuse a
request: it carries the digest from a `preview=true` response, and a mutation
whose change set hashes differently is rejected with `409 approval_mismatch`.

`Idempotency-Key` is the retry header for supported single-record mutations.
It must contain 16–128 visible-ASCII bytes; callers should generate it with at
least 128 bits of randomness. An exact retry returns the original status and
JSON result without adding history; mismatched reuse is `409
idempotency_conflict`.

## CRUD requests

Fetch one record:

```sh
curl http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal
```

The response includes the identity, relative path, domain-separated exact-byte
version, typed front matter, and Markdown body. Its `ETag` header is the quoted
form of `version`:

```json
{
  "collection": "deals",
  "id": "acme-renewal",
  "path": "records/deals/acme-renewal.md",
  "version": "sha256:3d8d9a6f…",
  "front_matter": {
    "name": "Acme renewal",
    "status": "won",
    "value": 25000
  },
  "markdown": "Renewal signed."
}
```

Fetch the exact Markdown file or one dotted field:

```sh
curl http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal/document
curl http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal/fields/owner.email
```

PATCH performs an atomic deep merge into front matter. `remove` explicitly removes dotted fields, while `markdown` replaces the Markdown body. JSON `null` remains a real front matter value and does not mean deletion:

```sh
curl -X PATCH http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal \
  -H 'Content-Type: application/json' \
  -d '{
    "front_matter": {
      "status": "won",
      "owner": { "email": "sales@example.com" }
    },
    "remove": ["temporary_note"],
    "markdown": "Closed-won notes."
  }'
```

Replace a complete document only with the ETag from a prior read:

```sh
etag=$(curl -sD - http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal \
  -o /dev/null | awk 'tolower($1) == "etag:" { print $2 }' | tr -d '\r')
curl -X PUT http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal \
  -H 'Content-Type: application/json' \
  -H "If-Match: $etag" \
  -d '{"front_matter":{"status":"won"},"markdown":"Closed-won notes."}'
```

`If-Match` also accepts a comma-separated list of strong CR record ETags or
`*`. Weak validators never match. Conditional previews check the same version
without writing, and `X-CR-Approved-Changes` remains an independent guard over
the resulting audit change set.

Create a relation, remove it, or delete a record:

```sh
curl -X POST http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal/links \
  -H 'Content-Type: application/json' \
  -d '{
    "relation": "company",
    "target_collection": "companies",
    "target_id": "acme"
  }'

curl -X DELETE http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal/links/company/companies/acme

curl -X DELETE http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal
```

Removing a relation accepts the same `If-Match`, `Idempotency-Key`, and
`preview=true` as adding one. Removing a reference that is not there changes
nothing, and the target does not have to exist.

List the records that link to one, paginated like any list. `from`,
`relation`, `where`, `where_expr`, `sort`, and `direction` narrow and order
the sources, and each result names the relations holding the reference:

```sh
curl 'http://127.0.0.1:3000/api/v1/collections/companies/records/acme/backlinks?from=deals&sort=value&direction=desc'
```

Read, review, install, or remove a collection's schema. `PUT` takes the
schema itself as the body and answers with a review naming every existing
record that fails it; `preview=true` only reviews, and a schema some record
fails is refused with `422` unless `allow_violations=true`. The same rules as
`cr schema set` apply: owners only, and no change to encryption or record
ownership.

```sh
curl -X PUT 'http://127.0.0.1:3000/api/v1/collections/deals/schema?preview=true' \
  -H 'Content-Type: application/json' \
  -d '{ "type": "object", "required": ["stage"] }'
```

Follow relations outward from a record with `traverse`. `depth` (1 to 10) and
repeated `relation` parameters bound it, and `expand=true` returns a nested
tree instead of a flat graph of `nodes` and `edges`:

```sh
curl 'http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal/traverse?depth=2&expand=true'
```

## Filtering, search, and pagination

Repeated `where` parameters are combined with AND and retain YAML types. URL-encode the `=` when writing URLs manually:

```sh
curl 'http://127.0.0.1:3000/api/v1/collections/deals/records?where=status%3Dwon&where=active%3Dtrue&limit=50&offset=0'
curl 'http://127.0.0.1:3000/api/v1/collections/deals/records?where_expr=value%3E%3D10000&where_expr=name%20contains%20renewal'
curl 'http://127.0.0.1:3000/api/v1/collections/deals/records?sort=value&direction=desc&limit=50'
```

`filter` takes the same boolean filter language as the CLI's `--filter`, on
lists, search, and backlinks, and combines with `where` and `where_expr` by
AND. URL-encode it:

```sh
curl -G 'http://127.0.0.1:3000/api/v1/collections/deals/records' \
  --data-urlencode 'filter=stage in [open, won] AND (value >= 10000 OR owner is null)'
```

A filter that does not parse is refused with `422 validation_failed` and a
message naming the column, as is one whose parentheses and `NOT`s nest more
than 64 levels deep.

`sort` orders lists, search, and backlinks before they are paginated, with the
keys `--sort` takes: `FIELD`, `FIELD:asc`, or `FIELD:desc`, comma-separated or
in repeated parameters, most significant first. A record missing a key's field
follows the records that have it in either direction, and collection and then
record ID, ascending, order whatever every key leaves tied, so an `offset` names
the same place on every request. `direction=desc` is the one-key spelling of
`FIELD:desc` and still works with a single `sort`; with several keys, or a key
that has its own direction, it is refused. More than five keys, a field named
twice, and a key written `-FIELD` are refused with `422 validation_failed`:

```sh
curl 'http://127.0.0.1:3000/api/v1/collections/deals/records?sort=stage&sort=value:desc&limit=50'
curl 'http://127.0.0.1:3000/api/v1/collections/deals/records?sort=stage,value:desc,owner.name'
```

`select` returns only the named fields, on lists, search, backlinks, a single
record, and `traverse`. Each result becomes a flat object keyed by the
selectors, and a single record keeps its `ETag`:

```sh
curl 'http://127.0.0.1:3000/api/v1/collections/deals/records?select=$id,value,owner.name'
```

Count and summarize a collection with `count`, which takes the same filters as
a list plus `by`, `sum`, `avg`, `min`, and `max`, and answers with the same
JSON as `cr count --json`:

```sh
curl 'http://127.0.0.1:3000/api/v1/collections/deals/count?by=stage&sum=value&avg=value'
```

List and search responses contain compact `{ path, front_matter }` records inside a page:

```json
{
  "data": [
    {
      "path": "records/deals/acme-renewal.md",
      "front_matter": { "status": "won", "active": true }
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "returned": 1,
    "total": 1,
    "has_more": false,
    "next_offset": null,
    "previous_offset": null
  }
}
```

Search supports the same targets and matching modes as `cr search`:

```sh
curl 'http://127.0.0.1:3000/api/v1/search?q=follow%20up&collection=deals&target=body&ignore_case=true&limit=50'
curl 'http://127.0.0.1:3000/api/v1/search?q=renewal&collection=deals&where_expr=value%3E%3D10000'
curl 'http://127.0.0.1:3000/api/v1/search?q=renewal&collection=deals&sort=value&direction=desc'
curl 'http://127.0.0.1:3000/api/v1/search?q=%5Ewon%24&collection=deals&target=field&field=status&regex=true'
```

Allowed targets are `document`, `front_matter`, `field`, `body`, and `path`. The default target is `document`. The default maximum page size is 200 and can be changed with `cr serve --max-page-size N`. Offsets are deterministic because records are ordered by collection and ID.

REST list, search, backlinks, and `cr list --sort` sort stored record data only. The server-rendered views' `$created_at` and `$updated_at` are audit-derived, so asking a plain record scan for them is refused by name rather than quietly replaying the whole journal per request.

Audit-log pages deliberately return `total: null`: the journal reads only the requested newest window rather than loading the entire segmented history to count it. `has_more` and `next_offset` remain available.

## Direct edits and audit endpoints

The REST equivalents of the direct-edit and audit commands are:

```text
GET  /api/v1/status
GET  /api/v1/check
POST /api/v1/save
GET  /api/v1/audit/log
GET  /api/v1/audit/head
GET  /api/v1/audit/verify
POST /api/v1/audit/baseline
```

For example, accept selected direct edits:

```sh
curl -X POST http://127.0.0.1:3000/api/v1/save \
  -H 'Content-Type: application/json' \
  -H 'X-CR-Actor: editor@example.com' \
  -d '{
    "records": ["deals/acme-renewal"],
    "message": "Reviewed direct Markdown edit"
  }'
```

Use `{"all": true}` instead of `records` to accept every reported change.

`GET /api/v1/check` returns the same report as the command, with findings paginated by `limit` and `offset` and an optional `collection` scope:

```sh
curl 'http://127.0.0.1:3000/api/v1/check?limit=20'
```

It answers `200` whether or not it found anything — the findings are the resource, so a broken database is not an HTTP error. The `summary` object sits beside the page rather than inside it, so a client reading one page can still tell a clean database from a broken one. Decide from `summary.errors`, which is what the CLI's exit status is computed from.

`GET /api/v1/audit/verify` and `GET /api/v1/check` judge the [signed
checkpoint](audit.md#sign-checkpoints) against the public keys in repeatable
`trusted_key` parameters, and against the server's `CR_AUDIT_TRUSTED_KEYS`
when a request gives none. A request may only give keys inline; a value that is
not an `ed25519:` key is `422 validation_failed`, because a caller must not be
able to name a file for the server to read. A verification that fails the
signature check is `409 signature_mismatch`, with a message that names
sequences, hashes, and key IDs and never a path:

```sh
curl 'http://127.0.0.1:3000/api/v1/audit/verify?trusted_key=ed25519:wJ_mDPbr-ScbnvgC2v5ufoxJabn94Z892fBDmyGt7gk'
```

```json
{
  "entries": 42,
  "records_checked": 17,
  "head": { "sequence": 42, "hash": "sha256:9f2c…" },
  "anchor": { "state": "matched", "sequence": 42 },
  "signature": { "state": "matched", "sequence": 42, "key_id": "sha256:58e7…" }
}
```

`signature.state` is `matched`, `behind` (with `head`), `empty` for a journal
with no events, or `unverified` when a signed checkpoint exists and no trusted
key was given. The field is omitted when there is neither, so an unsigned
database verifies to the same response it always did.

## Health and readiness

Two public routes answer a probe, and they answer different questions. Both
stay public under `CR_API_TOKEN`, `--require-token`, and `--cloudflare-access`,
so a deploy that restarts the server should check `/ready` — or `/health` for
liveness alone — rather than a route that needs signing in, such as
`/openapi.json`.

`GET /health` is liveness: the process is running and answering HTTP. It reads
nothing, always answers `200 {"status":"ok"}`, and is what a supervisor should
restart the process on.

`GET /ready` is readiness: whether the database behind the server can be used
right now. It answers `200` when every check passes:

```json
{ "status": "ready" }
```

and `503` otherwise, listing every check that ran, in order, and the request ID
its log lines are under:

```json
{
  "status": "not_ready",
  "checks": [
    { "name": "database", "ok": true },
    { "name": "config", "ok": true },
    { "name": "audit_recovery", "ok": false, "code": "pending_mutation" },
    { "name": "sync_recovery", "ok": true },
    { "name": "journal", "ok": true }
  ],
  "request_id": "5d0e47a1c9b3f286"
}
```

| Check | Code | Meaning, and what clears it |
| --- | --- | --- |
| `database` | `database_unreachable` | The root, `.cr/`, or the records directory cannot be opened, or `.cr/` or the records directory has become a symbolic link. When this fails it is the only check listed, because every other one reads beneath it. |
| `config` | `config_invalid` | `.cr/config.yaml` no longer loads as `cr` would load it at startup: it does not parse, or names an unsupported version, an unknown key, an unsafe `data_dir`, or a zero limit. The running server keeps the configuration it started with; the next `cr` command, and the next start, would refuse. |
| `audit_recovery` | `pending_mutation` | A mutation was interrupted — its process crashed or was killed — and is waiting for recovery. The next request that reads the audit journal, any `cr` command, or a restart finishes or discards it. |
| `audit_recovery` | `audit_recovery_unreadable` | Whether one is waiting could not be determined. |
| `sync_recovery` | `interrupted_sync_run` | A sync run stopped partway through applying its records. `cr sync recover <name> --check` describes it and `cr sync recover <name>` completes it; the log line names the sync. |
| `sync_recovery` | `sync_recovery_unreadable` | Whether one is waiting could not be determined. |
| `journal` | `journal_warming` | The server has not finished the verified walk of the audit journal it starts when it begins listening. Requests that read audited state wait for that walk, so it clears by itself. |
| `journal` | `journal_unverified` | The last walk of the journal failed. The next request that reads the journal walks it again and logs why; `cr audit verify` says the same. |
| `journal` | `journal_changed` | The newest event on disk is behind, or different from, the head this server verified: events it verified are gone or were rewritten. |
| `journal` | `journal_unreadable` | The newest audit segment, or its last event, cannot be read. |
| `cloudflare_access` | `cloudflare_access_keys_pending` | Only under `--cloudflare-access`: the team's signing keys have not been fetched yet. The server fetches them when it starts, and a probe starts the fetch if nothing has, so it clears by itself. |
| `cloudflare_access` | `cloudflare_access_keys_unavailable` | The last fetch of the keys failed and none are held, so nobody can sign in. The log line says why — a mistyped team domain is a `404` — and the next sign-in or probe tries again, no more than once every ten seconds. |

Names and codes are stable, and they are all a probe is told: never a path, a
record, a sync, or a count. Each failing check writes one line to the server's
standard error under the request ID, with the reason:

```text
cr error request_id=5d0e47a1c9b3f286 status=503 code=pending_mutation method=GET path=/ready detail="an interrupted mutation is waiting for recovery; the next request that reads the audit journal, or any cr command, finishes or discards it"
```

Every check is cheap and none of them waits. The probe reads the configuration,
lists two directories, reads the newest audit segment, however long the
history is, and under `--cloudflare-access` asks whether signing keys are held; it never walks the journal from its first event, which is what
`GET /api/v1/audit/verify` and `GET /api/v1/check` are for. It never waits for
a lock either. Every mutation writes its pending file while it holds the audit
lock, and every sync run keeps its ledger while it holds the sync application
lock, so the probe only reports one when nobody holds the lock that owns it:
a write or an import in progress is not a failure. Nor does readiness repair
anything: it does not recover a pending mutation or sync run, and after the
server's first walk it does not walk the journal again. A load balancer that
stops sending traffic to a server that is not ready therefore also stops
whatever request would have recovered it; clear the condition with the command
in the table, or a restart.

## Generated OpenAPI

`GET /openapi.json` returns an OpenAPI 3.1 document covering every HTTP route. It is generated from the live database whenever it is requested. Each valid `.cr/schemas/<collection>.json` file is included under `components.schemas`, and `x-cr-collection-schemas` maps collection names to their exact component references. Schema-only collections appear even before their first record is created.

This means changing a collection's JSON Schema updates the OpenAPI document without restarting the server. Schemaless collections use the generic open front matter object.

The complete endpoint list is discoverable from that document. The main resource routes are:

```text
GET    /api/v1/collections
GET    /api/v1/collections/{collection}/count
GET    /api/v1/collections/{collection}/schema
PUT    /api/v1/collections/{collection}/schema
DELETE /api/v1/collections/{collection}/schema
GET    /api/v1/collections/{collection}/records
POST   /api/v1/collections/{collection}/records
GET    /api/v1/collections/{collection}/records/{id}
PATCH  /api/v1/collections/{collection}/records/{id}
DELETE /api/v1/collections/{collection}/records/{id}
POST   /api/v1/collections/{collection}/records/{id}/links
DELETE /api/v1/collections/{collection}/records/{id}/links/{relation}/{target_collection}/{target_id}
GET    /api/v1/collections/{collection}/records/{id}/backlinks
GET    /api/v1/collections/{collection}/records/{id}/traverse
GET    /api/v1/search
```

Errors use a stable JSON envelope and appropriate HTTP status such as `400`, `401`, `404`, `409`, `413`, or `422`:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "record does not match schema for collection 'deals'",
    "request_id": "3f1c9a70b52d4e18"
  }
}
```

`message` is written for the caller and never contains a filesystem path, an
operating-system error, or other server-internal context. A missing record
names itself by collection and ID:

```json
{
  "error": {
    "code": "not_found",
    "message": "record deals/nope does not exist",
    "request_id": "9b40e2c1d7a35f66"
  }
}
```

A request the transport cannot decode is refused before it reaches the
database, in the same envelope: `400 invalid_json` for a body, `400
invalid_query` for a query string, and `400 invalid_path` for a path segment
that is not UTF-8 once percent-decoded. A collection, record, or view name
the filesystem cannot store, because it is too long or holds a NUL byte, is
`422 validation_failed`, and so is front matter nested more than 64 levels
deep.

An unexpected failure returns `500` with a fixed generic message. Every
response, including successful ones, carries an `X-Request-Id` header that
matches `error.request_id`, and every error writes one line to the server's
standard error containing the request ID, method, path, status, code, and the
complete diagnostic chain:

```text
cr error request_id=9b40e2c1d7a35f66 status=404 code=not_found method=GET path=/api/v1/collections/deals/records/nope detail="record deals/nope does not exist: could not read record /srv/crm/records/deals/nope.md: No such file or directory (os error 2)"
```

Server-rendered HTML error pages apply the same rules and display the request
ID so it can be quoted in a report.

Every response, the JSON API's, `/health`'s, and `/static`'s included, also
carries `X-Content-Type-Options: nosniff`, so a browser never runs an answer as
a script or applies it as a stylesheet unless its `Content-Type` says it is
one.
