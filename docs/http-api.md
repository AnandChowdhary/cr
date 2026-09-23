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

`GET /health` remains public so process supervisors can check readiness, and so
is `GET /static/<name>` for the UI's embedded script: a `<script src>` tag has
no way to send a bearer header, and the file is part of the binary rather than
part of the database. For a database without RBAC, binding to a non-loopback address without a token prints
a warning. An RBAC-enabled server refuses every non-loopback bind because its
user switcher is an owner impersonation console, not a network authentication
boundary. The built-in server does not terminate TLS; use a trusted reverse
proxy for access across a network.

The token mechanism is an HTTP bearer header. A normal browser address-bar request cannot attach that header, so the built-in HTML UI is currently intended for the default loopback-without-token setup or a trusted proxy that injects authentication. A browser login/session flow is tracked in `TODO.md`.

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

REST list, search, and `cr list --sort-by` sort stored record data only. The server-rendered views' `$created_at` and `$updated_at` are audit-derived, so asking a plain record scan for them is refused by name rather than quietly replaying the whole journal per request.

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

## Generated OpenAPI

`GET /openapi.json` returns an OpenAPI 3.1 document covering every HTTP route. It is generated from the live database whenever it is requested. Each valid `.cr/schemas/<collection>.json` file is included under `components.schemas`, and `x-cr-collection-schemas` maps collection names to their exact component references. Schema-only collections appear even before their first record is created.

This means changing a collection's JSON Schema updates the OpenAPI document without restarting the server. Schemaless collections use the generic open front matter object.

The complete endpoint list is discoverable from that document. The main resource routes are:

```text
GET    /api/v1/collections
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
