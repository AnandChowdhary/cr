# Security policy

`cr` stores a database as plain Markdown files and claims that every accepted
change extends a tamper-evident audit chain. Anything that breaks that claim —
or that lets a request read or write outside the database root — is a security
issue, not a bug report.

Collections may opt selected values into encrypted storage. Those values use
XChaCha20-Poly1305 and environment-provided keys; key material must not be
committed beside the database. Protected record values, bodies, audit history,
pending mutations, and interrupted-sync streams are ciphertext at rest.
`.cr/encryption.json` is a non-secret portable database identity, must be kept
with clones and backups, and prevents ciphertext swaps between independently
initialized databases. Sync adapters do not inherit the storage keyring and
their bounded stdout is held in memory. Encryption does not protect a running
`cr` process that has the keyring, record identities and paths, unmarked values,
sync checkpoints, adapter stderr, or plaintext that was audited before
encryption was enabled. Losing an old key makes every envelope under that
key—including audit history—unreadable; losing the database context makes all
protected data unreadable.
Treat checkpoints and stderr as non-secret operational metadata: never place
credentials or other confidential values in either surface.

## Reporting a vulnerability

Please report privately. **Do not open a public issue.**

- Preferred: [open a private security advisory](https://github.com/AnandChowdhary/cr/security/advisories/new).
  This is a private channel between you and the maintainer, and it lets us
  credit you and issue an advisory when a fix ships.
- Alternative: email <mail@anandchowdhary.com> with `cr security` in the subject.

A useful report includes the version or commit, the platform, a minimal
reproduction (ideally a small database directory plus the commands or HTTP
requests), what you expected, and what happened instead.

This is a single-maintainer project, so please treat these as intentions rather
than guarantees: acknowledgement within a week, an assessment with a plan or a
reasoned decline within two weeks, and coordinated public disclosure once a fix
is available. If you have not heard back in two weeks, a nudge is welcome.

Please give the maintainer a reasonable opportunity to fix an issue before
disclosing it publicly. Testing must be against your own data — do not test
against anyone else's `cr` instance.

## Scope

In scope:

- Forging, reordering, truncating, or replaying entries in the audit chain, or
  any way to change a record without producing a correct audit entry.
- Escaping the database root — path traversal, symlink escapes, or any read or
  write outside the configured directory.
- Authentication or authorisation bypass in the REST API or the server-rendered
  views, including bypassing the API token.
- Injection in the rendered HTML, or in query, filter, and search handling.
- Corruption or lock bypass in concurrent access and in `cr sync`.
- Memory unsafety, and denial of service reachable from untrusted input.

Out of scope:

- Anything that requires an attacker who can already write to the database
  directory or run as the serving user. `cr` deliberately treats direct file
  edits as legitimate input, reviewed through `cr status` and `cr save`; the
  audit chain records them rather than preventing them.
- Serving a database over an untrusted network without a TLS-terminating proxy.
  `cr serve` speaks plain HTTP by design.
- Findings against a dependency that already has a published advisory. The
  `cargo audit` workflow covers those; open a normal issue instead.
- The known, already-tracked hardening gaps listed as **P0** and **P1** in
  [`TODO.md`](TODO.md) — for example internal error detail in HTTP 500 bodies
  and incomplete symlink hardening. A report that adds a working exploit or a
  materially worse impact than what is recorded there is still welcome.

## Supported versions

`cr` is pre-1.0 and has not had a tagged release. Only the current `main` branch
receives fixes; there are no backports. Please confirm an issue reproduces on
`main` before reporting.
