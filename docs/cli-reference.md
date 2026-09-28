# Command reference

Global `--as PRINCIPAL` delegates one command from an audited database owner.
Global `--verify-audit` makes the command verify the audit journal from its
first event instead of resuming the walk the last write saved under
`.cr/cache/`; see [Reads, writes, and the saved walk](audit.md#reads-writes-and-the-saved-walk).
Global `--json-errors` writes failures to stderr as
`{"error":{"code":"...","message":"..."}}`. A command line `cr` will not run
uses `usage_error`, whether parsing refused it or a check parsing cannot
express did: `--as` with `init` or `serve`, an `update` with nothing to change,
a `delete` or `user delete` without `--yes`, `audit log --limit 0`, a
record-owned `access policy set` on anything but `collection:NAME`, or one
field given to both `--set` and `--set-env`. A value parsing takes as text and
the database then refuses — a field path, a `--select` list, a `--sort` key
and the `--desc` that goes with it, a record hash, a `--fail-on` threshold — is
`validation_failed` instead, as every value the database refuses is.
Classified domain failures retain their stable code, and an unclassified
failure uses `internal_error`. The codes a scheduled sync can fail with are
listed in [Run on a schedule](sync.md#run-on-a-schedule).

A failed command exits 1, except a usage error, which exits 2 with or without
`--json-errors`. `check` and `schema check` also exit 2 when they ran and found
problems; their findings go to stdout, and a usage error only to stderr.

```text
cr [--database PATH] [--actor IDENTITY] [--as PRINCIPAL] [--verify-audit] [--json-errors] COMMAND

cr init PATH
cr identity [--json] [ATTRIBUTION]

cr create COLLECTION ID [--set KEY=YAML]... [--set-env KEY=ENV]...
                        [--body TEXT] [--file PATH=SOURCE]... [-m MESSAGE] [ATTRIBUTION]
                        [--preview [--json]]
cr get COLLECTION ID [--json | --field KEY [--raw] | --select FIELDS [--json] | --file PATH]
cr list COLLECTION [--where KEY=YAML]... [--where-expr EXPRESSION]...
                   [--filter FILTER] [--select FIELDS]... [SORT] [--json]
cr count COLLECTION [--where KEY=YAML]... [--where-expr EXPRESSION]... [--filter FILTER]
                    [--by FIELD] [--sum FIELDS]... [--avg FIELDS]...
                    [--min FIELDS]... [--max FIELDS]... [--json]
cr search PATTERN [--collection COLLECTION] [--where KEY=YAML]...
                  [--where-expr EXPRESSION]... [--filter FILTER] [--select FIELDS]...
                  [SORT] [--json]
                  [--front-matter | --field KEY | --body | --path]
                  [--ignore-case] [--regex]
cr update COLLECTION ID [--set KEY=YAML]... [--set-env KEY=ENV]...
                        [--unset KEY]... [--body TEXT]
                        [--file PATH=SOURCE]... [--remove-file PATH]...
                        [-m MESSAGE] [ATTRIBUTION] [--preview [--json]]
cr link SOURCE_COLLECTION SOURCE_ID RELATION TARGET_COLLECTION TARGET_ID
              [-m MESSAGE] [ATTRIBUTION] [--preview [--json]]
cr unlink SOURCE_COLLECTION SOURCE_ID RELATION TARGET_COLLECTION TARGET_ID
              [-m MESSAGE] [ATTRIBUTION] [--preview [--json]]
cr backlinks COLLECTION ID [--from COLLECTION] [--relation NAME]
                           [--where KEY=YAML]... [--where-expr EXPRESSION]...
                           [--filter FILTER] [--select FIELDS]...
                           [SORT] [--json]
cr traverse COLLECTION ID [--relation NAME]... [--depth N]
                          [--json [--expand] [--select FIELDS]...]
cr delete COLLECTION ID --yes [-m MESSAGE] [ATTRIBUTION]
cr delete COLLECTION ID --preview [--json]
cr serve [--bind ADDRESS] [--max-page-size N] [--max-body-bytes N] [--require-token]
         [--cloudflare-access TEAM_DOMAIN --cloudflare-access-aud TAG]
         [--superadmin USER_ID]...

cr collections [--json]
cr schema show COLLECTION
cr schema check COLLECTION FILE [--json]
cr schema set COLLECTION FILE [--allow-violations] [--json]
cr schema remove COLLECTION
cr schema encrypt COLLECTION FIELD
cr schema encrypt-body COLLECTION
cr schema label COLLECTION (LABEL | --clear)
cr schema icon COLLECTION (EMOJI | --clear)

cr access init [--name NAME] [--email EMAIL] [--kind human|service | --service]
cr access check ACTION RESOURCE [--json]
cr access grant USER ROLE RESOURCE
cr access revoke USER RESOURCE
cr access policy set collection:NAME --mode record-owned [--default-visibility private]
cr access visibility COLLECTION ID private|shared
cr access owner COLLECTION ID PRINCIPAL
cr access token issue USER [--label TEXT] [--expires-in 90d|12h] [--json]
cr access token list [USER] [--json]
cr access token revoke USER ID

cr user add ID --name NAME [--email EMAIL] [--kind human|service | --service]
            [--set KEY=YAML]... [--reuse-deleted-id] [--json]
cr user ensure ID --name NAME [--email EMAIL] [--kind human|service | --service]
               [--set KEY=YAML]... [--reuse-deleted-id] [--json]
cr user update ID [--name NAME] [--email EMAIL | --clear-email]
               [--kind human|service | --service] [--status active|disabled]
               [--set KEY=YAML]... [--json]
cr user delete ID --yes [--if-unused] [--json]
cr user restore ID [--json]
cr user list [--json]
cr user show [ID] [--json]

cr view create NAME --collection COLLECTION [--where KEY=YAML]... [--column FIELD]...
                    [--layout table|kanban] [--group-by FIELD]
                    [--sort-by KEY]... [--sort-direction asc|desc] [--page-size N]
cr view list [--json]
cr view show NAME [--json]
cr view delete NAME

cr pin add PATH [--label LABEL]
cr pin remove PATH
cr pin list [--json]

cr sync create NAME [--actor IDENTITY] [--agent AGENT] [--timeout-seconds N] -- COMMAND...
cr sync list [--json]
cr sync show NAME [--json]
cr sync run NAME [--json]
cr sync recover NAME [--check] [--json]
cr sync state NAME

cr status [--json]
cr check [--collection COLLECTION] [--json] [--fail-on error|warning|never]
         [--trusted-key KEY|FILE]...
cr save COLLECTION/ID... [--message TEXT] [--json] [--preview] [ATTRIBUTION]
cr save --all [--message TEXT] [--json] [--preview] [ATTRIBUTION]

cr audit log [COLLECTION] [ID] [--by-agent AGENT] [--by-session SESSION] [--limit N] [--json]
cr audit verify [--expected-head HASH] [--trusted-key KEY|FILE]...
cr audit head [--json]
cr audit anchor [--write] [--json]
cr audit key generate PATH [--json]
cr audit key show [PATH] [--json]
cr audit baseline

SORT = --sort KEY [--sort KEY]... | --sort FIELD --desc
KEY  = FIELD | FIELD:asc | FIELD:desc, or several of them separated by commas

ATTRIBUTION = [--agent AGENT] [--agent-version V] [--agent-model MODEL]
              [--agent-session SESSION] [--agent-turn TURN]
              [--authorization MODE] [--grant GRANT]
              [--approved-by IDENTITY] [--approved-at TIMESTAMP]
              [--approved-changes SHA256]
              [--intent JSON] [--intent-request TEXT] [--intent-rationale TEXT]
```

A sort takes at most five keys, most significant first, each field once.
`--desc`, like `--sort-direction` on `cr view create`, gives the direction of
a single key written without one, and is refused with several; see
[Sort results](working-with-records.md#sort-results).

`--file`, `--remove-file`, and `get --file` apply to a collection whose
records are folders of files; see [Bundle records](working-with-records.md#bundle-records).
`--file` reads SOURCE, a local file or `-` for standard input, and stores its
bytes at PATH inside the record's folder.

`CR_AGENT`, `CR_AUTHORIZATION`, and `CR_INTENT` supply ATTRIBUTION to every
command, beneath the flags. `CR_HOOK_AGENT` and `CR_HOOK_AUTHORIZATION` are the
layer a harness hook fills in, beneath those; see
[Let Claude Code fill in the attribution](agents.md#let-claude-code-fill-in-the-attribution).

`CR_AUDIT_SIGNING_KEY` names a private key from `cr audit key generate`; while
it is set, every command that records an audit event also signs the new head
into `.cr-audit-head.sig.json`, and `cr audit anchor --write` signs the current
one. `--trusted-key` takes an `ed25519:` public key or a file of them, one per
line, and may be repeated; without it, `CR_AUDIT_TRUSTED_KEYS` supplies the
same values separated by commas. A failed signature check is
`signature_mismatch`. `audit key` opens no database. See
[Sign checkpoints](audit.md#sign-checkpoints).

Run `cr COMMAND --help` for complete command-specific help.
