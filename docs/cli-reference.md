# Command reference

Global `--as PRINCIPAL` delegates one command from an audited database owner.
Global `--json-errors` writes failures to stderr as
`{"error":{"code":"...","message":"..."}}`; command-line syntax failures use
`usage_error`, classified domain failures retain their stable code, and an
unclassified failure uses `internal_error`.

```text
cr [--database PATH] [--actor IDENTITY] [--as PRINCIPAL] [--json-errors] COMMAND

cr init PATH
cr identity [--json] [ATTRIBUTION]

cr create COLLECTION ID [--set KEY=YAML]... [--set-env KEY=ENV]...
                        [--body TEXT] [-m MESSAGE] [ATTRIBUTION]
                        [--preview [--json]]
cr get COLLECTION ID [--json | --field KEY [--raw]]
cr list COLLECTION [--where KEY=YAML]... [--where-expr EXPRESSION]...
                   [--sort FIELD [--desc]] [--json]
cr search PATTERN [--collection COLLECTION] [--where KEY=YAML]...
                  [--where-expr EXPRESSION]... [--sort FIELD [--desc]] [--json]
                  [--front-matter | --field KEY | --body | --path]
                  [--ignore-case] [--regex]
cr update COLLECTION ID [--set KEY=YAML]... [--set-env KEY=ENV]...
                        [--unset KEY]... [--body TEXT] [-m MESSAGE] [ATTRIBUTION]
                        [--preview [--json]]
cr link SOURCE_COLLECTION SOURCE_ID RELATION TARGET_COLLECTION TARGET_ID
              [-m MESSAGE] [ATTRIBUTION] [--preview [--json]]
cr unlink SOURCE_COLLECTION SOURCE_ID RELATION TARGET_COLLECTION TARGET_ID
              [-m MESSAGE] [ATTRIBUTION] [--preview [--json]]
cr delete COLLECTION ID --yes [-m MESSAGE] [ATTRIBUTION]
cr delete COLLECTION ID --preview [--json]
cr serve [--bind ADDRESS] [--max-page-size N] [--max-body-bytes N]

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
                    [--sort-by FIELD] [--sort-direction asc|desc] [--page-size N]
cr view list [--json]
cr view show NAME [--json]

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
cr save COLLECTION/ID... [--message TEXT] [--json] [--preview] [ATTRIBUTION]
cr save --all [--message TEXT] [--json] [--preview] [ATTRIBUTION]

cr audit log [COLLECTION] [ID] [--by-agent AGENT] [--by-session SESSION] [--limit N] [--json]
cr audit verify [--expected-head HASH]
cr audit head [--json]
cr audit anchor [--write] [--json]
cr audit baseline

ATTRIBUTION = [--agent AGENT] [--agent-version V] [--agent-model MODEL]
              [--agent-session SESSION] [--agent-turn TURN]
              [--authorization MODE] [--grant GRANT]
              [--approved-by IDENTITY] [--approved-at TIMESTAMP]
              [--approved-changes SHA256]
              [--intent JSON] [--intent-request TEXT] [--intent-rationale TEXT]
```

Run `cr COMMAND --help` for complete command-specific help.
