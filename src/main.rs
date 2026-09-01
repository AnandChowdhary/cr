use std::{net::SocketAddr, path::PathBuf, process::ExitCode};

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use cr::{
    AgentEvidence, Assignment, AttributionOverrides, AuditFilter, Database, FilterExpression,
    Record, SearchQuery, SearchTarget, SortDirection, SyncAttribution, ViewLayout,
    sort_records_by_field,
};
use serde::Serialize;
use yaml_serde::Mapping;

#[derive(Debug, Serialize)]
struct ListedRecord {
    path: PathBuf,
    front_matter: Mapping,
}

impl From<Record> for ListedRecord {
    fn from(record: Record) -> Self {
        Self {
            path: record.path,
            front_matter: record.attributes,
        }
    }
}

/// Attribution recorded beside `--actor` when software acts for a human.
///
/// `--actor` stays the responsible human. These options say which software
/// carried the change out, how much of a human decision stood behind it, and
/// what was asked. Every value is a claim the calling process makes about
/// itself: `cr` records it, never verifies it, and never lets it affect what an
/// operation is allowed to do. `CR_AGENT`, `CR_AUTHORIZATION`, and `CR_INTENT`
/// supply the same three values to every command, and `CR_AGENT=none` declares
/// that no agent was involved.
#[derive(Clone, Debug, Default, Args)]
struct AttributionArgs {
    /// Software acting for the actor: 'none', an identifier such as claude-code, or a JSON object.
    #[arg(long, value_name = "AGENT")]
    agent: Option<String>,

    /// Release of the acting software.
    #[arg(long, value_name = "VERSION")]
    agent_version: Option<String>,

    /// Model that did the reasoning. Never detected from the environment, only declared.
    #[arg(long, value_name = "MODEL")]
    agent_model: Option<String>,

    /// Agent conversation identifier.
    #[arg(long, value_name = "SESSION")]
    agent_session: Option<String>,

    /// Agent turn or prompt identifier inside the session.
    #[arg(long, value_name = "TURN")]
    agent_turn: Option<String>,

    /// Approval mode: direct, interactive, delegated, autonomous, or unknown. Also accepts a JSON object.
    #[arg(long, value_name = "MODE")]
    authorization: Option<String>,

    /// Raw vendor grant string, recorded verbatim beside the approval mode.
    #[arg(long, value_name = "GRANT")]
    grant: Option<String>,

    /// Who approved the change, when that is known separately from the actor.
    #[arg(long, value_name = "IDENTITY")]
    approved_by: Option<String>,

    /// When the change was approved, as an RFC 3339 timestamp.
    #[arg(long, value_name = "TIMESTAMP")]
    approved_at: Option<String>,

    /// Digest printed by --preview. The mutation is refused unless its change set matches.
    #[arg(long, value_name = "SHA256")]
    approved_changes: Option<String>,

    /// JSON intent object carrying a request, a rationale, or both.
    #[arg(long, value_name = "JSON")]
    intent: Option<String>,

    /// What the human asked for, attributed to the human.
    #[arg(long, value_name = "TEXT")]
    intent_request: Option<String>,

    /// What the agent believed this write was doing, attributed to the agent.
    #[arg(long, value_name = "TEXT")]
    intent_rationale: Option<String>,
}

impl AttributionArgs {
    fn overrides(&self) -> AttributionOverrides<'_> {
        AttributionOverrides {
            agent: self.agent.as_deref(),
            agent_version: self.agent_version.as_deref(),
            agent_model: self.agent_model.as_deref(),
            agent_session: self.agent_session.as_deref(),
            agent_turn: self.agent_turn.as_deref(),
            authorization: self.authorization.as_deref(),
            grant: self.grant.as_deref(),
            approved_by: self.approved_by.as_deref(),
            approved_at: self.approved_at.as_deref(),
            approved_changes: self.approved_changes.as_deref(),
            intent: self.intent.as_deref(),
            intent_request: self.intent_request.as_deref(),
            intent_rationale: self.intent_rationale.as_deref(),
        }
    }

    /// Apply these declarations on top of whatever the environment detected.
    fn apply(&self, database: Database) -> Result<Database> {
        let mut attribution = database.attribution().clone();
        attribution.apply(&self.overrides(), AgentEvidence::Flag)?;
        Ok(database.with_attribution(attribution))
    }
}

/// Apply attribution and an optional audit message to one command's database.
fn attributed(
    database: Database,
    attribution: &AttributionArgs,
    message: Option<&str>,
) -> Result<Database> {
    let database = attribution.apply(database)?;
    match message {
        Some(message) => database.with_audit_message(message),
        None => Ok(database),
    }
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "A file-based database built on Markdown and YAML front matter",
    arg_required_else_help = true
)]
struct Cli {
    /// Database root. By default, search this directory and its parents.
    #[arg(long, global = true, value_name = "PATH")]
    database: Option<PathBuf>,

    /// Identity recorded in audit events. Overrides CR/Git identity discovery.
    #[arg(long, global = true, value_name = "IDENTITY")]
    actor: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a database.
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Create a record.
    Create {
        collection: String,
        id: String,

        /// Set a front matter field using KEY=YAML. Dotted keys create nested fields.
        #[arg(short = 's', long = "set", value_name = "KEY=YAML")]
        assignments: Vec<Assignment>,

        /// Set the Markdown body.
        #[arg(long, default_value = "")]
        body: String,

        /// Explain why this record is being created.
        #[arg(short = 'm', long, value_name = "MESSAGE")]
        message: Option<String>,

        /// Compute the change set without writing, and print the digest that approves it.
        #[arg(long, conflicts_with = "approved_changes")]
        preview: bool,

        /// Print the preview as JSON.
        #[arg(long, requires = "preview")]
        json: bool,

        #[command(flatten)]
        attribution: AttributionArgs,
    },

    /// Fetch a record.
    Get {
        collection: String,
        id: String,

        /// Return a JSON envelope containing identity, attributes, and body.
        #[arg(long, conflicts_with = "field")]
        json: bool,

        /// Return one front matter field. Dotted paths select nested fields.
        #[arg(long, value_name = "KEY", conflicts_with = "json")]
        field: Option<String>,
    },

    /// List and filter records in a collection.
    List {
        collection: String,

        /// Match a field using KEY=YAML. Multiple filters are combined with AND.
        #[arg(short = 'w', long = "where", value_name = "KEY=YAML")]
        filters: Vec<Assignment>,

        /// Match a typed expression such as value>=10000, name contains Acme, or owner is-empty.
        #[arg(long = "where-expr", value_name = "EXPRESSION")]
        expressions: Vec<FilterExpression>,

        /// Sort by a dotted field, $id, $collection, or $path. Missing fields stay last.
        #[arg(long, value_name = "FIELD")]
        sort: Option<String>,

        /// Sort descending. Record ID remains the ascending deterministic tie-breaker.
        #[arg(long, requires = "sort")]
        desc: bool,

        /// Return each file path and front matter as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Search record paths, front matter, and Markdown bodies.
    Search {
        /// Literal text to find, or a regular expression with --regex.
        pattern: String,

        /// Search only this collection. By default, search every collection.
        #[arg(short, long, value_name = "COLLECTION")]
        collection: Option<String>,

        /// First match a field using KEY=YAML. Multiple filters use AND.
        #[arg(short = 'w', long = "where", value_name = "KEY=YAML")]
        filters: Vec<Assignment>,

        /// First match a typed expression such as value>=10000. Multiple expressions use AND.
        #[arg(long = "where-expr", value_name = "EXPRESSION")]
        expressions: Vec<FilterExpression>,

        /// Sort by a dotted field, $id, $collection, or $path. Missing fields stay last.
        #[arg(long, value_name = "FIELD")]
        sort: Option<String>,

        /// Sort descending. Record ID remains the ascending deterministic tie-breaker.
        #[arg(long, requires = "sort")]
        desc: bool,

        /// Search only parsed front matter.
        #[arg(long, conflicts_with_all = ["field", "body", "path"])]
        front_matter: bool,

        /// Search only one front matter field. Dotted paths select nested fields.
        #[arg(long, value_name = "KEY", conflicts_with_all = ["front_matter", "body", "path"])]
        field: Option<String>,

        /// Search only the Markdown body.
        #[arg(long, conflicts_with_all = ["front_matter", "field", "path"])]
        body: bool,

        /// Search only database-relative Markdown paths.
        #[arg(long, conflicts_with_all = ["front_matter", "field", "body"])]
        path: bool,

        /// Match without regard to letter case.
        #[arg(short = 'i', long)]
        ignore_case: bool,

        /// Interpret PATTERN as a Rust regular expression instead of literal text.
        #[arg(long)]
        regex: bool,

        /// Return each matching file path and front matter as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Serve the database through a web UI and REST API.
    Serve {
        /// TCP address to listen on. Defaults to local access only.
        #[arg(long, default_value = "127.0.0.1:3000")]
        bind: SocketAddr,

        /// Largest accepted page size for list, search, status, and audit endpoints.
        #[arg(long, default_value_t = 200)]
        max_page_size: usize,

        /// Largest accepted JSON request body in bytes.
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        max_body_bytes: usize,
    },

    /// Create and inspect saved web views.
    View {
        #[command(subcommand)]
        command: ViewCommand,
    },

    /// Create, inspect, and run external data syncs.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },

    /// Update a record's front matter and optionally its Markdown body.
    Update {
        collection: String,
        id: String,

        /// Set a front matter field using KEY=YAML. Dotted keys create nested fields.
        #[arg(short = 's', long = "set", value_name = "KEY=YAML")]
        assignments: Vec<Assignment>,

        /// Replace the Markdown body. If omitted, the existing body is preserved.
        #[arg(long)]
        body: Option<String>,

        /// Explain why this record is being updated.
        #[arg(short = 'm', long, value_name = "MESSAGE")]
        message: Option<String>,

        /// Compute the change set without writing, and print the digest that approves it.
        #[arg(long, conflicts_with = "approved_changes")]
        preview: bool,

        /// Print the preview as JSON.
        #[arg(long, requires = "preview")]
        json: bool,

        #[command(flatten)]
        attribution: AttributionArgs,
    },

    /// Add a named relation from one record to another.
    Link {
        collection: String,
        id: String,
        relation: String,
        target_collection: String,
        target_id: String,

        /// Explain why this relation is being added.
        #[arg(short = 'm', long, value_name = "MESSAGE")]
        message: Option<String>,

        /// Compute the change set without writing, and print the digest that approves it.
        #[arg(long, conflicts_with = "approved_changes")]
        preview: bool,

        /// Print the preview as JSON.
        #[arg(long, requires = "preview")]
        json: bool,

        #[command(flatten)]
        attribution: AttributionArgs,
    },

    /// Show direct Markdown changes not yet recorded in the audit journal.
    Status {
        /// Return changes as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Record selected direct Markdown changes in the audit journal.
    Save {
        /// Records to accept, written as COLLECTION/ID.
        #[arg(value_name = "COLLECTION/ID")]
        records: Vec<String>,

        /// Accept every change shown by `cr status`.
        #[arg(short = 'a', long, conflicts_with = "records")]
        all: bool,

        /// Explain why the direct changes are being accepted.
        #[arg(short = 'm', long, value_name = "MESSAGE")]
        message: Option<String>,

        /// Return the committed audit events as JSON.
        #[arg(long)]
        json: bool,

        /// Compute each change set without recording it, and print its digest.
        #[arg(long, conflicts_with = "approved_changes")]
        preview: bool,

        #[command(flatten)]
        attribution: AttributionArgs,
    },

    /// Print the attribution that will be recorded in audit events.
    Identity {
        #[arg(long)]
        json: bool,

        #[command(flatten)]
        attribution: AttributionArgs,
    },

    /// Delete a record while retaining its previous state in the audit log.
    Delete {
        collection: String,
        id: String,

        /// Confirm the destructive operation. Not needed with --preview, which deletes nothing.
        #[arg(long)]
        yes: bool,

        /// Explain why this record is being deleted.
        #[arg(short = 'm', long, value_name = "MESSAGE")]
        message: Option<String>,

        /// Compute the change set without writing, and print the digest that approves it.
        #[arg(long, conflicts_with = "approved_changes")]
        preview: bool,

        /// Print the preview as JSON.
        #[arg(long, requires = "preview")]
        json: bool,

        #[command(flatten)]
        attribution: AttributionArgs,
    },

    /// Inspect and verify the tamper-evident audit journal.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ViewCommand {
    /// Create a saved view definition in .cr/views.
    Create {
        name: String,

        /// Collection queried by the view.
        #[arg(long)]
        collection: String,

        /// Human-readable page title. Defaults to the view name.
        #[arg(long)]
        title: Option<String>,

        /// Match a field using KEY=YAML. Multiple filters are combined with AND.
        #[arg(short = 'w', long = "where", value_name = "KEY=YAML")]
        filters: Vec<String>,

        /// Match a typed expression such as value>=10000. Multiple expressions use AND.
        #[arg(long = "where-expr", value_name = "EXPRESSION")]
        expressions: Vec<String>,

        /// Show this dotted front matter field as a table column or Kanban card detail.
        #[arg(short, long = "column", value_name = "FIELD")]
        columns: Vec<String>,

        /// Render records as a table or Kanban board.
        #[arg(long, value_enum, default_value_t = ViewLayoutArgument::Table)]
        layout: ViewLayoutArgument,

        /// Group Kanban lanes by this dotted front matter field.
        #[arg(long, value_name = "FIELD")]
        group_by: Option<String>,

        /// Default ordering field. Accepts dotted front matter, $id, $collection, or $path.
        #[arg(long, value_name = "FIELD")]
        sort_by: Option<String>,

        /// Default ordering direction for --sort-by.
        #[arg(long, value_enum, requires = "sort_by")]
        sort_direction: Option<ViewSortDirectionArgument>,

        /// Default records per page.
        #[arg(long, default_value_t = 50)]
        page_size: usize,
    },

    /// List automatic collection pages and saved views.
    List {
        #[arg(long)]
        json: bool,
    },

    /// Show a saved or automatic view definition.
    Show {
        name: String,

        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ViewLayoutArgument {
    Table,
    Kanban,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ViewSortDirectionArgument {
    Asc,
    Desc,
}

impl From<ViewSortDirectionArgument> for SortDirection {
    fn from(value: ViewSortDirectionArgument) -> Self {
        match value {
            ViewSortDirectionArgument::Asc => Self::Asc,
            ViewSortDirectionArgument::Desc => Self::Desc,
        }
    }
}

impl From<ViewLayoutArgument> for ViewLayout {
    fn from(value: ViewLayoutArgument) -> Self {
        match value {
            ViewLayoutArgument::Table => Self::Table,
            ViewLayoutArgument::Kanban => Self::Kanban,
        }
    }
}

#[derive(Debug, Subcommand)]
enum SyncCommand {
    /// Create a versioned sync definition in .cr/syncs.
    Create {
        name: String,

        /// Stop the command after this many seconds.
        #[arg(long, default_value_t = 300)]
        timeout_seconds: u64,

        /// Reject stdout larger than this many bytes.
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        max_output_bytes: u64,

        /// Reject more than this many JSONL protocol messages.
        #[arg(long, default_value_t = 10_000)]
        max_operations: usize,

        /// Identity recorded for this sync's audit events.
        #[arg(long)]
        actor: Option<String>,

        /// Software recorded as acting for that identity: an identifier or a JSON agent object.
        #[arg(long, value_name = "AGENT")]
        agent: Option<String>,

        /// Program and arguments. Use -- before the program.
        #[arg(
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },

    /// List configured syncs.
    List {
        #[arg(long)]
        json: bool,
    },

    /// Show one sync definition.
    Show {
        name: String,

        #[arg(long)]
        json: bool,
    },

    /// Run one sync and apply its operations with audit provenance.
    Run {
        name: String,

        #[arg(long)]
        json: bool,
    },

    /// Complete a run that stopped after applying some of its records.
    Recover {
        name: String,

        /// Report an interrupted run without applying anything.
        #[arg(long)]
        check: bool,

        #[arg(long)]
        json: bool,
    },

    /// Print the last committed checkpoint state as JSON.
    State { name: String },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Establish audit history for records that predate the audit journal.
    Baseline,

    /// Show the newest audit events first.
    Log {
        collection: Option<String>,
        id: Option<String>,

        /// Only events whose acting agent, or any delegate behind it, carries this identifier.
        #[arg(long, value_name = "AGENT")]
        agent: Option<String>,

        /// Only events whose acting agent, or any delegate behind it, carries this session.
        #[arg(long, value_name = "SESSION")]
        session: Option<String>,

        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,

        #[arg(long)]
        json: bool,
    },

    /// Verify the hash chain and reconcile it with current records.
    Verify {
        /// Require the chain to end at an externally saved head hash.
        #[arg(long, value_name = "SHA256")]
        expected_head: Option<String>,
    },

    /// Print the current sequence and head hash for external anchoring.
    Head {
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    if let Command::Init { path } = cli.command {
        let path = cli.database.unwrap_or(path);
        let database = Database::init(path)?;
        println!("Initialized database at {}", database.root().display());
        return Ok(());
    }

    let database = Database::discover(cli.database.as_deref())?;
    let database = match cli.actor {
        Some(actor) => database.with_actor(actor)?,
        None => database,
    };

    match cli.command {
        Command::Init { .. } => unreachable!(),
        Command::Create {
            collection,
            id,
            assignments,
            body,
            message,
            preview,
            json,
            attribution,
        } => {
            let database = attributed(database, &attribution, message.as_deref())?;
            if preview {
                let preview = database.preview_create(&collection, &id, &assignments, &body)?;
                print_preview(&preview, json)?;
            } else {
                let record = database.create(&collection, &id, &assignments, &body)?;
                println!("{}", record.reference());
            }
        }
        Command::Get {
            collection,
            id,
            json,
            field,
        } => {
            let record = database.get(&collection, &id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&record)?);
            } else if let Some(path) = field {
                let value = record
                    .field(&path)?
                    .ok_or_else(|| anyhow::anyhow!("field '{path}' does not exist"))?;
                print!("{}", yaml_serde::to_string(value)?);
            } else {
                print!("{}", database.read_raw(&collection, &id)?);
            }
        }
        Command::List {
            collection,
            filters,
            expressions,
            sort,
            desc,
            json,
        } => {
            let mut records = database.list(&collection, &filters)?;
            records.retain(|record| {
                expressions
                    .iter()
                    .all(|expression| expression.matches(&record.attributes))
            });
            if let Some(field) = sort {
                sort_records_by_field(
                    &mut records,
                    &field,
                    if desc {
                        SortDirection::Desc
                    } else {
                        SortDirection::Asc
                    },
                )?;
            }
            print_records(records, json)?;
        }
        Command::Search {
            pattern,
            collection,
            filters,
            expressions,
            sort,
            desc,
            front_matter,
            field,
            body,
            path,
            ignore_case,
            regex,
            json,
        } => {
            let target = if front_matter {
                SearchTarget::FrontMatter
            } else if let Some(field) = field {
                SearchTarget::Field(field)
            } else if body {
                SearchTarget::Body
            } else if path {
                SearchTarget::Path
            } else {
                SearchTarget::Document
            };
            let query = SearchQuery::new(&pattern, target, regex, ignore_case)?;
            let mut records = database.search(collection.as_deref(), &filters, &query)?;
            records.retain(|record| {
                expressions
                    .iter()
                    .all(|expression| expression.matches(&record.attributes))
            });
            if let Some(field) = sort {
                sort_records_by_field(
                    &mut records,
                    &field,
                    if desc {
                        SortDirection::Desc
                    } else {
                        SortDirection::Asc
                    },
                )?;
            }
            print_records(records, json)?;
        }
        Command::Serve {
            bind,
            max_page_size,
            max_body_bytes,
        } => {
            let api_token = std::env::var("CR_API_TOKEN")
                .ok()
                .filter(|value| !value.is_empty());
            if !bind.ip().is_loopback() && api_token.is_none() {
                eprintln!(
                    "warning: serving on a non-loopback address without CR_API_TOKEN authentication"
                );
            }
            let config = cr::server::ServerConfig {
                bind,
                max_page_size,
                max_body_bytes,
                api_token,
            };
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(cr::server::serve(database, config))?;
        }
        Command::View { command } => match command {
            ViewCommand::Create {
                name,
                collection,
                title,
                filters,
                expressions,
                columns,
                layout,
                group_by,
                sort_by,
                sort_direction,
                page_size,
            } => {
                let view = database.create_view_with_options(
                    &name,
                    title.as_deref(),
                    &collection,
                    filters,
                    expressions,
                    Vec::new(),
                    columns,
                    page_size,
                    layout.into(),
                    group_by,
                    sort_by,
                    sort_direction
                        .map(SortDirection::from)
                        .unwrap_or(SortDirection::Asc),
                )?;
                println!("/{}", view.name);
            }
            ViewCommand::List { json } => {
                let views = database.views()?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&views)?);
                } else {
                    for view in views {
                        let kind = if view.saved { "saved" } else { "automatic" };
                        println!(
                            "{}\t{}\t{}\t{}",
                            view.name, view.collection, kind, view.title
                        );
                    }
                }
            }
            ViewCommand::Show { name, json } => {
                let view = database.view(&name)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&view)?);
                } else {
                    print!("{}", yaml_serde::to_string(&view)?);
                }
            }
        },
        Command::Sync { command } => match command {
            SyncCommand::Create {
                name,
                timeout_seconds,
                max_output_bytes,
                max_operations,
                actor,
                agent,
                command,
            } => {
                let sync = database.create_sync(
                    &name,
                    command,
                    timeout_seconds,
                    max_output_bytes,
                    max_operations,
                    SyncAttribution { actor, agent },
                )?;
                println!("{}", sync.name);
            }
            SyncCommand::List { json } => {
                let syncs = database.syncs()?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&syncs)?);
                } else {
                    for sync in syncs {
                        println!("{}\t{}", sync.name, sync.command.join(" "));
                    }
                }
            }
            SyncCommand::Show { name, json } => {
                let sync = database.sync(&name)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&sync)?);
                } else {
                    print!("{}", yaml_serde::to_string(&sync)?);
                }
            }
            SyncCommand::Run { name, json } => {
                report_sync_run(&database.run_sync(&name)?, json)?;
            }
            SyncCommand::Recover { name, check, json } => {
                if check {
                    let pending = database.pending_sync_run(&name)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&pending)?);
                    } else {
                        match pending {
                            Some(ledger) => println!(
                                "Sync {} run {} was interrupted at {}: {} operations recorded, {} audit events committed, checkpoint {}{}",
                                ledger.name,
                                ledger.run_id,
                                ledger.started,
                                ledger.operations,
                                ledger.events_committed,
                                if ledger.checkpoint_pending {
                                    "pending"
                                } else {
                                    "committed"
                                },
                                if ledger.foreign_events {
                                    "; unrelated events were committed after it stopped"
                                } else {
                                    ""
                                }
                            ),
                            None => println!("Sync {name} has no interrupted run"),
                        }
                    }
                } else {
                    match database.recover_sync(&name)? {
                        Some(summary) => report_sync_run(&summary, json)?,
                        None if json => println!("null"),
                        None => println!("Sync {name} has no interrupted run"),
                    }
                }
            }
            SyncCommand::State { name } => {
                database.sync(&name)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &database
                            .sync_state(&name)?
                            .unwrap_or(serde_json::Value::Null)
                    )?
                );
            }
        },
        Command::Update {
            collection,
            id,
            assignments,
            body,
            message,
            preview,
            json,
            attribution,
        } => {
            if assignments.is_empty() && body.is_none() {
                bail!("provide at least one --set or --body value");
            }
            let database = attributed(database, &attribution, message.as_deref())?;
            if preview {
                let preview =
                    database.preview_update(&collection, &id, &assignments, body.as_deref())?;
                print_preview(&preview, json)?;
            } else {
                let record = database.update(&collection, &id, &assignments, body.as_deref())?;
                println!("{}", record.reference());
            }
        }
        Command::Link {
            collection,
            id,
            relation,
            target_collection,
            target_id,
            message,
            preview,
            json,
            attribution,
        } => {
            let database = attributed(database, &attribution, message.as_deref())?;
            if preview {
                let preview = database.preview_link(
                    &collection,
                    &id,
                    &relation,
                    &target_collection,
                    &target_id,
                )?;
                print_preview(&preview, json)?;
            } else {
                let record =
                    database.link(&collection, &id, &relation, &target_collection, &target_id)?;
                println!("{}", record.reference());
            }
        }
        Command::Status { json } => {
            let changes = database.status()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&changes)?);
            } else if changes.is_empty() {
                println!("Clean");
            } else {
                for change in changes {
                    println!("{} {}", change.status.short_code(), change.reference());
                }
            }
        }
        Command::Save {
            records,
            all,
            message,
            json,
            preview,
            attribution,
        } => {
            let database = attribution.apply(database)?;
            if preview {
                let previews = database.preview_save(&records, all, message.as_deref())?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&previews)?);
                } else if previews.is_empty() {
                    println!("No changes to save");
                } else {
                    for preview in &previews {
                        print_preview(preview, false)?;
                    }
                }
                return Ok(());
            }
            let entries = database.save(&records, all, message.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("No changes to save");
            } else {
                for entry in entries {
                    println!(
                        "Saved {} {} as audit event {}",
                        entry.payload.action,
                        entry.payload.record.reference(),
                        entry.payload.sequence
                    );
                }
            }
        }
        Command::Identity {
            json,
            attribution: declared,
        } => {
            let database = declared.apply(database)?;
            let attribution = database.attribution();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "actor": database.actor(),
                        "agent": attribution.agent,
                        "authorization": attribution.authorization,
                        "intent": attribution.intent,
                    }))?
                );
            } else {
                println!("{}", database.actor());
                print_attribution(attribution);
            }
        }
        Command::Delete {
            collection,
            id,
            yes,
            message,
            preview,
            json,
            attribution,
        } => {
            let database = attributed(database, &attribution, message.as_deref())?;
            if preview {
                let preview = database.preview_delete(&collection, &id)?;
                print_preview(&preview, json)?;
            } else {
                if !yes {
                    bail!("deleting a record requires --yes to confirm the destructive operation");
                }
                let record = database.delete(&collection, &id)?;
                println!("{}", record.reference());
            }
        }
        Command::Audit { command } => match command {
            AuditCommand::Baseline => {
                let added = database.audit_baseline()?;
                println!("Added {added} baseline audit events");
            }
            AuditCommand::Log {
                collection,
                id,
                agent,
                session,
                limit,
                json,
            } => {
                if limit == 0 {
                    bail!("audit log limit must be greater than zero");
                }
                let entries = database.audit_recent(
                    limit,
                    AuditFilter {
                        collection: collection.as_deref(),
                        id: id.as_deref(),
                        agent: agent.as_deref(),
                        session: session.as_deref(),
                    },
                )?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&entries)?);
                } else {
                    for entry in entries {
                        let agent = entry
                            .payload
                            .agent
                            .as_ref()
                            .map(|agent| format!(" agent={}", agent.id))
                            .unwrap_or_default();
                        println!(
                            "{} {} {} {} {}{}",
                            entry.payload.sequence,
                            entry.payload.timestamp,
                            entry.payload.action,
                            entry.payload.record.reference(),
                            entry.hash,
                            agent
                        );
                    }
                }
            }
            AuditCommand::Verify { expected_head } => {
                let verification = database.audit_verify(expected_head.as_deref())?;
                println!(
                    "Verified {} audit events and {} records; head {}",
                    verification.entries,
                    verification.records_checked,
                    verification.head.hash.as_deref().unwrap_or("none")
                );
            }
            AuditCommand::Head { json } => {
                let head = database.audit_head()?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&head)?);
                } else {
                    println!(
                        "{} {}",
                        head.sequence,
                        head.hash.as_deref().unwrap_or("none")
                    );
                }
            }
        },
    }

    Ok(())
}

/// Print what a sync run applied.
///
/// A resumed run reports the interrupted run's own identifier, because the
/// audit events it just committed carry that identifier too.
fn report_sync_run(summary: &cr::SyncRunSummary, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(summary)?);
        return Ok(());
    }
    println!(
        "Sync {} {}{}: {} created, {} updated, {} deleted, {} unchanged; checkpoint {}",
        summary.name,
        summary.run_id,
        if summary.resumed { " (resumed)" } else { "" },
        summary.created,
        summary.updated,
        summary.deleted,
        summary.unchanged,
        if summary.checkpoint_updated {
            "updated"
        } else {
            "unchanged"
        }
    );
    Ok(())
}

/// Print a change set that was computed but not written.
///
/// The last line is always `digest sha256:…`, so a caller can lift the value to
/// pass back as `--approved-changes` without parsing the rest.
fn print_preview(preview: &cr::ChangePreview, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(preview)?);
        return Ok(());
    }
    println!("{} {}", preview.action, preview.record.reference());
    for change in &preview.changes {
        match change {
            cr::AuditChange::Add { path, after } => {
                println!("add {} {}", change_path(path), compact(after)?);
            }
            cr::AuditChange::Remove { path, before } => {
                println!("remove {} {}", change_path(path), compact(before)?);
            }
            cr::AuditChange::Replace {
                path,
                before,
                after,
            } => {
                println!(
                    "replace {} {} -> {}",
                    change_path(path),
                    compact(before)?,
                    compact(after)?
                );
            }
        }
    }
    println!("digest {}", preview.digest);
    Ok(())
}

/// Name the whole document rather than printing an empty JSON Pointer.
fn change_path(path: &str) -> &str {
    if path.is_empty() { "(record)" } else { path }
}

fn compact(value: &serde_json::Value) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

/// Print the agent, authorization, and intent an event would carry.
///
/// Prints nothing when there is nothing to say, so a human at the keyboard sees
/// exactly the single identity line `cr identity` has always printed.
fn print_attribution(attribution: &cr::Attribution) {
    if let Some(agent) = &attribution.agent {
        let mut line = format!("agent: {}", agent.id);
        if let Some(version) = &agent.version {
            line.push_str(&format!(" {version}"));
        }
        if let Some(model) = &agent.model {
            line.push_str(&format!(" model={model}"));
        }
        if let Some(session) = &agent.session {
            line.push_str(&format!(" session={session}"));
        }
        if let Some(turn) = &agent.turn {
            line.push_str(&format!(" turn={turn}"));
        }
        for delegate in agent.via.iter().flatten() {
            line.push_str(&format!(" via={}", delegate.id));
        }
        line.push_str(&format!(
            " (asserted, detected from {})",
            agent.detected_from.label()
        ));
        println!("{line}");
    }
    if let Some(authorization) = &attribution.authorization {
        let mut line = format!("authorization: {}", authorization.mode.label());
        if let Some(grant) = &authorization.grant {
            line.push_str(&format!(" grant={grant}"));
        }
        if let Some(approved_by) = &authorization.approved_by {
            line.push_str(&format!(" approved_by={approved_by}"));
        }
        if let Some(at) = &authorization.at {
            line.push_str(&format!(" at={at}"));
        }
        if let Some(approved) = &authorization.approved_changes {
            line.push_str(&format!(" approved_changes={approved}"));
        }
        println!("{line}");
    }
    if let Some(intent) = &attribution.intent {
        for (label, part) in [
            ("request", intent.request.as_ref()),
            ("rationale", intent.rationale.as_ref()),
        ] {
            let Some(part) = part else { continue };
            let body = match (&part.text, &part.digest) {
                (Some(text), _) => text.replace('\n', " "),
                (None, Some(digest)) => format!("not retained; digest {digest}"),
                (None, None) => String::new(),
            };
            println!("intent {label} ({}): {body}", part.author.label());
        }
    }
}

fn print_records(records: Vec<Record>, json: bool) -> Result<()> {
    if json {
        let records: Vec<ListedRecord> = records.into_iter().map(Into::into).collect();
        println!("{}", serde_json::to_string_pretty(&records)?);
    } else {
        for record in records {
            println!("{}", record.path.display());
        }
    }
    Ok(())
}
