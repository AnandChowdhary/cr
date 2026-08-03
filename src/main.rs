use std::{path::PathBuf, process::ExitCode};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use cr::{Assignment, Database};

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

    /// Actor recorded in audit events. Defaults to CR_ACTOR or the OS user.
    #[arg(long, global = true, value_name = "NAME")]
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

        /// Return complete records as JSON.
        #[arg(long)]
        json: bool,
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
    },

    /// Add a named relation from one record to another.
    Link {
        collection: String,
        id: String,
        relation: String,
        target_collection: String,
        target_id: String,
    },

    /// Delete a record while retaining its previous state in the audit log.
    Delete {
        collection: String,
        id: String,

        /// Confirm the destructive operation.
        #[arg(long, required = true)]
        yes: bool,
    },

    /// Inspect and verify the tamper-evident audit journal.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Establish audit history for records that predate the audit journal.
    Baseline,

    /// Show the newest audit events first.
    Log {
        collection: Option<String>,
        id: Option<String>,

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
        Some(actor) => database.with_actor(actor),
        None => database,
    };

    match cli.command {
        Command::Init { .. } => unreachable!(),
        Command::Create {
            collection,
            id,
            assignments,
            body,
        } => {
            let record = database.create(&collection, &id, &assignments, &body)?;
            println!("{}", record.reference());
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
            json,
        } => {
            let records = database.list(&collection, &filters)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&records)?);
            } else {
                for record in records {
                    println!("{}", record.reference());
                }
            }
        }
        Command::Update {
            collection,
            id,
            assignments,
            body,
        } => {
            if assignments.is_empty() && body.is_none() {
                bail!("provide at least one --set or --body value");
            }
            let record = database.update(&collection, &id, &assignments, body.as_deref())?;
            println!("{}", record.reference());
        }
        Command::Link {
            collection,
            id,
            relation,
            target_collection,
            target_id,
        } => {
            let record =
                database.link(&collection, &id, &relation, &target_collection, &target_id)?;
            println!("{}", record.reference());
        }
        Command::Delete {
            collection,
            id,
            yes: _,
        } => {
            let record = database.delete(&collection, &id)?;
            println!("{}", record.reference());
        }
        Command::Audit { command } => match command {
            AuditCommand::Baseline => {
                let added = database.audit_baseline()?;
                println!("Added {added} baseline audit events");
            }
            AuditCommand::Log {
                collection,
                id,
                limit,
                json,
            } => {
                if limit == 0 {
                    bail!("audit log limit must be greater than zero");
                }
                let entries = database.audit_recent(limit, collection.as_deref(), id.as_deref())?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&entries)?);
                } else {
                    for entry in entries {
                        println!(
                            "{} {} {} {} {}",
                            entry.payload.sequence,
                            entry.payload.timestamp,
                            entry.payload.action,
                            entry.payload.record.reference(),
                            entry.hash
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
