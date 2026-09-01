//! Who acted, under what authorization, and why.
//!
//! `actor` stays the responsible human. When software acts on that human's
//! behalf, three optional objects are recorded beside it: [`AuditAgent`] says
//! which software ran the command, [`AuditAuthorization`] says how much of a
//! human decision stood behind it, and [`AuditIntent`] says what was asked and
//! what the agent believed it was doing.
//!
//! Every value here is a claim made by a cooperating local process about
//! itself. `cr` has no attestation authority: it cannot prove that an agent is
//! what it says it is, that the human really asked, or that the recorded
//! reasoning is complete. [`AgentEvidence`] therefore records *how `cr` came to
//! believe* an agent was involved, and none of its values means "verified".
//! Nothing in this module may ever gate an authorization decision.
//!
//! Two rules keep the audit chain compatible while these objects evolve:
//!
//! - **Everything added to the payload is `Option` with `skip_serializing_if`.**
//!   An event with no attribution serializes to exactly the bytes it did before
//!   these fields existed, so old journals keep verifying and no audit version
//!   bump is needed.
//! - **Reading is permissive and writing is strict.** The stored types below
//!   ignore unknown fields, and the three enums below accept a label they do
//!   not know rather than failing, so a journal written by a newer `cr` still
//!   verifies under an older one. The separate `*Spec` input types reject
//!   unknown fields and unknown enum labels, so a caller cannot smuggle in a
//!   value `cr` is supposed to determine — `detected_from` above all — or
//!   record a value this build cannot name.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::error::invalid;

/// Longest accepted attribution identifier, in characters.
const MAX_IDENTIFIER_CHARS: usize = 256;
/// Longest accepted single intent text, in characters.
const MAX_INTENT_TEXT_CHARS: usize = 4096;
/// Longest accepted total intent text for one event, in characters.
const MAX_INTENT_CHARS: usize = 8192;
/// Longest accepted delegation chain, counting the acting agent.
const MAX_DELEGATION_DEPTH: usize = 8;

/// Environment variables a coding agent documents for exactly this purpose,
/// paired with the identifier `cr` records when it observes one.
///
/// Deliberately short. Only these two are documented by their vendors;
/// synthesising an identity from an undocumented variable would put a guess
/// into a permanent record. An unrecognised agent falls back to today's
/// behavior, which records nothing rather than something invented.
const AGENT_PROBES: &[AgentProbe] = &[
    AgentProbe {
        variable: "CLAUDECODE",
        id: "claude-code",
        session_variable: Some("CLAUDE_CODE_SESSION_ID"),
    },
    AgentProbe {
        variable: "CURSOR_AGENT",
        id: "cursor-agent",
        session_variable: None,
    },
];

/// One entry of the environment probe table.
#[derive(Clone, Copy, Debug)]
struct AgentProbe {
    variable: &'static str,
    id: &'static str,
    session_variable: Option<&'static str>,
}

/// Define one of the attribution enums stored inside the hashed audit payload.
///
/// The three enums this generates live inside a payload whose exact stored
/// bytes are the hash input, and whose format version is deliberately not
/// bumped when metadata is added (see `docs/architecture.md`). A closed enum
/// would make adding a value a chain-breaking event: an older `cr` that cannot
/// deserialize the label fails the payload, and a payload that fails to
/// deserialize fails the whole journal — the exact hard failure the
/// no-version-bump decision exists to prevent.
///
/// So the generated type carries an `Other` variant that **preserves the label
/// verbatim**. Reading is permissive: an unknown label parses. Writing is
/// strict: only [`parse_known`](Self::parse_known) turns caller input into a
/// value, and it rejects anything this build cannot name, so `Other` is
/// reachable from stored bytes and from nothing else.
///
/// Serialization writes the preserved label back unchanged, so a payload
/// carrying an unknown value round-trips byte for byte and keeps its hash. A
/// tolerant reader that normalized unknown labels — to a default, or to a
/// marker string — would silently rewrite the bytes and destroy the very
/// property it was added to protect.
macro_rules! stored_label_enum {
    (
        $(#[$enum_meta:meta])*
        $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $label:literal,
            )+
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
            /// A label this build does not know, preserved exactly as stored.
            ///
            /// Produced only by reading a journal written by a newer `cr`.
            /// Rendered verbatim and serialized verbatim, so the event's bytes
            /// and hash survive a read and a rewrite unchanged.
            Other(String),
        }

        impl $name {
            /// The stored label for this value.
            ///
            /// Stable, lowercase, and for `Other` exactly the bytes that were
            /// read. Safe for output and rendering: it is a bounded label from
            /// the journal, not free text.
            pub fn label(&self) -> &str {
                match self {
                    $(Self::$variant => $label,)+
                    Self::Other(label) => label,
                }
            }

            /// True when this build does not know what this value means.
            pub fn is_known(&self) -> bool {
                !matches!(self, Self::Other(_))
            }

            /// Parse a label this build knows, rejecting every other value.
            ///
            /// This is the writing half of the rule. Every caller-supplied
            /// value goes through here, so `cr` never records a label it
            /// cannot name.
            pub fn parse_known(label: &str) -> Option<Self> {
                match label {
                    $($label => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.label())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let label = String::deserialize(deserializer)?;
                Ok(Self::parse_known(&label).unwrap_or(Self::Other(label)))
            }
        }
    };
}

stored_label_enum! {
    /// How `cr` came to believe that an agent was involved.
    ///
    /// None of these values means the claim was verified. They rank the strength
    /// of the assertion only: an explicit declaration outranks a sniffed
    /// environment because somebody chose to make it.
    ///
    /// `cr` determines this itself, so no caller can supply it and the `Other`
    /// variant is reachable only by reading a journal a newer `cr` wrote.
    AgentEvidence {
        /// Observed in the process environment through a documented variable.
        Environment => "environment",
        /// Declared by a command-line flag or a `CR_*` environment variable.
        Flag => "flag",
        /// Declared by an `X-CR-*` request header.
        Header => "header",
        /// Declared by stored configuration, such as a sync definition.
        Config => "config",
    }
}

/// The software that carried out a change on the actor's behalf.
///
/// `via` is the delegation chain behind it, nearest actor first, so a sub-agent
/// does not silently erase the agent that spawned it. Prior actors are
/// informational: they exist to make the record legible, never to grant
/// anything.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditAgent {
    /// Stable identifier for the software, such as `claude-code`.
    pub id: String,
    /// Release of that software, when it was declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The model that did the reasoning. Never sniffed; only ever declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Conversation identifier, a correlation key into a store `cr` does not own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Turn or prompt identifier within that session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn: Option<String>,
    /// How `cr` came to believe this. No value means "verified".
    pub detected_from: AgentEvidence,
    /// Delegation chain behind this agent, nearest actor first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<Vec<AuditAgent>>,
}

impl AuditAgent {
    /// True when this agent or any delegate behind it carries `id`.
    pub fn declares_id(&self, id: &str) -> bool {
        self.id == id
            || self
                .via
                .iter()
                .flatten()
                .any(|delegate| delegate.declares_id(id))
    }

    /// True when this agent or any delegate behind it carries `session`.
    pub fn declares_session(&self, session: &str) -> bool {
        self.session.as_deref() == Some(session)
            || self
                .via
                .iter()
                .flatten()
                .any(|delegate| delegate.declares_session(session))
    }
}

stored_label_enum! {
    /// How much of a human decision stood behind one change.
    ///
    /// Ordered by decreasing human proximity. The question an auditor actually
    /// asks is "did a person see *this* change before it happened", and only
    /// `direct` and `interactive` answer yes.
    ///
    /// Note that `Unknown` and `Other` are different answers. `unknown` is a
    /// value a writer chose: it says the approval path could not be determined.
    /// `Other` says a writer named an approval path this build has never heard
    /// of, and the reader must not guess how much human was behind it.
    AuthorizationMode {
        /// A human ran the command. No agent involved.
        Direct => "direct",
        /// A human was present and approved this specific invocation.
        Interactive => "interactive",
        /// A human instructed the task; this write was covered by a standing grant.
        Delegated => "delegated",
        /// No human in the session: scheduled, headless, or unattended.
        Autonomous => "autonomous",
        /// The approval path could not be determined.
        Unknown => "unknown",
    }
}

/// The approval a change was made under.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditAuthorization {
    /// Normalized approval mode, for querying.
    pub mode: AuthorizationMode,
    /// The raw vendor grant string, verbatim, for fidelity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    /// Who approved, when that is known separately from `actor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    /// When the approval was given, as an RFC 3339 timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    /// Digest of the change set that was previewed and approved.
    ///
    /// The one field in this module that is checked rather than believed. `cr`
    /// refuses to apply a mutation whose change set hashes differently, and
    /// `audit verify` recomputes the digest from the event's stored `changes`.
    ///
    /// It commits to *what* was applied, not to *who saw it*. That a human read
    /// the preview is asserted, exactly like everything else here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_changes: Option<String>,
}

stored_label_enum! {
    /// Who a piece of recorded intent is attributed to.
    IntentAuthor {
        /// Attributed to the responsible human. `cr` did not witness them type it.
        Human => "human",
        /// The agent's own account of itself. Self-serving evidence by construction.
        Agent => "agent",
        /// Generated by tooling rather than by either party.
        System => "system",
    }
}

/// One provenance-tagged piece of intent.
///
/// Carries either the text itself or a digest of text stored elsewhere. Inline
/// text is permanent once written, exactly like every other value in the
/// journal; the digest form exists so a deployment that must be able to delete
/// intent text later can adopt it without a schema change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditIntentPart {
    /// Who this text is attributed to. Never a claim that `cr` observed them.
    pub author: IntentAuthor,
    /// The text itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// A `sha256:` digest of text held outside the payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Where that text is held, when it is held anywhere.
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// When this was said, as an RFC 3339 timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// What was asked, and what the agent thought it was doing.
///
/// Both halves are kept because they answer different questions and neither
/// substitutes for the other. The request is evidence about the human; the
/// rationale is evidence about the agent. The gap between them is where an
/// agent's misreadings become visible, and a single field would hide it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditIntent {
    /// The instruction the change was made under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<AuditIntentPart>,
    /// The agent's account of what this particular write was discharging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<AuditIntentPart>,
}

/// The attribution one `Database` records on every event it appends.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Attribution {
    /// The software that acted, if any.
    pub agent: Option<AuditAgent>,
    /// The approval it acted under, if any was recorded.
    pub authorization: Option<AuditAuthorization>,
    /// What was asked and why, if either was recorded.
    pub intent: Option<AuditIntent>,
}

/// Attribution declared by flags, environment variables, or request headers.
///
/// Each field is a caller-supplied string. `agent`, `authorization`, and
/// `intent` accept a compact form or a JSON object; the rest fill in single
/// fields of whichever object is already in effect.
#[derive(Clone, Copy, Debug, Default)]
pub struct AttributionOverrides<'a> {
    /// `none`, a bare agent identifier, or a JSON agent object.
    pub agent: Option<&'a str>,
    /// Release of the acting software.
    pub agent_version: Option<&'a str>,
    /// The model that did the reasoning.
    pub agent_model: Option<&'a str>,
    /// Conversation identifier.
    pub agent_session: Option<&'a str>,
    /// Turn or prompt identifier.
    pub agent_turn: Option<&'a str>,
    /// A bare authorization mode or a JSON authorization object.
    pub authorization: Option<&'a str>,
    /// The raw vendor grant string.
    pub grant: Option<&'a str>,
    /// Who approved the change.
    pub approved_by: Option<&'a str>,
    /// When the change was approved.
    pub approved_at: Option<&'a str>,
    /// `sha256:` digest of the change set that was previewed and approved.
    pub approved_changes: Option<&'a str>,
    /// A JSON intent object.
    pub intent: Option<&'a str>,
    /// The instruction, attributed to the human.
    pub intent_request: Option<&'a str>,
    /// The agent's account of this write, attributed to the agent.
    pub intent_rationale: Option<&'a str>,
}

impl<'a> AttributionOverrides<'a> {
    /// True when nothing was declared, so applying this is a no-op.
    fn is_empty(&self) -> bool {
        self.agent.is_none()
            && self.agent_version.is_none()
            && self.agent_model.is_none()
            && self.agent_session.is_none()
            && self.agent_turn.is_none()
            && self.authorization.is_none()
            && self.grant.is_none()
            && self.approved_by.is_none()
            && self.approved_at.is_none()
            && self.approved_changes.is_none()
            && self.intent.is_none()
            && self.intent_request.is_none()
            && self.intent_rationale.is_none()
    }
}

impl Attribution {
    /// Resolve attribution from the process environment.
    ///
    /// `CR_AGENT`, `CR_AUTHORIZATION`, and `CR_INTENT` are explicit
    /// declarations and outrank the probe table below them. `CR_AGENT=none`
    /// declares that no agent was involved and suppresses detection entirely.
    /// That is an escape hatch, and it is also all it takes to defeat
    /// detection: the local user owns the process and its environment.
    pub fn from_environment() -> Result<Self> {
        let agent = environment("CR_AGENT");
        let authorization = environment("CR_AUTHORIZATION");
        let intent = environment("CR_INTENT");
        let mut attribution = Self {
            agent: if agent.is_some() { None } else { probe_agent() },
            ..Self::default()
        };
        attribution.apply(
            &AttributionOverrides {
                agent: agent.as_deref(),
                authorization: authorization.as_deref(),
                intent: intent.as_deref(),
                ..AttributionOverrides::default()
            },
            AgentEvidence::Flag,
        )?;
        Ok(attribution)
    }

    /// Apply declared overrides on top of whatever is already in effect.
    ///
    /// `evidence` records where the declaration came from. Enriching an agent
    /// that was merely observed promotes its `detected_from` to `evidence`,
    /// because once a caller has filled in part of the object, calling the whole
    /// of it "observed" would overstate what `cr` saw.
    pub fn apply(
        &mut self,
        overrides: &AttributionOverrides<'_>,
        evidence: AgentEvidence,
    ) -> Result<()> {
        if overrides.is_empty() {
            return Ok(());
        }
        self.apply_agent(overrides, evidence)?;
        self.apply_authorization(overrides)?;
        self.apply_intent(overrides)?;
        Ok(())
    }

    fn apply_agent(
        &mut self,
        overrides: &AttributionOverrides<'_>,
        evidence: AgentEvidence,
    ) -> Result<()> {
        if let Some(spec) = overrides.agent {
            self.agent = parse_agent(spec, evidence.clone())?;
        }
        let details = [
            ("agent version", overrides.agent_version),
            ("agent model", overrides.agent_model),
            ("agent session", overrides.agent_session),
            ("agent turn", overrides.agent_turn),
        ];
        if details.iter().all(|(_, value)| value.is_none()) {
            return Ok(());
        }
        let Some(agent) = self.agent.as_mut() else {
            let field = details
                .iter()
                .find_map(|(field, value)| value.map(|_| *field))
                .unwrap_or("agent detail");
            return Err(invalid(format!(
                "{field} cannot be recorded without an agent identity; declare one first"
            )));
        };
        if let Some(value) = overrides.agent_version {
            agent.version = Some(identifier(value, "agent version")?);
        }
        if let Some(value) = overrides.agent_model {
            agent.model = Some(identifier(value, "agent model")?);
        }
        if let Some(value) = overrides.agent_session {
            agent.session = Some(identifier(value, "agent session")?);
        }
        if let Some(value) = overrides.agent_turn {
            agent.turn = Some(identifier(value, "agent turn")?);
        }
        agent.detected_from = evidence;
        Ok(())
    }

    fn apply_authorization(&mut self, overrides: &AttributionOverrides<'_>) -> Result<()> {
        if let Some(spec) = overrides.authorization {
            self.authorization = Some(parse_authorization(spec)?);
        }
        let details = [
            ("authorization grant", overrides.grant),
            ("approving identity", overrides.approved_by),
            ("approval timestamp", overrides.approved_at),
            ("approved change set", overrides.approved_changes),
        ];
        if details.iter().all(|(_, value)| value.is_none()) {
            return Ok(());
        }
        let Some(authorization) = self.authorization.as_mut() else {
            let field = details
                .iter()
                .find_map(|(field, value)| value.map(|_| *field))
                .unwrap_or("authorization detail");
            return Err(invalid(format!(
                "{field} cannot be recorded without an authorization mode; declare one first"
            )));
        };
        if let Some(value) = overrides.grant {
            authorization.grant = Some(identifier(value, "authorization grant")?);
        }
        if let Some(value) = overrides.approved_by {
            authorization.approved_by = Some(identifier(value, "approving identity")?);
        }
        if let Some(value) = overrides.approved_at {
            authorization.at = Some(timestamp(value, "approval timestamp")?);
        }
        if let Some(value) = overrides.approved_changes {
            authorization.approved_changes = Some(digest(value, "approved change set")?);
        }
        Ok(())
    }

    fn apply_intent(&mut self, overrides: &AttributionOverrides<'_>) -> Result<()> {
        if let Some(spec) = overrides.intent {
            self.intent = Some(parse_intent(spec)?);
        }
        if let Some(text) = overrides.intent_request {
            let part = AuditIntentPart {
                author: IntentAuthor::Human,
                text: Some(intent_text(text, "intent request")?),
                digest: None,
                reference: None,
                at: None,
            };
            self.intent.get_or_insert_with(empty_intent).request = Some(part);
        }
        if let Some(text) = overrides.intent_rationale {
            let part = AuditIntentPart {
                author: IntentAuthor::Agent,
                text: Some(intent_text(text, "intent rationale")?),
                digest: None,
                reference: None,
                at: None,
            };
            self.intent.get_or_insert_with(empty_intent).rationale = Some(part);
        }
        if let Some(intent) = self.intent.as_ref() {
            validate_intent_size(intent)?;
        }
        Ok(())
    }
}

/// An intent with neither half filled in yet.
fn empty_intent() -> AuditIntent {
    AuditIntent {
        request: None,
        rationale: None,
    }
}

/// Read a non-empty environment variable.
fn environment(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Look for a documented agent variable in the process environment.
///
/// Records only what was observed. An agent that announces itself without a
/// session identifier produces an object with an identifier and nothing else,
/// rather than a plausible-looking guess.
fn probe_agent() -> Option<AuditAgent> {
    let probe = AGENT_PROBES
        .iter()
        .find(|probe| environment(probe.variable).is_some())?;
    Some(AuditAgent {
        id: probe.id.to_owned(),
        version: None,
        model: None,
        session: probe
            .session_variable
            .and_then(environment)
            .and_then(|value| identifier(&value, "agent session").ok()),
        turn: None,
        detected_from: AgentEvidence::Environment,
        via: None,
    })
}

/// A declared agent: `none`, a bare identifier, or a JSON object.
pub fn parse_agent(spec: &str, evidence: AgentEvidence) -> Result<Option<AuditAgent>> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(invalid("agent cannot be empty"));
    }
    if spec == "none" {
        return Ok(None);
    }
    if !spec.starts_with('{') {
        return Ok(Some(AuditAgent {
            id: identifier(spec, "agent")?,
            version: None,
            model: None,
            session: None,
            turn: None,
            detected_from: evidence,
            via: None,
        }));
    }
    let parsed: AgentSpec = serde_json::from_str(spec)
        .map_err(|error| invalid(format!("agent is not a valid agent object: {error}")))?;
    parsed.into_agent(&evidence, 1).map(Some)
}

/// A declared authorization: a bare mode or a JSON object.
pub fn parse_authorization(spec: &str) -> Result<AuditAuthorization> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(invalid("authorization cannot be empty"));
    }
    if !spec.starts_with('{') {
        return Ok(AuditAuthorization {
            mode: authorization_mode(spec)?,
            grant: None,
            approved_by: None,
            at: None,
            approved_changes: None,
        });
    }
    let parsed: AuthorizationSpec = serde_json::from_str(spec).map_err(|error| {
        invalid(format!(
            "authorization is not a valid authorization object: {error}"
        ))
    })?;
    Ok(AuditAuthorization {
        mode: authorization_mode(&parsed.mode)?,
        grant: optional_identifier(parsed.grant.as_deref(), "authorization grant")?,
        approved_by: optional_identifier(parsed.approved_by.as_deref(), "approving identity")?,
        at: optional_timestamp(parsed.at.as_deref(), "approval timestamp")?,
        approved_changes: parsed
            .approved_changes
            .as_deref()
            .map(|value| digest(value, "approved change set"))
            .transpose()?,
    })
}

/// Accept only an approval mode this build knows.
///
/// The stored type tolerates an unknown label so a journal a newer `cr` wrote
/// still verifies. Input does not: recording a mode `cr` cannot name would put
/// a value into a permanent record that no reader — including this one — can
/// interpret.
fn authorization_mode(label: &str) -> Result<AuthorizationMode> {
    AuthorizationMode::parse_known(label).ok_or_else(|| {
        invalid(format!(
            "authorization mode '{label}' must be direct, interactive, delegated, autonomous, or unknown"
        ))
    })
}

/// Accept only an intent author this build knows. See [`authorization_mode`].
fn intent_author(label: &str, field: &str) -> Result<IntentAuthor> {
    IntentAuthor::parse_known(label)
        .ok_or_else(|| invalid(format!("{field} author must be human, agent, or system")))
}

/// A declared intent object.
pub fn parse_intent(spec: &str) -> Result<AuditIntent> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(invalid("intent cannot be empty"));
    }
    if !spec.starts_with('{') {
        return Err(invalid(
            "intent must be a JSON object with a request, a rationale, or both",
        ));
    }
    let parsed: IntentSpec = serde_json::from_str(spec)
        .map_err(|error| invalid(format!("intent is not a valid intent object: {error}")))?;
    if parsed.request.is_none() && parsed.rationale.is_none() {
        return Err(invalid(
            "intent must contain a request, a rationale, or both",
        ));
    }
    let intent = AuditIntent {
        request: parsed
            .request
            .map(|part| part.into_part(IntentAuthor::Human, "intent request"))
            .transpose()?,
        rationale: parsed
            .rationale
            .map(|part| part.into_part(IntentAuthor::Agent, "intent rationale"))
            .transpose()?,
    };
    validate_intent_size(&intent)?;
    Ok(intent)
}

/// Reject an intent that would put more than the bounded budget in the journal.
///
/// The cap fails loudly rather than truncating, so an agent that tries to paste
/// a transcript into permanent storage finds out immediately.
fn validate_intent_size(intent: &AuditIntent) -> Result<()> {
    let total: usize = [intent.request.as_ref(), intent.rationale.as_ref()]
        .into_iter()
        .flatten()
        .filter_map(|part| part.text.as_deref())
        .map(str::chars)
        .map(Iterator::count)
        .sum();
    if total > MAX_INTENT_CHARS {
        return Err(invalid(format!(
            "intent text is {total} characters, which exceeds the {MAX_INTENT_CHARS}-character limit for one event"
        )));
    }
    Ok(())
}

/// The strict input shape for a declared agent.
///
/// `detected_from` is deliberately absent: it says how `cr` came to believe
/// this, so a caller supplying it would be answering a question about `cr`.
/// `deny_unknown_fields` turns that into an explicit rejection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSpec {
    id: String,
    version: Option<String>,
    model: Option<String>,
    session: Option<String>,
    turn: Option<String>,
    #[serde(default)]
    via: Vec<AgentSpec>,
}

impl AgentSpec {
    fn into_agent(self, evidence: &AgentEvidence, depth: usize) -> Result<AuditAgent> {
        if depth > MAX_DELEGATION_DEPTH {
            return Err(invalid(format!(
                "agent delegation chain is longer than {MAX_DELEGATION_DEPTH} agents"
            )));
        }
        let via = self
            .via
            .into_iter()
            .map(|delegate| delegate.into_agent(evidence, depth + 1))
            .collect::<Result<Vec<_>>>()?;
        Ok(AuditAgent {
            id: identifier(&self.id, "agent")?,
            version: optional_identifier(self.version.as_deref(), "agent version")?,
            model: optional_identifier(self.model.as_deref(), "agent model")?,
            session: optional_identifier(self.session.as_deref(), "agent session")?,
            turn: optional_identifier(self.turn.as_deref(), "agent turn")?,
            detected_from: evidence.clone(),
            via: (!via.is_empty()).then_some(via),
        })
    }
}

/// The strict input shape for a declared authorization.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationSpec {
    /// Validated against the labels this build knows, never stored verbatim.
    mode: String,
    grant: Option<String>,
    approved_by: Option<String>,
    at: Option<String>,
    approved_changes: Option<String>,
}

/// The strict input shape for a declared intent.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentSpec {
    request: Option<IntentPartSpec>,
    rationale: Option<IntentPartSpec>,
}

/// The strict input shape for one half of a declared intent.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentPartSpec {
    /// Validated against the labels this build knows, never stored verbatim.
    author: Option<String>,
    text: Option<String>,
    digest: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    at: Option<String>,
}

impl IntentPartSpec {
    fn into_part(self, default_author: IntentAuthor, field: &str) -> Result<AuditIntentPart> {
        let part = AuditIntentPart {
            author: self
                .author
                .as_deref()
                .map(|label| intent_author(label, field))
                .transpose()?
                .unwrap_or(default_author),
            text: self
                .text
                .as_deref()
                .map(|value| intent_text(value, field))
                .transpose()?,
            digest: self
                .digest
                .as_deref()
                .map(|value| digest(value, field))
                .transpose()?,
            reference: optional_identifier(self.reference.as_deref(), field)?,
            at: optional_timestamp(self.at.as_deref(), field)?,
        };
        match (part.text.is_some(), part.digest.is_some()) {
            (true, false) | (false, true) => {}
            (true, true) => {
                return Err(invalid(format!(
                    "{field} must carry either text or a digest, not both"
                )));
            }
            (false, false) => return Err(invalid(format!("{field} must carry text or a digest"))),
        }
        if part.text.is_some() && part.reference.is_some() {
            return Err(invalid(format!(
                "{field} cannot carry a reference alongside inline text"
            )));
        }
        Ok(part)
    }
}

/// Validate a single-line attribution identifier.
fn identifier(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid(format!("{field} cannot be empty")));
    }
    let length = value.chars().count();
    if length > MAX_IDENTIFIER_CHARS {
        return Err(invalid(format!(
            "{field} is {length} characters, which exceeds the {MAX_IDENTIFIER_CHARS}-character limit"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} cannot contain control characters"
        )));
    }
    Ok(value.to_owned())
}

fn optional_identifier(value: Option<&str>, field: &str) -> Result<Option<String>> {
    value.map(|value| identifier(value, field)).transpose()
}

/// Validate bounded intent prose. Line breaks are allowed; other control
/// characters are not.
fn intent_text(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid(format!("{field} cannot be empty")));
    }
    let length = value.chars().count();
    if length > MAX_INTENT_TEXT_CHARS {
        return Err(invalid(format!(
            "{field} is {length} characters, which exceeds the {MAX_INTENT_TEXT_CHARS}-character limit"
        )));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(invalid(format!(
            "{field} cannot contain control characters"
        )));
    }
    Ok(value.to_owned())
}

/// Validate a `sha256:` digest of text held outside the payload.
fn digest(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    let hex = value.strip_prefix("sha256:").filter(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    match hex {
        Some(_) => Ok(value.to_owned()),
        None => Err(invalid(format!(
            "{field} digest must be 'sha256:' followed by 64 lowercase hexadecimal characters"
        ))),
    }
}

/// Shape-check an RFC 3339 timestamp.
///
/// This checks the layout only. It does not validate the calendar, and it is
/// not evidence that the instant is real: like everything else here, the value
/// is a claim by the process that supplied it.
fn timestamp(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    let bytes = value.as_bytes();
    let shaped = bytes.len() >= 20
        && bytes.len() <= 64
        && matches!(bytes[4], b'-')
        && matches!(bytes[7], b'-')
        && matches!(bytes[10], b'T' | b't' | b' ')
        && matches!(bytes[13], b':')
        && matches!(bytes[16], b':')
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit)
        && bytes[19..]
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'.' | b'+' | b'-' | b':' | b'Z' | b'z'));
    if !shaped {
        return Err(invalid(format!(
            "{field} must be an RFC 3339 timestamp such as 2026-09-01T09:17:41Z"
        )));
    }
    Ok(value.to_owned())
}

fn optional_timestamp(value: Option<&str>, field: &str) -> Result<Option<String>> {
    value.map(|value| timestamp(value, field)).transpose()
}

#[cfg(test)]
mod tests {
    use super::{
        AgentEvidence, Attribution, AttributionOverrides, AuditAgent, AuthorizationMode,
        IntentAuthor, MAX_INTENT_TEXT_CHARS, parse_agent, parse_authorization, parse_intent,
    };
    use crate::DomainError;

    fn overrides<'a>() -> AttributionOverrides<'a> {
        AttributionOverrides::default()
    }

    fn message(error: &anyhow::Error) -> String {
        DomainError::of(error)
            .expect("attribution rejections are classified")
            .message()
            .to_owned()
    }

    #[test]
    fn a_bare_identifier_records_only_what_was_declared() {
        let agent = parse_agent("claude-code", AgentEvidence::Flag)
            .unwrap()
            .unwrap();
        assert_eq!(agent.id, "claude-code");
        assert_eq!(agent.detected_from, AgentEvidence::Flag);
        assert!(agent.version.is_none());
        assert!(agent.model.is_none());
        assert!(agent.session.is_none());
        assert!(agent.via.is_none());
    }

    #[test]
    fn declaring_no_agent_clears_a_detected_one() {
        let mut attribution = Attribution {
            agent: Some(AuditAgent {
                id: "claude-code".to_owned(),
                version: None,
                model: None,
                session: None,
                turn: None,
                detected_from: AgentEvidence::Environment,
                via: None,
            }),
            ..Attribution::default()
        };
        attribution
            .apply(
                &AttributionOverrides {
                    agent: Some("none"),
                    ..overrides()
                },
                AgentEvidence::Flag,
            )
            .unwrap();
        assert!(attribution.agent.is_none());
    }

    #[test]
    fn a_caller_cannot_declare_how_cr_came_to_believe_it() {
        let error = parse_agent(
            r#"{"id":"claude-code","detected_from":"environment"}"#,
            AgentEvidence::Header,
        )
        .unwrap_err();
        assert!(message(&error).contains("detected_from"));
    }

    #[test]
    fn enriching_an_observed_agent_downgrades_its_evidence_to_declared() {
        let mut attribution = Attribution {
            agent: Some(AuditAgent {
                id: "claude-code".to_owned(),
                version: None,
                model: None,
                session: None,
                turn: None,
                detected_from: AgentEvidence::Environment,
                via: None,
            }),
            ..Attribution::default()
        };
        attribution
            .apply(
                &AttributionOverrides {
                    agent_model: Some("claude-opus-4-5"),
                    ..overrides()
                },
                AgentEvidence::Flag,
            )
            .unwrap();
        let agent = attribution.agent.unwrap();
        assert_eq!(agent.model.as_deref(), Some("claude-opus-4-5"));
        assert_eq!(agent.detected_from, AgentEvidence::Flag);
    }

    #[test]
    fn agent_details_need_an_agent_identity() {
        let mut attribution = Attribution::default();
        let error = attribution
            .apply(
                &AttributionOverrides {
                    agent_session: Some("6d1baa69"),
                    ..overrides()
                },
                AgentEvidence::Flag,
            )
            .unwrap_err();
        assert!(message(&error).contains("without an agent identity"));
    }

    #[test]
    fn a_delegation_chain_is_queryable_at_every_hop() {
        let agent = parse_agent(
            r#"{"id":"claude-code-subagent","session":"child","via":[{"id":"claude-code","session":"parent"}]}"#,
            AgentEvidence::Header,
        )
        .unwrap()
        .unwrap();
        assert!(agent.declares_id("claude-code-subagent"));
        assert!(agent.declares_id("claude-code"));
        assert!(!agent.declares_id("cursor-agent"));
        assert!(agent.declares_session("parent"));
        assert!(agent.declares_session("child"));
        assert!(!agent.declares_session("other"));
        assert_eq!(
            agent.via.as_ref().unwrap()[0].detected_from,
            AgentEvidence::Header
        );
    }

    #[test]
    fn authorization_accepts_a_bare_mode_and_a_full_object() {
        assert_eq!(
            parse_authorization("delegated").unwrap().mode,
            AuthorizationMode::Delegated
        );
        let authorization = parse_authorization(
            r#"{"mode":"interactive","grant":"acceptEdits","approved_by":"Ada <ada@example.com>","at":"2026-09-01T09:17:55Z"}"#,
        )
        .unwrap();
        assert_eq!(authorization.mode, AuthorizationMode::Interactive);
        assert_eq!(authorization.grant.as_deref(), Some("acceptEdits"));
        assert_eq!(authorization.at.as_deref(), Some("2026-09-01T09:17:55Z"));
        assert!(authorization.approved_changes.is_none());

        let error = parse_authorization("supervised").unwrap_err();
        assert!(message(&error).contains("must be direct, interactive"));
    }

    /// The approved-change digest is shaped input like any other: `cr` checks
    /// it before recording it, so a malformed digest fails at the flag rather
    /// than becoming a permanent value that can never match anything.
    #[test]
    fn an_approved_change_digest_must_be_a_sha256_digest() {
        let error = parse_authorization(r#"{"mode":"delegated","approved_changes":"sha256:abc"}"#)
            .unwrap_err();
        assert!(message(&error).contains("64 lowercase hexadecimal"));

        let accepted = parse_authorization(
            r#"{"mode":"interactive","approved_changes":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#,
        )
        .unwrap();
        assert_eq!(
            accepted.approved_changes.as_deref(),
            Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );

        let mut attribution = Attribution::default();
        let orphan = attribution
            .apply(
                &AttributionOverrides {
                    approved_changes: Some(
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    ),
                    ..overrides()
                },
                AgentEvidence::Flag,
            )
            .unwrap_err();
        assert!(message(&orphan).contains("without an authorization mode"));
    }

    #[test]
    fn intent_keeps_the_request_and_the_rationale_separately_attributed() {
        let intent = parse_intent(
            r#"{"request":{"text":"close the deal","at":"2026-09-01T09:17:41Z"},"rationale":{"text":"set status to closed-won"}}"#,
        )
        .unwrap();
        let request = intent.request.unwrap();
        let rationale = intent.rationale.unwrap();
        assert_eq!(request.author, IntentAuthor::Human);
        assert_eq!(request.at.as_deref(), Some("2026-09-01T09:17:41Z"));
        assert_eq!(rationale.author, IntentAuthor::Agent);
        assert_eq!(rationale.text.as_deref(), Some("set status to closed-won"));
    }

    #[test]
    fn intent_carries_either_text_or_a_digest() {
        let stored = parse_intent(
            r#"{"request":{"digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ref":"intent/0123"}}"#,
        )
        .unwrap();
        assert!(stored.request.as_ref().unwrap().text.is_none());
        assert_eq!(
            stored.request.unwrap().reference.as_deref(),
            Some("intent/0123")
        );

        let both = parse_intent(
            r#"{"request":{"text":"a","digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}"#,
        )
        .unwrap_err();
        assert!(message(&both).contains("either text or a digest"));
        let neither = parse_intent(r#"{"request":{"author":"human"}}"#).unwrap_err();
        assert!(message(&neither).contains("must carry text or a digest"));
    }

    #[test]
    fn oversized_intent_fails_loudly_instead_of_being_truncated() {
        let text = "x".repeat(MAX_INTENT_TEXT_CHARS + 1);
        let mut attribution = Attribution::default();
        let error = attribution
            .apply(
                &AttributionOverrides {
                    intent_request: Some(&text),
                    ..overrides()
                },
                AgentEvidence::Flag,
            )
            .unwrap_err();
        assert!(message(&error).contains("exceeds the"));
    }

    #[test]
    fn rejections_never_name_a_path_or_an_operating_system_error() {
        for error in [
            parse_agent("", AgentEvidence::Flag).unwrap_err(),
            parse_agent("{\"id\":\"\"}", AgentEvidence::Flag).unwrap_err(),
            parse_authorization("{").unwrap_err(),
            parse_intent("not json").unwrap_err(),
        ] {
            let message = message(&error);
            assert!(!message.contains('/'), "{message}");
            assert!(!message.contains("os error"), "{message}");
        }
    }

    /// Reading tolerates a value this build does not know; writing does not.
    ///
    /// The stored types have to accept an unknown label, because refusing it
    /// would fail the payload and therefore the whole hash chain. Caller input
    /// has to refuse it, because recording a label `cr` cannot name would put a
    /// value nobody can interpret into a permanent record — and would let a
    /// caller invent an approval mode that looks stronger than it is.
    #[test]
    fn an_unknown_label_is_read_verbatim_but_never_accepted_from_a_caller() {
        let mode: AuthorizationMode = serde_json::from_str(r#""escalated""#).unwrap();
        assert_eq!(mode, AuthorizationMode::Other("escalated".to_owned()));
        assert_eq!(mode.label(), "escalated");
        assert!(!mode.is_known());
        assert_eq!(serde_json::to_string(&mode).unwrap(), r#""escalated""#);

        let evidence: AgentEvidence = serde_json::from_str(r#""attestation""#).unwrap();
        assert_eq!(evidence, AgentEvidence::Other("attestation".to_owned()));
        assert_eq!(
            serde_json::to_string(&evidence).unwrap(),
            r#""attestation""#
        );

        let author: IntentAuthor = serde_json::from_str(r#""operator""#).unwrap();
        assert_eq!(author, IntentAuthor::Other("operator".to_owned()));
        assert_eq!(serde_json::to_string(&author).unwrap(), r#""operator""#);

        assert!(AuthorizationMode::parse_known("escalated").is_none());
        assert_eq!(
            AuthorizationMode::parse_known("delegated"),
            Some(AuthorizationMode::Delegated)
        );
        assert!(AuthorizationMode::Delegated.is_known());

        let bare = parse_authorization("escalated").unwrap_err();
        assert!(message(&bare).contains("must be direct, interactive"));
        let object = parse_authorization(r#"{"mode":"escalated"}"#).unwrap_err();
        assert!(message(&object).contains("must be direct, interactive"));
        let author =
            parse_intent(r#"{"request":{"author":"operator","text":"hello"}}"#).unwrap_err();
        assert!(message(&author).contains("author must be human, agent, or system"));
    }

    #[test]
    fn timestamps_are_shape_checked() {
        let error = parse_authorization(r#"{"mode":"delegated","at":"yesterday"}"#).unwrap_err();
        assert!(message(&error).contains("RFC 3339"));
    }
}
