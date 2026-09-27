//! Signing people in to `cr serve` through Cloudflare Access.
//!
//! Cloudflare Access sits in front of the server, signs its visitors in with
//! the organisation's identity provider, and forwards each request with a JSON
//! Web Token in the `Cf-Access-Jwt-Assertion` header. The token is signed with
//! RS256 by a key the team publishes at
//! `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`, and names the
//! team (`iss`), the Access application (`aud`), when it expires, and who
//! signed in (`email`, and Cloudflare's own ID for them, `sub`).
//!
//! This module checks that assertion and nothing else. The signature is what
//! makes it evidence: anything on the machine can reach a loopback port and
//! send whatever headers it likes, so `Cf-Access-Authenticated-User-Email` and
//! the `CF_Authorization` cookie are never read. Which user the verified email
//! belongs to is the database's question, answered by
//! [`crate::Database::authenticate_email`] against the audited policy.
//!
//! The team's keys are fetched once and cached. A token signed by a key the
//! cache does not know causes one more fetch, which is how a rotated key is
//! picked up, but no more than one every [`MIN_FETCH_INTERVAL`], so a stream of
//! made-up key IDs cannot turn the server into a client hammering Cloudflare.
//! A cache older than [`KEYS_MAX_AGE`] is replaced on the next request, so a
//! key Cloudflare withdraws stops verifying; if that refresh fails, the keys
//! already held keep working rather than signing everybody out.

use std::{
    collections::HashMap,
    fmt,
    sync::{Mutex, PoisonError, RwLock, TryLockError},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::{
    Engine as _,
    engine::{
        DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::URL_SAFE_NO_PAD,
    },
};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde_json::{Map, Value as JsonValue};

use crate::error::invalid;

/// The request header Cloudflare Access carries its signed assertion in.
pub const ASSERTION_HEADER: &str = "cf-access-jwt-assertion";

const TEAM_DOMAIN_SUFFIX: &str = ".cloudflareaccess.com";
const CERTS_PATH: &str = "/cdn-cgi/access/certs";

/// Longer than any assertion Cloudflare issues, and short enough that a
/// request cannot make the server decode and parse megabytes before refusing.
const MAX_ASSERTION_BYTES: usize = 16 * 1024;
/// A team's key set is a few kilobytes; anything past this is not one.
const MAX_CERTS_BYTES: u64 = 256 * 1024;
/// Keys kept from one key set. Cloudflare publishes the current key and the
/// previous one.
const MAX_KEYS: usize = 32;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a fetched key set is used before the next request replaces it.
pub const KEYS_MAX_AGE: Duration = Duration::from_secs(60 * 60);
/// The shortest time between two fetches of the key set.
pub const MIN_FETCH_INTERVAL: Duration = Duration::from_secs(10);
/// Clock difference tolerated between Cloudflare and this server when
/// checking `exp` and `nbf`.
pub const CLOCK_LEEWAY_SECONDS: i64 = 60;

/// Longest `email` and `sub` claim accepted. Both are recorded, so both are
/// bounded, although Cloudflare signed them.
const MAX_EMAIL_CHARS: usize = 320;
const MAX_SUBJECT_CHARS: usize = 256;

/// A key set's `n` and `e` are unpadded base64url, but a JWK written by hand
/// sometimes pads them; the token itself is held to the strict form.
const JWK_BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// What `cr serve` checks a Cloudflare Access assertion against, and the
/// team's signing keys, fetched on demand and cached.
pub struct CloudflareAccess {
    issuer: String,
    audience: String,
    certs_url: String,
    min_fetch_interval: Duration,
    agent: ureq::Agent,
    keys: RwLock<KeySet>,
    /// Held while the key set is fetched, so requests that all need a key the
    /// cache lacks wait for one fetch rather than each making their own.
    fetching: Mutex<()>,
}

impl fmt::Debug for CloudflareAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareAccess")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("certs_url", &self.certs_url)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct KeySet {
    keys: HashMap<String, SigningKey>,
    /// When `keys` was fetched.
    fetched: Option<Instant>,
    /// When a fetch was last started, whether or not it succeeded.
    attempted: Option<Instant>,
    /// Why the most recent fetch failed; cleared by one that succeeds.
    failure: Option<String>,
}

impl KeySet {
    fn fresh(&self) -> bool {
        self.fetched
            .is_some_and(|fetched| fetched.elapsed() < KEYS_MAX_AGE)
    }

    fn fetch_due(&self, interval: Duration) -> bool {
        self.attempted
            .is_none_or(|attempted| attempted.elapsed() >= interval)
    }
}

#[derive(Clone)]
struct SigningKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

/// Whether the server can check an assertion without fetching first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyStatus {
    /// At least one signing key is held. It may be older than
    /// [`KEYS_MAX_AGE`], if every refresh since has failed.
    Held,
    /// No fetch has finished yet.
    NotFetched,
    /// No key is held, and this is why the last fetch failed.
    Unavailable(String),
}

/// Who a verified assertion says signed in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAssertion {
    pub email: String,
    /// Cloudflare's ID for the person, recorded as the credential.
    pub subject: Option<String>,
}

/// Why an assertion was not accepted.
#[derive(Debug)]
pub enum AssertionError {
    /// The assertion proves nothing: malformed, not signed by the team, for
    /// another application, expired, or naming no email.
    Rejected(String),
    /// The team's keys could not be fetched, so no assertion signed by a key
    /// the server does not already hold can be checked. The server's fault,
    /// not the caller's.
    KeysUnavailable(anyhow::Error),
}

impl fmt::Display for AssertionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(reason) => {
                write!(formatter, "the Cloudflare Access assertion {reason}")
            }
            Self::KeysUnavailable(error) => {
                write!(
                    formatter,
                    "the Cloudflare Access signing keys are unavailable: {error:#}"
                )
            }
        }
    }
}

impl std::error::Error for AssertionError {}

fn rejected(reason: impl Into<String>) -> AssertionError {
    AssertionError::Rejected(reason.into())
}

impl CloudflareAccess {
    /// Check assertions issued by `team_domain` for the Access application
    /// whose audience tag is `audience`.
    ///
    /// The team is named as Cloudflare shows it — `https://example.cloudflareaccess.com`
    /// — or as `example.cloudflareaccess.com` or `example`. It becomes the
    /// `iss` every assertion must carry exactly, and the host the keys are
    /// fetched from; nothing here follows a URL an assertion names.
    pub fn new(team_domain: &str, audience: &str) -> Result<Self> {
        let issuer = team_issuer(team_domain)?;
        let audience = audience.trim();
        if audience.is_empty()
            || audience.len() > 256
            || !audience.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(invalid(
                "the Cloudflare Access audience must be the application's AUD tag, 1 to 256 visible ASCII characters",
            ));
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(FETCH_TIMEOUT))
            // The key set is served where it is asked for. A redirect is a
            // misconfiguration to report, not somewhere else to trust.
            .max_redirects(0)
            .http_status_as_error(false)
            .user_agent(concat!("cr/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Self {
            certs_url: format!("{issuer}{CERTS_PATH}"),
            min_fetch_interval: MIN_FETCH_INTERVAL,
            issuer,
            audience: audience.to_owned(),
            agent,
            keys: RwLock::default(),
            fetching: Mutex::default(),
        })
    }

    /// Fetch the signing keys from `url` rather than from the team domain.
    ///
    /// For tests and for a mirror. Assertions must still name the team as
    /// their issuer.
    pub fn with_certs_url(mut self, url: impl Into<String>) -> Self {
        self.certs_url = url.into();
        self
    }

    /// Allow fetches closer together than [`MIN_FETCH_INTERVAL`]. For tests,
    /// which rotate keys faster than Cloudflare does.
    pub fn with_min_fetch_interval(mut self, interval: Duration) -> Self {
        self.min_fetch_interval = interval;
        self
    }

    /// The `iss` every accepted assertion carries.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The application audience tag every accepted assertion carries.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Where the team's signing keys are fetched from.
    pub fn certs_url(&self) -> &str {
        &self.certs_url
    }

    /// Fetch the key set now, whenever it was last fetched, returning how many
    /// usable keys it held. `cr serve` calls this at startup so the first
    /// sign-in does not wait for it, and so a wrong team is reported at once.
    pub fn refresh_keys(&self) -> Result<usize> {
        let _fetching = self.fetching.lock().unwrap_or_else(PoisonError::into_inner);
        self.fetch_and_store()
    }

    /// Fetch the key set unless it is fresh, was tried too recently, or is
    /// being fetched already.
    ///
    /// For a caller that must not wait, such as a readiness probe, to run on a
    /// thread of its own.
    pub fn refresh_keys_if_due(&self) {
        let _fetching = match self.fetching.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        let due = {
            let keys = self.read_keys();
            !keys.fresh() && keys.fetch_due(self.min_fetch_interval)
        };
        if due {
            // A failure is recorded in the key set, which is where readiness
            // and the next request read it.
            let _ = self.fetch_and_store();
        }
    }

    /// Whether any signing key is held, answered from the cache without
    /// fetching.
    pub fn key_status(&self) -> KeyStatus {
        let keys = self.read_keys();
        if !keys.keys.is_empty() {
            KeyStatus::Held
        } else if let Some(failure) = &keys.failure {
            KeyStatus::Unavailable(failure.clone())
        } else {
            KeyStatus::NotFetched
        }
    }

    /// Verify an assertion as of now.
    pub fn verify(
        &self,
        assertion: &str,
    ) -> std::result::Result<VerifiedAssertion, AssertionError> {
        self.verify_at(assertion, time::OffsetDateTime::now_utc().unix_timestamp())
    }

    /// Verify an assertion as of `now`, in seconds since the Unix epoch.
    ///
    /// The order matters. Nothing in the payload is read until the signature
    /// over it has verified, and the header is read only for the two things
    /// needed to verify it: that the algorithm is RS256, and which key.
    pub fn verify_at(
        &self,
        assertion: &str,
        now: i64,
    ) -> std::result::Result<VerifiedAssertion, AssertionError> {
        if assertion.len() > MAX_ASSERTION_BYTES {
            return Err(rejected("is too long"));
        }
        let mut segments = assertion.split('.');
        let (Some(header), Some(payload), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(rejected("is not a signed JSON Web Token"));
        };
        let header = json_segment(header).ok_or_else(|| rejected("has an unreadable header"))?;
        // Only RS256, whatever the header asks for: `none`, an HMAC keyed with
        // the public key, and every other substitution fail here.
        if header.get("alg").and_then(JsonValue::as_str) != Some("RS256") {
            return Err(rejected("is not signed with RS256"));
        }
        // An extension marked critical must be understood or refused, and
        // Cloudflare marks none.
        if header.contains_key("crit") {
            return Err(rejected("names critical extensions cr does not understand"));
        }
        let key_id = header
            .get("kid")
            .and_then(JsonValue::as_str)
            .filter(|kid| !kid.is_empty())
            .ok_or_else(|| rejected("names no signing key"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| rejected("has an unreadable signature"))?;
        let key = self.signing_key(key_id)?;
        let signed = &assertion.as_bytes()[..header_and_payload_len(assertion)];
        RsaPublicKeyComponents {
            n: &key.n,
            e: &key.e,
        }
        .verify(&RSA_PKCS1_2048_8192_SHA256, signed, &signature)
        .map_err(|_| rejected("is not signed by the team's key"))?;

        let claims = json_segment(payload).ok_or_else(|| rejected("has an unreadable payload"))?;
        if claims.get("iss").and_then(JsonValue::as_str) != Some(self.issuer.as_str()) {
            return Err(rejected(format!("was not issued by {}", self.issuer)));
        }
        let audience_matches = match claims.get("aud") {
            Some(JsonValue::String(audience)) => audience == &self.audience,
            Some(JsonValue::Array(audiences)) => audiences
                .iter()
                .any(|audience| audience.as_str() == Some(self.audience.as_str())),
            _ => false,
        };
        if !audience_matches {
            return Err(rejected(
                "is for another Access application (its aud does not include this server's tag)",
            ));
        }
        let expires = claims
            .get("exp")
            .and_then(numeric_date)
            .ok_or_else(|| rejected("has no readable expiry"))?;
        if now >= expires.saturating_add(CLOCK_LEEWAY_SECONDS) {
            return Err(rejected("has expired"));
        }
        if let Some(not_before) = claims.get("nbf") {
            let not_before =
                numeric_date(not_before).ok_or_else(|| rejected("has an unreadable nbf"))?;
            if now.saturating_add(CLOCK_LEEWAY_SECONDS) < not_before {
                return Err(rejected("is not valid yet"));
            }
        }
        // A service token's assertion carries a `common_name` and no email.
        let email = claims
            .get("email")
            .and_then(JsonValue::as_str)
            .filter(|email| !email.is_empty())
            .ok_or_else(|| rejected("names no email, as a service token's does"))?;
        if email.chars().count() > MAX_EMAIL_CHARS || email.chars().any(char::is_control) {
            return Err(rejected("names an email cr cannot record"));
        }
        let subject = match claims.get("sub") {
            None => None,
            Some(JsonValue::String(subject)) if subject.is_empty() => None,
            Some(JsonValue::String(subject))
                if subject.chars().count() <= MAX_SUBJECT_CHARS
                    && !subject.chars().any(char::is_control) =>
            {
                Some(subject.clone())
            }
            Some(_) => return Err(rejected("names a subject cr cannot record")),
        };
        Ok(VerifiedAssertion {
            email: email.to_owned(),
            subject,
        })
    }

    fn read_keys(&self) -> std::sync::RwLockReadGuard<'_, KeySet> {
        self.keys.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The key an assertion names, fetching the key set when the cache does
    /// not hold it or is too old.
    fn signing_key(&self, key_id: &str) -> std::result::Result<SigningKey, AssertionError> {
        {
            let keys = self.read_keys();
            if keys.fresh()
                && let Some(key) = keys.keys.get(key_id)
            {
                return Ok(key.clone());
            }
        }
        let _fetching = self.fetching.lock().unwrap_or_else(PoisonError::into_inner);
        let due = {
            // Another request may have fetched while this one waited.
            let keys = self.read_keys();
            if keys.fresh()
                && let Some(key) = keys.keys.get(key_id)
            {
                return Ok(key.clone());
            }
            keys.fetch_due(self.min_fetch_interval)
        };
        if due {
            // Recorded in the key set either way; what matters below is only
            // whether the key is now held.
            let _ = self.fetch_and_store();
        }
        let keys = self.read_keys();
        if let Some(key) = keys.keys.get(key_id) {
            // Fresh, or held from before a refresh that failed.
            return Ok(key.clone());
        }
        match &keys.failure {
            Some(failure) => Err(AssertionError::KeysUnavailable(anyhow!("{failure}"))),
            None => Err(rejected("is signed by a key the team does not publish")),
        }
    }

    /// Fetch the key set and store the outcome. The caller holds `fetching`.
    fn fetch_and_store(&self) -> Result<usize> {
        self.keys
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .attempted = Some(Instant::now());
        let fetched = self.fetch();
        let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        match fetched {
            Ok(fetched) => {
                let count = fetched.len();
                keys.keys = fetched;
                keys.fetched = Some(Instant::now());
                keys.failure = None;
                Ok(count)
            }
            Err(error) => {
                keys.failure = Some(format!("{error:#}"));
                Err(error)
            }
        }
    }

    fn fetch(&self) -> Result<HashMap<String, SigningKey>> {
        let context = || {
            format!(
                "could not fetch Cloudflare Access keys from {}",
                self.certs_url
            )
        };
        let mut response = self
            .agent
            .get(&self.certs_url)
            .call()
            .with_context(context)?;
        let status = response.status();
        if status != ureq::http::StatusCode::OK {
            return Err(anyhow!("the server answered {status}")).with_context(context);
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_CERTS_BYTES)
            .read_to_string()
            .with_context(context)?;
        parse_key_set(&body).with_context(context)
    }
}

/// The issuer a team domain names, `https://<team>.cloudflareaccess.com`.
fn team_issuer(team_domain: &str) -> Result<String> {
    let domain = team_domain.trim();
    let domain = domain.strip_prefix("https://").unwrap_or(domain);
    let domain = domain
        .strip_suffix('/')
        .unwrap_or(domain)
        .to_ascii_lowercase();
    let team = domain.strip_suffix(TEAM_DOMAIN_SUFFIX).unwrap_or(&domain);
    let is_label = !team.is_empty()
        && team.len() <= 63
        && !team.starts_with('-')
        && !team.ends_with('-')
        && team
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !is_label {
        return Err(invalid(format!(
            "'{team_domain}' is not a Cloudflare Access team domain such as https://example{TEAM_DOMAIN_SUFFIX}"
        )));
    }
    Ok(format!("https://{team}{TEAM_DOMAIN_SUFFIX}"))
}

/// The RS256 keys in a JSON Web Key Set, by key ID. A key that is not an
/// RSA signing key for RS256, or is shorter than 2048 bits, is skipped rather
/// than failing the set; a set with no usable key at all is an error.
fn parse_key_set(body: &str) -> Result<HashMap<String, SigningKey>> {
    let document: JsonValue = serde_json::from_str(body).context("the key set is not JSON")?;
    let Some(listed) = document.get("keys").and_then(JsonValue::as_array) else {
        bail!("the key set has no keys");
    };
    let mut keys = HashMap::new();
    for key in listed.iter().take(MAX_KEYS) {
        let text = |name: &str| key.get(name).and_then(JsonValue::as_str);
        let usable = text("kty") == Some("RSA")
            && text("alg").is_none_or(|alg| alg == "RS256")
            && text("use").is_none_or(|usage| usage == "sig");
        let Some(key_id) = text("kid").filter(|kid| !kid.is_empty() && kid.len() <= 256) else {
            continue;
        };
        // Unsigned big-endian, which some publishers pad with a zero byte and
        // `ring` refuses to see padded.
        let integer = |name: &str| {
            text(name)
                .and_then(|value| JWK_BASE64.decode(value).ok())
                .map(|bytes| {
                    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
                    bytes[zeros..].to_vec()
                })
        };
        let (Some(n), Some(e)) = (integer("n"), integer("e")) else {
            continue;
        };
        if usable && (256..=1024).contains(&n.len()) && !e.is_empty() {
            keys.insert(key_id.to_owned(), SigningKey { n, e });
        }
    }
    if keys.is_empty() {
        bail!("the key set has no RS256 signing key");
    }
    Ok(keys)
}

/// The length of `header.payload`, the bytes the signature covers.
fn header_and_payload_len(assertion: &str) -> usize {
    assertion.rfind('.').unwrap_or(assertion.len())
}

fn json_segment(segment: &str) -> Option<Map<String, JsonValue>> {
    let bytes = URL_SAFE_NO_PAD.decode(segment).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        JsonValue::Object(object) => Some(object),
        _ => None,
    }
}

/// A JWT NumericDate, in whole seconds since the Unix epoch.
fn numeric_date(value: &JsonValue) -> Option<i64> {
    let number = value.as_number()?;
    number.as_i64().or_else(|| {
        number
            .as_f64()
            .filter(|seconds| seconds.is_finite())
            .map(|seconds| seconds.floor() as i64)
    })
}

#[cfg(test)]
mod tests {
    use super::{CloudflareAccess, parse_key_set, team_issuer};

    #[test]
    fn a_team_is_named_the_ways_cloudflare_shows_it() {
        for spelling in [
            "harmess",
            "harmess.cloudflareaccess.com",
            "https://harmess.cloudflareaccess.com",
            "https://Harmess.cloudflareaccess.com/",
            " harmess ",
        ] {
            assert_eq!(
                team_issuer(spelling).unwrap(),
                "https://harmess.cloudflareaccess.com",
                "{spelling:?}"
            );
        }
        for wrong in [
            "",
            "http://harmess.cloudflareaccess.com",
            "harmess.example.com",
            "https://harmess.cloudflareaccess.com/cdn-cgi/access/certs",
            "-harmess",
            "har mess",
            "https://evil.com#.cloudflareaccess.com",
        ] {
            assert!(team_issuer(wrong).is_err(), "{wrong:?}");
        }
        let access = CloudflareAccess::new("harmess", "  aud-tag ").unwrap();
        assert_eq!(access.audience(), "aud-tag");
        assert_eq!(
            access.certs_url(),
            "https://harmess.cloudflareaccess.com/cdn-cgi/access/certs"
        );
        assert!(CloudflareAccess::new("harmess", "").is_err());
        assert!(CloudflareAccess::new("harmess", "two words").is_err());
    }

    #[test]
    fn a_key_set_keeps_only_rs256_signing_keys() {
        let modulus = format!("AQ{}", "A".repeat(340));
        let set = serde_json::json!({
            "keys": [
                { "kid": "good", "kty": "RSA", "alg": "RS256", "use": "sig", "e": "AQAB", "n": modulus },
                { "kid": "unlabelled", "kty": "RSA", "e": "AQAB", "n": modulus },
                { "kid": "encryption", "kty": "RSA", "use": "enc", "e": "AQAB", "n": modulus },
                { "kid": "other-alg", "kty": "RSA", "alg": "RS512", "e": "AQAB", "n": modulus },
                { "kid": "elliptic", "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA" },
                { "kid": "short", "kty": "RSA", "e": "AQAB", "n": "AQAB" },
                { "kty": "RSA", "e": "AQAB", "n": modulus },
            ],
            "public_cert": { "kid": "good", "cert": "-----BEGIN CERTIFICATE-----" }
        });
        let keys = parse_key_set(&set.to_string()).unwrap();
        let mut ids = keys.keys().cloned().collect::<Vec<_>>();
        ids.sort();
        assert_eq!(ids, ["good", "unlabelled"]);

        assert!(parse_key_set("not json").is_err());
        assert!(parse_key_set("{}").is_err());
        assert!(parse_key_set(r#"{"keys": []}"#).is_err());
    }

    #[test]
    fn malformed_assertions_are_refused_before_any_key_is_fetched() {
        // No key set is reachable here, so each of these would be a
        // `KeysUnavailable` if it got as far as asking for a key.
        let access = CloudflareAccess::new("harmess", "aud")
            .unwrap()
            .with_certs_url("http://127.0.0.1:9/unreachable");
        let encode = |value: serde_json::Value| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        let payload = encode(serde_json::json!({ "email": "ada@example.com" }));
        for (assertion, reason) in [
            (String::new(), "is not a signed JSON Web Token"),
            ("a.b".to_owned(), "is not a signed JSON Web Token"),
            ("a.b.c.d".to_owned(), "is not a signed JSON Web Token"),
            ("!.b.c".to_owned(), "has an unreadable header"),
            (
                format!(
                    "{}.{payload}.",
                    encode(serde_json::json!({ "alg": "none" }))
                ),
                "is not signed with RS256",
            ),
            (
                format!(
                    "{}.{payload}.AA",
                    encode(serde_json::json!({ "alg": "HS256", "kid": "k" }))
                ),
                "is not signed with RS256",
            ),
            (
                format!(
                    "{}.{payload}.AA",
                    encode(serde_json::json!({ "alg": "RS256", "kid": "k", "crit": ["exp"] }))
                ),
                "names critical extensions cr does not understand",
            ),
            (
                format!(
                    "{}.{payload}.AA",
                    encode(serde_json::json!({ "alg": "RS256" }))
                ),
                "names no signing key",
            ),
            (
                format!(
                    "{}.{payload}.A=",
                    encode(serde_json::json!({ "alg": "RS256", "kid": "k" }))
                ),
                "has an unreadable signature",
            ),
            ("x".repeat(20_000), "is too long"),
        ] {
            match access.verify(&assertion) {
                Err(super::AssertionError::Rejected(actual)) => {
                    assert_eq!(actual, reason, "{assertion:.60}");
                }
                other => panic!("{assertion:.60}: {other:?}"),
            }
        }
    }
}
