//! The command line's `lifecycle` scenario: one grant, from request to
//! revocation, with a key the scenario generates and the proof method it is
//! told to use.
//!
//! The scenario sends only what its plan names and what the responses it
//! accepted point to, through an [`Admission`] that the transport enforces.
//! It never follows an interaction link: it shows the link to the operator
//! and polls. Each step reports what it observed; a step the server or its
//! policy declined, such as an unknown client or a missing management API,
//! is a limit of the scenario, not a deviation from the RFC.

use crate::cli::{Finding, Outcome, Profile, Report};
use gnap_client::{
    sign_jose_request, sign_request, ClientError, HttpRequest, HttpTransport, Session, Step,
};
use gnap_crypto::jws::JwsMethod;
use gnap_crypto::{Ed25519Signer, Es256Signer, JwkSigner, Ps256Signer, Rs256Signer};
use gnap_registry::ErrorCode;
use gnap_types::access::AccessItem;
use gnap_types::token::TokenValue;
use serde_json::json;
use std::sync::Arc;

/// Most access entries a plan carries.
pub const MAX_ACCESS: usize = 8;
/// Longest access entry, in bytes.
pub const MAX_ACCESS_BYTES: usize = 512;
/// Longest wait for an operator's interaction, in seconds.
pub const MAX_WAIT: u64 = 600;
/// Longest wait for a second at which a resource read signs a fresh proof:
/// a wall clock set back further leaves the read inconclusive.
pub const FRESH_PROOF_WAIT: u64 = 5;
/// Longest wait before cleanup's first request, in seconds: cleanup takes
/// at most this wait, then the network budget of `Limits::CLEANUP`.
pub const CLEANUP_WAIT: u64 = 10;

/// The proof method the scenario's key declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    Httpsig,
    Jose(JwsMethod),
}

/// The algorithm of the scenario's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Ps256,
    Rs256,
    Es256,
    EdDsa,
}

/// What a `lifecycle` run does, validated before any network work.
#[derive(Debug, Clone)]
pub struct Plan {
    pub endpoint: String,
    pub proof: Proof,
    pub alg: Alg,
    pub access: Vec<AccessItem>,
    pub resource: Option<String>,
    pub rotate_key: bool,
    pub wait: u64,
}

impl Plan {
    /// A plan, or the reason it is refused; nothing in the reason repeats
    /// the input.
    ///
    /// # Errors
    ///
    /// Fails for an unknown method or algorithm, a pair that the method
    /// doesn't take, too many or too long access entries, an entry that
    /// isn't a GNAP access entry, or a wait beyond [`MAX_WAIT`].
    pub fn new(
        endpoint: &str,
        proof: &str,
        alg: &str,
        access: &[String],
        resource: Option<&str>,
        rotate_key: bool,
        wait: u64,
    ) -> Result<Self, &'static str> {
        let proof = match proof {
            "httpsig" => Proof::Httpsig,
            "jws" => Proof::Jose(JwsMethod::Jws),
            "jwsd" => Proof::Jose(JwsMethod::Jwsd),
            _ => return Err("the proof method is httpsig, jws, or jwsd"),
        };
        let alg = match alg {
            "PS256" => Alg::Ps256,
            "RS256" => Alg::Rs256,
            "ES256" => Alg::Es256,
            "EdDSA" => Alg::EdDsa,
            _ => return Err("the algorithm is PS256, RS256, ES256, or EdDSA"),
        };
        match (proof, alg) {
            (Proof::Httpsig, Alg::Rs256) => return Err("httpsig takes PS256, ES256, or EdDSA"),
            (Proof::Jose(_), Alg::Ps256) => return Err("jws and jwsd take RS256, ES256, or EdDSA"),
            _ => {}
        }
        if access.is_empty() || access.len() > MAX_ACCESS {
            return Err("give one to eight --access entries");
        }
        let access = access
            .iter()
            .map(|entry| {
                if entry.len() > MAX_ACCESS_BYTES {
                    return Err("an access entry is too long");
                }
                // RFC 8259 §2 — JSON whitespace may come before an object.
                if entry
                    .trim_start_matches([' ', '\t', '\n', '\r'])
                    .starts_with('{')
                {
                    // Read whole, so that serde refuses a known member given
                    // twice, such as `type`.
                    serde_json::from_str(entry)
                        .map_err(|_| "an access object isn't a GNAP access entry")
                } else {
                    // A reference, kept byte for byte.
                    serde_json::from_value(json!(entry))
                        .map_err(|_| "an access entry isn't a GNAP access entry")
                }
            })
            .collect::<Result<Vec<AccessItem>, _>>()?;
        if wait > MAX_WAIT {
            return Err("the wait is at most 600 seconds");
        }
        Ok(Self {
            endpoint: endpoint.to_owned(),
            proof,
            alg,
            access,
            resource: resource.map(ToOwned::to_owned),
            rotate_key,
            wait,
        })
    }
}

/// The scenario's time: the clock it signs with, and the waits it makes.
pub trait Clock {
    /// The current time, in seconds since the Unix epoch.
    fn now(&self) -> u64;
    /// Waits until `at`, and returns `false` if the operator interrupted.
    fn sleep_until(&self, at: u64) -> bool;
    /// Whether the operator interrupted.
    fn interrupted(&self) -> bool;
    /// Waits until `at`, even after an interruption: cleanup needs it, and
    /// its caller bounds it.
    fn pause(&self, at: u64);
    /// Seconds elapsed since an origin of the clock's choosing, which a
    /// change of the wall clock doesn't move: deadlines use it.
    fn elapsed(&self) -> u64;
}

/// What the scenario may add to the requests its transport sends.
pub trait Admission {
    /// Admits `method` to a URI a response supplied; `false` if the
    /// scenario's profile doesn't let it go there.
    fn admit(&self, method: &'static str, url: &str) -> bool;
    /// Moves to the reserved cleanup budget.
    fn clean_up(&self);
}

type Key = Arc<dyn JwkSigner + Send + Sync>;

fn generate(alg: Alg, kid: &str) -> Result<Key, gnap_crypto::ProofError> {
    Ok(match alg {
        Alg::Ps256 => Arc::new(Ps256Signer::generate(2048, kid)?),
        Alg::Rs256 => Arc::new(Rs256Signer::generate(2048, kid)?),
        Alg::Es256 => Arc::new(Es256Signer::generate(kid)?),
        Alg::EdDsa => Arc::new(Ed25519Signer::generate(kid)?),
    })
}

const fn method_name(proof: Proof) -> &'static str {
    match proof {
        Proof::Httpsig => "httpsig",
        Proof::Jose(method) => method.name(),
    }
}

const fn alg_name(alg: Alg) -> &'static str {
    match alg {
        Alg::Ps256 => "PS256",
        Alg::Rs256 => "RS256",
        Alg::Es256 => "ES256",
        Alg::EdDsa => "EdDSA",
    }
}

impl Plan {
    /// What the report says the scenario was asked to run.
    #[must_use]
    pub fn profile(&self) -> Profile {
        Profile {
            proof: method_name(self.proof),
            alg: alg_name(self.alg),
            access: self.access.len(),
            resource: self.resource.is_some(),
            rotate_key: self.rotate_key,
            wait: self.wait,
        }
    }
}

/// The scenario's steps, in order: a step it didn't reach is reported as
/// skipped, so that every run lists the same checks.
const STEPS: [&str; 8] = [
    "grant-request",
    "token-issued",
    "resource-access",
    "token-rotation",
    "key-rotation",
    "resource-access-before-revocation",
    "token-revocation",
    "revoked-token-refused",
];

const RFC: &str = "https://www.rfc-editor.org/rfc/rfc9635.html";
const GRANT: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-2";
const CONTINUATION: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-5";
const ROTATION: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-6.1";
const KEY_ROTATION: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-6.1.1";
const REVOCATION: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-6.2";
const GRANT_REVOCATION: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-5.4";
const PRESENTATION: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-7.2";

/// Reports each step the scenario didn't reach as skipped, so that every run
/// lists the same checks.
fn skip_unreached(findings: &mut Vec<Finding>) {
    for id in STEPS {
        if findings.iter().all(|finding| finding.id != id) {
            findings.push(finding(
                id,
                Outcome::Skipped,
                RFC,
                "The scenario ended before this step, as an earlier finding explains.",
            ));
        }
    }
}

const fn finding(
    id: &'static str,
    outcome: Outcome,
    reference: &'static str,
    detail: &'static str,
) -> Finding {
    Finding {
        id,
        outcome,
        reference,
        detail,
    }
}

/// The outcome of a client operation the AS may decline: its refusal is a
/// limit of the scenario, a response the client must refuse is a deviation.
fn judged(result: &Result<impl Sized, ClientError>) -> Outcome {
    match result {
        Ok(_) => Outcome::Passed,
        Err(ClientError::Protocol(_) | ClientError::Parse(_)) => Outcome::Failed,
        Err(_) => Outcome::Inconclusive,
    }
}

/// An interaction link fit to show an operator: HTTPS, or HTTP loopback in
/// a local run, without control characters, and bounded.
fn showable(link: &str, local: bool) -> bool {
    let Ok(url) = reqwest::Url::parse(link) else {
        return false;
    };
    let loopback = local && url.scheme() == "http" && crate::net::loopback(&url);
    link.len() <= 2048
        && !link.chars().any(char::is_control)
        && url.username().is_empty()
        && url.password().is_none()
        && (url.scheme() == "https" || loopback)
}

/// A token the scenario holds: its value, its key, and when it expires.
type Held = (TokenValue, Key, Option<u64>);

/// Shows the operator the interaction a pending answer asks for, unless it
/// is the one already shown; returns the link now shown.
fn show_interaction(
    response: &gnap_types::message::GrantResponse,
    shown: Option<String>,
    local: bool,
    notify: &dyn Fn(&str),
) -> Option<String> {
    let Some(interact) = response.interact.as_ref() else {
        return shown;
    };
    let link = interact
        .redirect
        .as_deref()
        .filter(|link| showable(link, local));
    match link {
        Some(link) if shown.as_deref() == Some(link) => {}
        Some(link) => notify(&format!(
            "Open this link to approve the scenario's request, then wait: {link}"
        )),
        None => notify("The AS asked for an interaction this scenario can't show; it polls."),
    }
    link.map(str::to_owned).or(shown)
}

/// What a resource read observed.
enum Read {
    NotRequested,
    Unavailable,
    Status(u16),
}

/// The state the scenario keeps besides the session.
struct Run<'a, T: HttpTransport> {
    session: Session<&'a T, Key>,
    plan: &'a Plan,
    admission: &'a dyn Admission,
    clock: &'a dyn Clock,
    findings: Vec<Finding>,
    /// The token the scenario presents, and the key that presents it.
    token: Option<Held>,
    /// When the last continuation answer arrived, which its wait counts from.
    continued_at: u64,
    /// Whether the AS answered the grant request, so that it may hold state
    /// the scenario has to clean up.
    obtained: bool,
    current: Key,
    /// The second the last resource proof was signed at: the next one has
    /// to be later, so that it never repeats a proof's replay identity.
    last_read: std::cell::Cell<u64>,
    /// The second the scenario's own token revocation was signed at, which
    /// a retry at cleanup has to come after.
    last_revocation: std::cell::Cell<Option<u64>>,
}

impl<T: HttpTransport> Run<'_, T> {
    fn push(
        &mut self,
        id: &'static str,
        outcome: Outcome,
        reference: &'static str,
        detail: &'static str,
    ) {
        self.findings.push(finding(id, outcome, reference, detail));
    }

    /// Admits the exact continuation and management URIs the session holds.
    fn admit_held(&mut self) {
        let now = self.clock.now();
        let mut uris = Vec::new();
        if let Some(continuation) = self.session.continuation() {
            uris.push(continuation.uri.clone());
        }
        for token in self.session.usable_tokens(now).unwrap_or_default() {
            if let Some(manage) = &token.manage {
                uris.push(manage.uri.clone());
            }
        }
        for uri in uris {
            let admitted = ["POST", "DELETE"]
                .into_iter()
                .all(|method| self.admission.admit(method, &uri));
            if !admitted {
                self.push(
                    "destination-profile",
                    Outcome::Inconclusive,
                    CONTINUATION,
                    "The AS named a continuation or management URI outside this scenario's \
                     profile: another origin, or a form the bounded transport refuses. This \
                     is a limit of the command line, not a deviation from the RFC.",
                );
            }
        }
    }

    /// Remembers the token the session holds, to present it and to check it
    /// after revocation.
    fn hold_token(&mut self, issued_at: u64) {
        let now = self.clock.now();
        self.token = self
            .session
            .usable_tokens(now)
            .and_then(|tokens| {
                tokens
                    .first()
                    .map(|token| (token.value.clone(), token.expires_in))
            })
            .map(|(value, expires_in)| {
                (
                    value,
                    Arc::clone(&self.current),
                    expires_in.map(|seconds| issued_at.saturating_add(seconds)),
                )
            });
    }

    /// A resource request proven with `key`, once the clock moved past
    /// `after`, so that the proof is fresh.
    fn present(&self, transport: &T, (token, key, expires_at): &Held, after: u64) -> Read {
        let Some(resource) = self.plan.resource.as_ref() else {
            return Read::NotRequested;
        };
        let after = after.max(self.last_read.get());
        let fresh = after.saturating_add(1);
        if fresh.saturating_sub(self.clock.now()) > FRESH_PROOF_WAIT
            || !self.clock.sleep_until(fresh)
        {
            return Read::Unavailable;
        }
        let now = self.clock.now();
        // A wall clock set back would repeat a second the resource saw, and
        // the wait may outlast the token.
        if now <= after || expires_at.is_some_and(|at| now >= at) {
            return Read::Unavailable;
        }
        self.last_read.set(now);
        let request = HttpRequest::new("GET", resource.as_str());
        let signed = match self.plan.proof {
            Proof::Httpsig => sign_request(request, key.as_ref(), Some(token), now),
            Proof::Jose(method) => {
                sign_jose_request(request, method, key.as_ref(), Some(token), now)
            }
        };
        signed
            .ok()
            .and_then(|signed| transport.send(signed).ok())
            .map_or(Read::Unavailable, |response| Read::Status(response.status))
    }

    /// Reads the resource with `token` and `key`, expecting it accepted, and
    /// records the finding; returns whether it was accepted.
    fn witness(&mut self, transport: &T, id: &'static str, held: &Held) -> bool {
        let read = self.present(transport, held, self.clock.now());
        let (outcome, accepted) = match read {
            Read::NotRequested => (Outcome::Skipped, false),
            Read::Unavailable => (Outcome::Inconclusive, false),
            Read::Status(status) if (200..300).contains(&status) => (Outcome::Passed, true),
            Read::Status(_) => (Outcome::Inconclusive, false),
        };
        self.push(
            id,
            outcome,
            PRESENTATION,
            "The resource answered 2xx to the token, proven with its key. Another status may \
             come from the resource's own rights, and a request that couldn't be signed or \
             sent decides nothing: both leave the check inconclusive. Without --resource, it \
             is skipped.",
        );
        accepted
    }
}

/// Runs the `lifecycle` scenario and reports what each step observed.
///
/// `transport` enforces `admission`; `notify` shows the operator what it
/// has to do, and never receives a credential.
#[allow(
    clippy::too_many_lines,
    reason = "The scenario reads as one sequence of steps, each with its finding"
)]
pub fn lifecycle<T: HttpTransport>(
    transport: &T,
    admission: &dyn Admission,
    clock: &dyn Clock,
    notify: &dyn Fn(&str),
    plan: &Plan,
    local: bool,
) -> Report {
    let started = clock.now();
    let kid = format!(
        "gnap-conformance-{}",
        gnap_crypto::httpsig::fresh_nonce().unwrap_or_default()
    );
    let Ok(key) = generate(plan.alg, &kid) else {
        let mut findings = vec![finding(
            "key-generation",
            Outcome::Inconclusive,
            RFC,
            "The scenario couldn't generate its key: the system's random source is unavailable.",
        )];
        skip_unreached(&mut findings);
        return Report::scenario(&plan.endpoint, started, plan.profile(), findings);
    };
    let mut run = Run {
        session: Session::new(transport, Arc::clone(&key), plan.endpoint.as_str()),
        plan,
        admission,
        clock,
        findings: Vec::new(),
        token: None,
        continued_at: started,
        obtained: false,
        current: Arc::clone(&key),
        last_read: std::cell::Cell::new(0),
        last_revocation: std::cell::Cell::new(None),
    };

    if run.clock.interrupted() {
        return finish(run, transport, started);
    }
    // §9 — a key change is tried only when the AS announces it, or when the
    // operator asks for it regardless.
    let announces_rotation = plan.rotate_key.then(|| {
        transport
            .send(HttpRequest::new("OPTIONS", plan.endpoint.as_str()))
            .ok()
            .and_then(|response| serde_json::from_slice::<serde_json::Value>(&response.body).ok())
            .and_then(|document| document["key_rotation_supported"].as_bool())
    });

    // §2 — the grant request, offering a redirect start and no finish.
    let jwk = key.public_jwk().unwrap_or_default();
    let request = serde_json::from_value(json!({
        "client": {"key": {"proof": method_name(plan.proof), "jwk": jwk}},
        "access_token": {"access": plan.access},
        "interact": {"start": ["redirect"]}
    }));
    let Ok(request) = request else {
        run.push(
            "grant-request",
            Outcome::Inconclusive,
            GRANT,
            "The scenario couldn't build its grant request.",
        );
        return finish(run, transport, started);
    };
    if run.clock.interrupted() {
        return finish(run, transport, started);
    }
    let issued_at = clock.now();
    let result = run.session.start(&request, issued_at);
    run.continued_at = clock.now();
    run.obtained = result.is_ok();
    run.admit_held();
    let mut approved_at = clock.now();
    let mut issued = false;
    let mut shown = None;
    let mut approved = match &result {
        Ok(Step::Approved(response)) => {
            issued = response.access_token.is_some();
            true
        }
        Ok(Step::Pending(response)) => {
            shown = show_interaction(response, None, local, notify);
            false
        }
        _ => false,
    };
    // §3.6 — an error with a continuation lets the scenario poll, but the
    // request itself wasn't granted.
    let answered = if matches!(result, Ok(Step::Recoverable(_))) {
        Outcome::Inconclusive
    } else {
        judged(&result)
    };
    run.push(
        "grant-request",
        answered,
        GRANT,
        "The AS answered the grant request with an approval or a pending grant the client \
         accepts. A GNAP error, such as an unknown client, is the AS's policy and leaves the \
         scenario inconclusive, even when it comes with a continuation the scenario polls.",
    );
    if result.is_err() {
        return finish(run, transport, started);
    }

    // §5.2 — poll until approved, denied, or out of time.
    let deadline = clock.elapsed().saturating_add(plan.wait);
    while !approved {
        let Some(wait) = run
            .session
            .continuation()
            .map(gnap_types::message::Continue::effective_wait)
        else {
            run.push(
                "interaction-outcome",
                Outcome::Inconclusive,
                CONTINUATION,
                "The grant is pending without a continuation the scenario can poll.",
            );
            return finish(run, transport, started);
        };
        if clock.elapsed().saturating_add(wait.max(1)) > deadline {
            run.push(
                "interaction-outcome",
                Outcome::Inconclusive,
                CONTINUATION,
                "The interaction wasn't completed within the scenario's wait.",
            );
            return finish(run, transport, started);
        }
        if !clock.sleep_until(clock.now().saturating_add(wait.max(1))) {
            return finish(run, transport, started);
        }
        let polled = run.session.continue_grant(clock.now());
        run.continued_at = clock.now();
        run.admit_held();
        match polled {
            Ok(Step::Approved(response)) => {
                issued = response.access_token.is_some();
                approved = true;
                approved_at = clock.now();
            }
            // A poll can bring the interaction, as after a recoverable first
            // answer: its link is shown once.
            Ok(Step::Pending(response)) => {
                shown = show_interaction(&response, shown, local, notify);
            }
            Ok(Step::Recoverable(_)) => {
                // §3.6 — such as too_fast, though the scenario waited as
                // asked: the scenario follows the new continuation, and the
                // interaction's outcome can't be read as clean.
                if run.findings.iter().all(|f| f.id != "continuation-error") {
                    run.push(
                        "continuation-error",
                        Outcome::Inconclusive,
                        CONTINUATION,
                        "The AS answered a poll with a GNAP error and a new continuation, \
                         after the scenario waited as asked; it followed the new continuation.",
                    );
                }
            }
            Err(ClientError::Server(error)) if error.code == ErrorCode::UserDenied => {
                run.push(
                    "interaction-outcome",
                    Outcome::NotApplicable,
                    CONTINUATION,
                    "The resource owner denied the request (user_denied): a result of the \
                     scenario, not a deviation. The later steps don't apply.",
                );
                return finish(run, transport, started);
            }
            Err(ClientError::Server(_)) => {
                run.push(
                    "interaction-outcome",
                    Outcome::Inconclusive,
                    CONTINUATION,
                    "The AS answered the continuation with a GNAP error other than \
                     user_denied, which doesn't show how the interaction ended.",
                );
                return finish(run, transport, started);
            }
            Err(error) => {
                let outcome = judged(&Err::<(), _>(error));
                run.push(
                    "interaction-outcome",
                    outcome,
                    CONTINUATION,
                    "The continuation answer was refused by the client, or the exchange failed.",
                );
                return finish(run, transport, started);
            }
        }
    }
    run.hold_token(approved_at);
    let Some(held) = run.token.clone() else {
        if issued {
            run.push(
                "token-issued",
                Outcome::Inconclusive,
                GRANT,
                "The approved grant carries an access token that expired before the scenario \
                 could use it.",
            );
        } else {
            run.push(
                "token-issued",
                Outcome::NotApplicable,
                GRANT,
                "The approved grant carries no access token the scenario can use.",
            );
        }
        return finish(run, transport, started);
    };
    run.push(
        "token-issued",
        Outcome::Passed,
        GRANT,
        "The approved grant carries an access token.",
    );

    if run.clock.interrupted() {
        return finish(run, transport, started);
    }
    // §7.2 — the resource accepts the token, proven with its key.
    run.witness(transport, "resource-access", &held);

    if run.clock.interrupted() {
        return finish(run, transport, started);
    }
    // §6.1 — the token's value changes; the rights don't.
    let rotated = run.session.rotate_token(None, clock.now());
    run.push(
        "token-rotation",
        judged(&rotated),
        ROTATION,
        "The AS rotated the token's value, with the same rights, through its management API. \
         Without a management API, or after a refusal, the check is inconclusive.",
    );
    run.admit_held();
    // A failed rotation keeps the token and the lifetime it had.
    if rotated.is_ok() {
        run.hold_token(clock.now());
    }

    if run.clock.interrupted() {
        return finish(run, transport, started);
    }
    // §6.1.1 — the token's key changes, when asked for.
    if !plan.rotate_key {
        run.push(
            "key-rotation",
            Outcome::Skipped,
            KEY_ROTATION,
            "The plan didn't ask for a key change: pass --rotate-key to try it.",
        );
    } else {
        if announces_rotation.flatten() == Some(false) || announces_rotation.flatten().is_none() {
            run.push(
                "key-rotation",
                Outcome::Skipped,
                KEY_ROTATION,
                "The AS doesn't announce key rotation in its discovery document, so the \
                 scenario didn't try it.",
            );
        } else if let Ok(replacement) = generate(plan.alg, &format!("{kid}-next")) {
            // Generating an RSA key takes long enough for an interrupt.
            if run.clock.interrupted() {
                return finish(run, transport, started);
            }
            let presented = serde_json::from_value(json!({
                "proof": method_name(plan.proof),
                "jwk": replacement.public_jwk().unwrap_or_default()
            }));
            let changed = presented.map_or_else(
                |_| Err(ClientError::Usage("the new key".into())),
                |presented| {
                    run.session.rotate_key(
                        None,
                        Arc::clone(&replacement) as gnap_client::SharedSigner,
                        &presented,
                        clock.now(),
                    )
                },
            );
            let adopted = changed.is_ok();
            if adopted {
                run.current = replacement;
            }
            run.push(
                "key-rotation",
                judged(&changed),
                KEY_ROTATION,
                "The AS bound the token to a new key of the same method and algorithm, proven \
                 by both keys. A refusal leaves the check inconclusive.",
            );
            run.admit_held();
            if adopted {
                run.hold_token(clock.now());
            }
        } else {
            run.push(
                "key-rotation",
                Outcome::Inconclusive,
                KEY_ROTATION,
                "The scenario couldn't generate the new key: the system's random source is \
                 unavailable.",
            );
        }
    }

    if run.clock.interrupted() {
        return finish(run, transport, started);
    }
    // §6.2 — the token is revoked, and the resource refuses it. The last
    // token, with the last key, has to be accepted first, or a refusal after
    // revocation could come from anything else.
    let last = run.token.clone();
    if last.is_none() && plan.resource.is_some() {
        // As when a rotation returns a token already past its lifetime.
        run.push(
            "resource-access-before-revocation",
            Outcome::Inconclusive,
            PRESENTATION,
            "The scenario no longer holds a usable token, so it couldn't read the resource.",
        );
        run.push(
            "revoked-token-refused",
            Outcome::Inconclusive,
            REVOCATION,
            "The scenario no longer holds a usable token, so it couldn't check its refusal.",
        );
    }
    let accepted = last
        .as_ref()
        .is_some_and(|held| run.witness(transport, "resource-access-before-revocation", held));
    if run.clock.interrupted() {
        return finish(run, transport, started);
    }
    let revoking_at = clock.now();
    run.last_revocation.set(Some(revoking_at));
    let revoked = run.session.revoke_token(None, revoking_at);
    run.push(
        "token-revocation",
        judged(&revoked),
        REVOCATION,
        "The AS revoked the token through its management API with 204. A refusal leaves the \
         check inconclusive.",
    );
    if let (Ok(()), Some(held)) = (&revoked, last) {
        let read = run.present(transport, &held, clock.now());
        let expired = held.2.is_some_and(|at| at <= clock.now());
        let outcome = match read {
            Read::NotRequested => Outcome::Skipped,
            _ if !accepted || expired => Outcome::Inconclusive,
            Read::Status(401 | 403) => Outcome::Passed,
            Read::Status(200..=299) => Outcome::Failed,
            Read::Status(_) | Read::Unavailable => Outcome::Inconclusive,
        };
        run.push(
            "revoked-token-refused",
            outcome,
            REVOCATION,
            "The resource refused the revoked token with 401 or 403, to a fresh proof that was \
             never presented before, after it accepted the same token and key. Without that \
             acceptance, or with a token already past its lifetime, the check is inconclusive: \
             something else could explain the refusal.",
        );
    }
    finish(run, transport, started)
}

/// Revokes what the scenario still holds, with the reserved budget: the
/// token, if the scenario didn't revoke it, then the grant. Builds the report.
fn finish<T: HttpTransport>(mut run: Run<'_, T>, _: &T, started: u64) -> Report {
    run.admission.clean_up();
    if run.clock.interrupted() {
        run.push(
            "operator-interrupt",
            Outcome::Inconclusive,
            RFC,
            "The operator interrupted the scenario; its findings so far are kept.",
        );
    }
    skip_unreached(&mut run.findings);
    // A revoked token leaves the session, so a managed token it still holds
    // is one the scenario didn't revoke.
    let now = run.clock.now();
    let managed = run
        .session
        .usable_tokens(now)
        .and_then(|tokens| tokens.first().map(|token| token.manage.is_some()))
        .unwrap_or(false);
    let continuation = run
        .session
        .continuation()
        .map(gnap_types::message::Continue::effective_wait);
    if managed || continuation.is_some() {
        // Cleanup waits before its first request, for at most CLEANUP_WAIT,
        // so that the wait never spends its network budget: until a second
        // no earlier request was signed at, so that a retried revocation
        // has its own replay identity, and (§5) until the continuation's
        // wait has passed.
        let fresh = now
            .max(run.last_revocation.get().unwrap_or(0))
            .saturating_add(1);
        let ready = continuation.map_or(fresh, |wait| {
            fresh.max(run.continued_at.saturating_add(wait))
        });
        run.clock.pause(ready.min(now.saturating_add(CLEANUP_WAIT)));
    }
    // A retry signed at the second of the revocation it retries would repeat
    // its proof: when the wall clock went back too far to wait it out, the
    // scenario doesn't send it.
    let retry_at = run.clock.now();
    let repeats = run.last_revocation.get().is_some_and(|at| retry_at <= at);
    if managed && repeats {
        run.push(
            "token-cleanup",
            Outcome::Inconclusive,
            REVOCATION,
            "The scenario couldn't sign a new proof to revoke the token it still held, since the \
             wall clock went back past its revocation: the token may remain live.",
        );
    } else if managed {
        let revoked = run.session.revoke_token(None, retry_at);
        run.push(
            "token-cleanup",
            judged(&revoked),
            REVOCATION,
            "The scenario revoked the token it still held through its management API with 204, \
             within the budget reserved for cleanup.",
        );
    }
    if run.session.continuation().is_some() {
        let revoked = run.session.revoke_grant(run.clock.now());
        run.push(
            "grant-revocation",
            judged(&revoked),
            GRANT_REVOCATION,
            "The scenario revoked its grant through the continuation API with 204, within a \
             budget reserved for cleanup. If an answer was lost, the grant may remain at the AS.",
        );
    } else if run.obtained {
        run.push(
            "grant-revocation",
            Outcome::NotApplicable,
            GRANT_REVOCATION,
            "The AS gave no continuation API for the grant, which RFC 9635 allows, so the \
             scenario had no grant to revoke.",
        );
    }
    Report::scenario(
        &run.plan.endpoint,
        started,
        run.plan.profile(),
        run.findings,
    )
}

#[cfg(test)]
mod tests {
    use super::showable;

    #[test]
    fn only_a_plain_https_link_is_shown_to_the_operator() {
        assert!(showable("https://as.example/interact/abc?x=1", false));
        assert!(showable("http://localhost:8080/interact/abc", true));
        for link in [
            "http://as.example/interact",
            "http://localhost:8080/interact",
            "https://user:secret@as.example/interact",
            "https://as.example/interact\u{1b}[31m",
            "javascript:alert(1)",
            "not a link",
        ] {
            assert!(!showable(link, false), "{link}");
        }
        assert!(!showable(
            &format!("https://as.example/{}", "a".repeat(2048)),
            false
        ));
    }
}
