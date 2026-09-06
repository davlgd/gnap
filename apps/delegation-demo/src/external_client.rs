//! Explicitly registered public clients and separate, manual synthetic consent.
use super::*;
use gnap_crypto::Ps256Verifier;
use gnap_types::key::{KeyObject, Proof};

pub(super) const LIFETIME: u64 = 300;
pub(super) const MAX_GRANTS: usize = 32;
pub(super) const MAX_PER_KEY: usize = 4;
const MAX_OWNERS: usize = 64;
const MAX_ATTEMPTS: usize = 120;

struct Allowed {
    key: KeyObject,
    callback: String,
}
#[derive(Default)]
pub(super) struct Registry {
    allowed: Vec<Allowed>,
    owners: HashMap<String, Owner>,
    decisions: HashMap<GrantId, Choice>,
    attempts: VecDeque<Instant>,
}
struct Owner {
    born: Instant,
    ticket: Option<String>,
    pending: Pending,
}
struct Pending {
    id: GrantId,
    handle: String,
    request: GrantRequest,
    as_nonce: Option<String>,
    deadline: u64,
}
struct Choice {
    pending: Pending,
    reference: String,
    allow: bool,
}

impl Registry {
    pub(super) fn parse(raw: Option<&str>, app_origin: &str) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            jwk: serde_json::Map<String, Value>,
            callback: String,
        }
        let Some(raw) = raw else {
            return Ok(Self::default());
        };
        if raw.len() > 65_536 {
            return Err("GNAP_EXTERNAL_CLIENTS exceeds its configuration limit".into());
        }
        let values: Vec<Value> = serde_json::from_str(raw).map_err(|_| {
            "GNAP_EXTERNAL_CLIENTS must be an array of public client configurations"
        })?;
        if values.len() > 8 {
            return Err("GNAP_EXTERNAL_CLIENTS accepts at most eight clients".into());
        }
        let mut registry = Self::default();
        for (index, value) in values.into_iter().enumerate() {
            let invalid = || format!("GNAP_EXTERNAL_CLIENTS: invalid entry at index {index}");
            let input: Input = serde_json::from_value(value).map_err(|_| invalid())?;
            let key = KeyObject {
                proof: Proof::Named(gnap_registry::KeyProofingMethod::Httpsig),
                jwk: Some(input.jwk),
                cert: None,
                cert_s256: None,
            };
            key.validate().map_err(|_| invalid())?;
            let verifier = Ps256Verifier::from_public_jwk(key.jwk.as_ref().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            if !(2048..=4096).contains(&verifier.modulus_bits())
                || !valid_callback(&input.callback, app_origin)
                || registry
                    .allowed
                    .iter()
                    .any(|entry| same_material(&entry.key, &key))
            {
                return Err(invalid());
            }
            registry.allowed.push(Allowed {
                key,
                callback: input.callback,
            });
        }
        Ok(registry)
    }

    fn key(&self, client: &Client) -> Option<&Allowed> {
        let value = client.as_value()?;
        if !value.extra.is_empty() || value.display.is_some() || value.class_id.is_some() {
            return None;
        }
        let key = value.key.as_value()?;
        if key.proof != Proof::Named(gnap_registry::KeyProofingMethod::Httpsig)
            || key.validate().is_err()
        {
            return None;
        }
        let verifier = Ps256Verifier::from_public_jwk(key.jwk.as_ref()?).ok()?;
        if !(2048..=4096).contains(&verifier.modulus_bits()) {
            return None;
        }
        self.allowed.iter().find(|entry| same_key(&entry.key, key))
    }
    pub(super) fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
        Ps256Verifier::from_public_jwk(self.key(client)?.key.jwk.as_ref()?)
            .ok()
            .map(|key| Box::new(key) as Box<dyn Verifier>)
    }
    fn profile(&self, request: &GrantRequest) -> Option<&Allowed> {
        let entry = self.key(&request.client)?;
        let tokens = request.access_token.as_ref()?;
        let interaction = request.interact.as_ref()?;
        let finish = interaction.finish.as_ref()?;
        if request.subject.is_some()
            || request.user.is_some()
            || request.existing_access_token.is_some()
            || !request.extra.is_empty()
            || tokens.cardinality != gnap_types::Cardinality::Single
            || tokens.tokens.len() != 1
            || tokens.tokens[0].access != [AccessItem::Reference(FOLDER_READ.into())]
            || tokens.tokens[0].label.is_some()
            || !tokens.tokens[0].flags.is_empty()
            || !tokens.tokens[0].extra.is_empty()
            || interaction.start.len() != 1
            || interaction.start[0].method().as_str() != "redirect"
            || !matches!(
                &interaction.start[0],
                gnap_types::polymorphic::MethodOrObject::Named(_)
            )
            || interaction.hints.is_some()
            || !interaction.extra.is_empty()
            || finish.method != gnap_registry::InteractionFinishMethod::Redirect
            || finish.uri.as_deref() != Some(entry.callback.as_str())
            || finish
                .hash_method
                .as_deref()
                .is_some_and(|method| method != "sha-256")
            || !finish.extra.is_empty()
            || finish.validate().is_err()
        {
            return None;
        }
        Some(entry)
    }
    pub(super) fn evaluate(
        &mut self,
        request: &GrantRequest,
        context: EvaluationContext<'_>,
    ) -> Decision {
        self.cleanup();
        if self.profile(request).is_none() {
            return Decision::Deny(gnap_registry::ErrorCode::RequestDenied);
        }
        match context {
            EvaluationContext::Initial => Decision::RequireInteraction,
            EvaluationContext::Modification(_) => {
                Decision::Deny(gnap_registry::ErrorCode::RequestDenied)
            }
            EvaluationContext::AfterInteraction(snapshot) => {
                if self.decisions.get(&snapshot.id).is_some_and(|choice| {
                    choice.allow
                        && choice.pending.request == *request
                        && choice.pending.as_nonce == snapshot.aggregate.record.as_nonce
                        && snapshot.aggregate.record.interact_ref.as_deref()
                            == Some(choice.reference.as_str())
                }) {
                    Decision::Approve {
                        access: vec![AccessItem::Reference(FOLDER_READ.into())],
                        subject: None,
                    }
                } else {
                    Decision::Deny(gnap_registry::ErrorCode::UserDenied)
                }
            }
        }
    }
    pub(super) fn introspect(&self, token: &gnap_as::TokenRecord) -> Option<KeyObject> {
        let entry = self.key(&token.client)?;
        let presented = token.client.as_value()?.key.as_value()?;
        (token.derivation.is_none()
            && token.token.expires_in == Some(LIFETIME)
            && token.token.access.as_deref() == Some(&[AccessItem::Reference(FOLDER_READ.into())])
            && token.token.flags.is_empty()
            && token.token.extra.is_empty()
            && token
                .token
                .key
                .as_ref()
                .is_none_or(|key| key.as_value() == Some(presented))
            && same_key(&entry.key, presented))
        .then(|| presented.clone())
    }
    fn cleanup(&mut self) {
        self.owners.retain(|_, owner| {
            owner.born.elapsed() < Duration::from_secs(LIFETIME) && now() < owner.pending.deadline
        });
        self.decisions
            .retain(|_, choice| now() < choice.pending.deadline);
        while self
            .attempts
            .front()
            .is_some_and(|at| at.elapsed() >= Duration::from_secs(60))
        {
            self.attempts.pop_front();
        }
    }
    fn admit(&mut self) -> bool {
        self.cleanup();
        if self.attempts.len() >= MAX_ATTEMPTS {
            return false;
        }
        self.attempts.push_back(Instant::now());
        true
    }
}
fn same_material(left: &KeyObject, right: &KeyObject) -> bool {
    let (Some(left), Some(right)) = (&left.jwk, &right.jwk) else {
        return false;
    };
    ["kty", "n", "e"]
        .iter()
        .all(|field| left.get(*field) == right.get(*field))
}
fn same_key(left: &KeyObject, right: &KeyObject) -> bool {
    let (Some(a), Some(b)) = (&left.jwk, &right.jwk) else {
        return false;
    };
    same_material(left, right)
        && ["alg", "kid"]
            .iter()
            .all(|field| a.get(*field) == b.get(*field))
}
pub(super) fn same_client_key(left: &Client, right: &Client) -> bool {
    left.as_value()
        .and_then(|value| value.key.as_value())
        .zip(right.as_value().and_then(|value| value.key.as_value()))
        .is_some_and(|(left, right)| same_material(left, right))
}
fn valid_callback(callback: &str, origin: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(callback) else {
        return false;
    };
    let loopback = |host: Option<&str>| {
        host.is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    };
    let local = reqwest::Url::parse(origin)
        .is_ok_and(|url| url.scheme() == "http" && loopback(url.host_str()));
    url.as_str() == callback
        && url.username().is_empty()
        && url.password().is_none()
        && !callback.split_once("://").is_some_and(|(_, rest)| {
            rest.split('/')
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/lifecycle/callback"
        && (url.scheme() == "https" || local && url.scheme() == "http" && loopback(url.host_str()))
}
fn deadline(record: &gnap_as::GrantRecord) -> Option<u64> {
    record
        .interact_expires_at?
        .checked_sub(gnap_as::server::INTERACTION_LIFETIME)?
        .checked_add(LIFETIME)
}
// Supplement typed policy where optional nulls or ignored nested fields would
// otherwise disappear during deserialization. Never rewrite a successful reply.
pub(super) fn wire_profile(request: &HttpRequest) -> bool {
    let Ok(raw) = serde_json::from_slice::<Value>(request.body.as_deref().unwrap_or_default())
    else {
        return true;
    };
    if !raw.get("client").is_some_and(Value::is_object) {
        return true;
    }
    fn only(value: &Value, names: &[&str]) -> bool {
        value
            .as_object()
            .is_some_and(|object| object.keys().all(|name| names.contains(&name.as_str())))
    }
    only(&raw, &["client", "access_token", "interact"])
        && only(&raw["client"], &["key"])
        && only(&raw["client"]["key"], &["proof", "jwk"])
        && only(
            &raw["client"]["key"]["jwk"],
            &["kty", "n", "e", "alg", "kid", "use", "key_ops"],
        )
        && only(&raw["access_token"], &["access"])
        && only(&raw["interact"], &["start", "finish"])
        && only(
            &raw["interact"]["finish"],
            &["method", "uri", "nonce", "hash_method"],
        )
}
fn owner_cookie(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers
        .get_all("cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|value| value.trim().strip_prefix("gnap_external_owner="));
    let value = values.next()?;
    (values.next().is_none()
        && value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    .then_some(value)
}
pub(super) fn is_external(app: &App, handle: &str) -> bool {
    app.storage
        .lookup(GrantSelector::Interaction(handle))
        .ok()
        .flatten()
        .is_some_and(|snapshot| {
            snapshot
                .aggregate
                .record
                .request
                .client
                .as_value()
                .is_some()
        })
}
pub(super) fn entry(app: &App, handle: &str, headers: &HeaderMap) -> Response {
    let Ok(mut decisions) = app.decisions.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let registry = &mut decisions.external;
    if !registry.admit() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Ok(Some(snapshot)) = app.storage.lookup(GrantSelector::Interaction(handle)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let record = snapshot.aggregate.record;
    let Some(deadline) = deadline(&record).filter(|deadline| now() < *deadline) else {
        return StatusCode::GONE.into_response();
    };
    if registry.profile(&record.request).is_none() || record.interaction_completed {
        return StatusCode::NOT_FOUND.into_response();
    }
    let existing = owner_cookie(headers).filter(|id| registry.owners.contains_key(*id));
    if existing.is_none() && registry.owners.len() >= MAX_OWNERS {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let (Ok(id), Ok(ticket)) = (
        existing.map_or_else(fresh_nonce, |id| Ok(id.into())),
        fresh_nonce(),
    ) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let born = registry
        .owners
        .get(&id)
        .map_or_else(Instant::now, |owner| owner.born);
    registry.owners.insert(
        id.clone(),
        Owner {
            born,
            ticket: Some(ticket.clone()),
            pending: Pending {
                id: snapshot.id,
                handle: handle.into(),
                request: record.request,
                as_nonce: record.as_nonce,
                deadline,
            },
        },
    );
    let page=format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>External GNAP client consent</title><h1>Authorize a synthetic test client?</h1><p>This external workbench client requests <code>synthetic-folder:read</code>. No real owner account or private document is involved.</p><p>Consent must be completed within five minutes of the initial grant. Reloading does not extend this limit.</p><form method=\"post\"><input type=\"hidden\" name=\"ticket\" value=\"{ticket}\"><button name=\"choice\" value=\"allow\">Allow synthetic folder read</button><button name=\"choice\" value=\"deny\">Deny</button></form></html>");
    let mut response = Html(page).into_response();
    let secure = if app.origin.starts_with("https:") {
        "; Secure"
    } else {
        ""
    };
    let age = deadline
        .saturating_sub(now())
        .min(LIFETIME.saturating_sub(born.elapsed().as_secs()));
    if let Ok(cookie)=format!("gnap_external_owner={id}; Path=/interact; HttpOnly; SameSite=Strict; Max-Age={age}{secure}").parse() { response.headers_mut().insert("set-cookie",cookie); }
    response
}

pub(super) async fn submit(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers.get_all("origin").iter().count() != 1 || !browser_origin(&headers, &app.origin) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if uri.query().is_some() || body.len() > 1024 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let handle = uri.path().trim_start_matches("/interact/").to_owned();
    let Ok(permit) = app.external_admission.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        submitted(&app, &handle, &headers, &body)
    })
    .await
    .unwrap_or_else(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())
}
fn form(headers: &HeaderMap, body: &[u8]) -> Option<(String, bool)> {
    if headers.get_all("content-type").iter().count() != 1
        || headers.get("content-type")?.to_str().ok()? != "application/x-www-form-urlencoded"
    {
        return None;
    }
    let mut url = reqwest::Url::parse("https://form.invalid/").ok()?;
    url.set_query(Some(std::str::from_utf8(body).ok()?));
    let (mut ticket, mut choice) = (None, None);
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "ticket" if ticket.is_none() => ticket = Some(value.into_owned()),
            "choice" if choice.is_none() => {
                choice = Some(match value.as_ref() {
                    "allow" => true,
                    "deny" => false,
                    _ => return None,
                })
            }
            _ => return None,
        }
    }
    Some((ticket?, choice?))
}
fn submitted(app: &App, handle: &str, headers: &HeaderMap, body: &[u8]) -> Response {
    let Ok(mut decisions) = app.decisions.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let registry = &mut decisions.external;
    registry.cleanup();
    let Some(id) = owner_cookie(headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(owner) = registry.owners.get(id) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if owner.pending.handle != handle {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Only a known, live owner addressing its displayed grant can consume
    // the shared form budget. Invalid forms and tickets still count below.
    if !registry.admit() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Some((ticket, allow)) = form(headers, body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(owner) = registry.owners.get_mut(id) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if owner.ticket.as_deref() != Some(ticket.as_str()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    owner.ticket = None;
    let pending = &owner.pending;
    if now() >= pending.deadline {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(Some(snapshot)) = app.storage.lookup(GrantSelector::Interaction(handle)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let record = &snapshot.aggregate.record;
    if snapshot.id != pending.id
        || record.request != pending.request
        || record.as_nonce != pending.as_nonce
        || record.interaction_completed
        || deadline(record) != Some(pending.deadline)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(callback) = registry
        .profile(&record.request)
        .map(|entry| entry.callback.clone())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(Finish::Redirect { uri }) = app.server.complete_interaction(handle, now()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if uri.split_once('?').map(|(base, _)| base) != Some(callback.as_str()) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Ok(finish) = InteractCallback::from_redirect(&uri) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    registry.decisions.insert(
        snapshot.id,
        Choice {
            pending: Pending {
                id: snapshot.id,
                handle: handle.into(),
                request: record.request.clone(),
                as_nonce: record.as_nonce.clone(),
                deadline: deadline(record).unwrap_or(0),
            },
            reference: finish.interact_ref,
            allow,
        },
    );
    (StatusCode::SEE_OTHER, [("location", uri)]).into_response()
}

#[cfg(test)]
mod tests;
