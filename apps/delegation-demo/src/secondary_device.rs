//! A separate browser locates a synthetic grant and explicitly decides it.
//! This is a no-finish polling consumer, not authenticated owner identity or C2.
use super::*;

const OWNER_LIFETIME: Duration = Duration::from_secs(600);
const MAX_OWNERS: usize = 64;
const SESSION_ATTEMPTS: usize = 5;
const GLOBAL_ATTEMPTS: usize = 60;
const INVALID: &str = "The code or request is unavailable. Check the first screen and try again.";

#[derive(Default)]
pub(super) struct Entries {
    owners: HashMap<String, Owner>,
    attempts: VecDeque<Instant>,
}
struct Owner {
    born: Instant,
    attempts: usize,
    ticket: String,
    pending: Option<Pending>,
}
struct Pending {
    id: GrantId,
    handle: String,
    request: GrantRequest,
    as_nonce: Option<String>,
}

impl Entries {
    fn cleanup(&mut self, at: Instant) {
        self.owners
            .retain(|_, owner| at.duration_since(owner.born) < OWNER_LIFETIME);
        while self
            .attempts
            .front()
            .is_some_and(|t| at.duration_since(*t) >= Duration::from_secs(60))
        {
            self.attempts.pop_front();
        }
    }
    fn admit(&mut self, at: Instant) -> bool {
        self.cleanup(at);
        if self.attempts.len() >= GLOBAL_ATTEMPTS {
            return false;
        }
        self.attempts.push_back(at);
        true
    }
}

fn owner_cookie(headers: &HeaderMap) -> Option<&str> {
    let mut found = headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().strip_prefix("gnap_owner="));
    let id = found.next()?;
    (found.next().is_none()
        && id.len() == 22
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then_some(id)
}

fn error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({"error":message}))).into_response()
}

pub(super) async fn entry(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    // A code never belongs in a URL; do not reflect or redirect query input.
    if uri.query().is_some() {
        return error(
            StatusCode::BAD_REQUEST,
            "Enter the code in the form, not in the address.",
        );
    }
    let Ok(mut entries) = app.code_entries.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    entries.cleanup(Instant::now());
    let existing = owner_cookie(&headers).filter(|id| entries.owners.contains_key(*id));
    let id = if let Some(id) = existing {
        id.to_owned()
    } else {
        if entries.owners.len() >= MAX_OWNERS {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "All owner sessions are in use. Retry later.",
            );
        }
        let (Ok(id), Ok(ticket)) = (fresh_nonce(), fresh_nonce()) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        entries.owners.insert(
            id.clone(),
            Owner {
                born: Instant::now(),
                attempts: 0,
                ticket,
                pending: None,
            },
        );
        id
    };
    let owner = &entries.owners[&id];
    let page = include_str!("../static/code.html")
        .replace("__TICKET__", &owner.ticket)
        .replace(
            "__REMAINING__",
            &SESSION_ATTEMPTS.saturating_sub(owner.attempts).to_string(),
        );
    let mut response = Html(page).into_response();
    // Reloading does not extend the server-side deadline or reset attempts.
    let age = OWNER_LIFETIME
        .saturating_sub(owner.born.elapsed())
        .as_secs();
    let secure = if app.origin.starts_with("https:") {
        "; Secure"
    } else {
        ""
    };
    response.headers_mut().insert(
        "set-cookie",
        format!("gnap_owner={id}; Path=/code; HttpOnly; SameSite=Strict; Max-Age={age}{secure}")
            .parse()
            .unwrap(),
    );
    response
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    ticket: String,
    code: Option<String>,
    choice: Option<String>,
}

pub(super) async fn submit(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !browser_origin(&headers, &app.origin) {
        return error(StatusCode::FORBIDDEN, "Origin must match APP_ORIGIN");
    }
    if uri.query().is_some() {
        return error(StatusCode::BAD_REQUEST, INVALID);
    }
    // The form body is bounded before this task. No crypto or network operation
    // runs while holding entry state; the SDK completion is a local CAS only.
    let result =
        tokio::task::spawn_blocking(move || submitted(&app, uri.path(), &headers, &body)).await;
    result.unwrap_or_else(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())
}

fn submitted(app: &App, path: &str, headers: &HeaderMap, body: &[u8]) -> Response {
    let Ok(mut entries) = app.code_entries.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let at = Instant::now();
    entries.cleanup(at);
    let Some((id, attempts)) = owner_cookie(headers)
        .and_then(|id| entries.owners.get(id).map(|owner| (id, owner.attempts)))
    else {
        return error(
            StatusCode::UNAUTHORIZED,
            "Open the code-entry page to obtain an owner session.",
        );
    };
    if attempts >= SESSION_ATTEMPTS {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "This owner's five attempts are exhausted. Wait for the session to expire.",
        );
    }
    if !entries.admit(at) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "60")],
            Json(json!({"error":"The shared attempt budget is exhausted. Wait one minute."})),
        )
            .into_response();
    }
    let owner = entries.owners.get_mut(id).expect("live admitted owner");
    owner.attempts += 1;
    let remaining = SESSION_ATTEMPTS - owner.attempts;
    let Ok(input) = serde_json::from_slice::<Submission>(body) else {
        owner.pending = None;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":INVALID, "remaining":remaining})),
        )
            .into_response();
    };
    if headers.get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json")
        || input.ticket != owner.ticket
    {
        return error(
            StatusCode::FORBIDDEN,
            "Invalid form ticket or content type. Reload the page.",
        );
    }
    let Ok(ticket) = fresh_nonce() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    owner.ticket = ticket.clone();
    let invalid = || {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":INVALID, "remaining":remaining, "ticket":ticket})),
        )
            .into_response()
    };
    if path == "/code/lookup" {
        owner.pending = None;
        let Some(code) = input.code.filter(|_| input.choice.is_none()) else {
            return invalid();
        };
        let Ok(handle) = app.server.resolve_user_code(&code, now()) else {
            return invalid();
        };
        let Ok(Some(snapshot)) = app.storage.lookup(GrantSelector::Interaction(&handle)) else {
            return invalid();
        };
        let record = snapshot.aggregate.record;
        // This entry page deliberately serves only polling requests. It never
        // sends a second browser to the first browser's callback endpoint.
        if record
            .request
            .interact
            .as_ref()
            .is_none_or(|i| i.finish.is_some())
        {
            return invalid();
        }
        let Some(slots) =
            multiple::requested_slots(&record.request, &app.rs_registration.resources)
        else {
            return invalid();
        };
        let rights = multiple::slots_view(&slots);
        owner.pending = Some(Pending {
            id: snapshot.id,
            handle,
            request: record.request,
            as_nonce: record.as_nonce,
        });
        Json(json!({"rights":rights, "ticket":owner.ticket, "remaining":remaining})).into_response()
    } else {
        let choice = match (input.code, input.choice.as_deref()) {
            (None, Some("allow")) => multiple::Choice::All,
            (None, Some("deny")) => multiple::Choice::Denied,
            _ => return invalid(),
        };
        let Some(pending) = owner.pending.take() else {
            return invalid();
        };
        if complete(app, pending, choice).is_err() {
            return invalid();
        }
        Json(json!({"complete":true, "remaining":remaining, "ticket":owner.ticket})).into_response()
    }
}

fn complete(app: &App, pending: Pending, allowed: multiple::Choice) -> Result<(), ()> {
    let snapshot = app
        .storage
        .lookup(GrantSelector::Interaction(&pending.handle))
        .map_err(|_| ())?
        .ok_or(())?;
    let record = &snapshot.aggregate.record;
    if snapshot.id != pending.id
        || record.request != pending.request
        || record.as_nonce != pending.as_nonce
        || record.interaction_completed
        || record.interact_expires_at.is_none_or(|at| now() >= at)
    {
        return Err(());
    }
    // Order: owner entries -> decisions -> storage, never the reverse. A poll
    // can take a snapshot meanwhile, but its policy cannot observe completion
    // without the corresponding choice. A CAS failure inserts no decision.
    let mut choices = app.decisions.lock().map_err(|_| ())?;
    if !matches!(
        app.server.complete_interaction(&pending.handle, now()),
        Ok(Finish::SendTheUserBack)
    ) {
        return Err(());
    }
    #[cfg(test)]
    if let Some(pause) = app.code_completion_hook.as_deref() {
        pause();
    }
    choices.grants.insert(
        snapshot.id,
        Consent {
            request: pending.request,
            interaction_reference: None,
            as_nonce: pending.as_nonce,
            allowed,
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests;
