//! A single callback attempt to this application's own registered endpoint.
//! Notification delivery never rolls back consent or enables AS polling.
use super::*;

pub(super) mod transport;

const CALLBACK_WINDOW: Duration = Duration::from_secs(300);
const MAX_CALLBACK_BODY: usize = 1024;
const CALLBACKS_PER_MINUTE: usize = 60;

#[derive(Default)]
pub(super) struct Registry {
    slots: HashMap<String, Slot>,
    attempts: VecDeque<Instant>,
}

struct Slot {
    client: String,
    grant: Option<GrantId>,
    registration: Registration,
    outbox: Option<Notification>,
}

/// Private callback correlation, never the browser cookie or a public view.
#[derive(Clone)]
pub(super) struct Registration {
    id: String,
    pub uri: String,
    status: Arc<Mutex<Status>>,
}

struct Status {
    created: Instant,
    received: bool,
    queued: bool,
    delivery: Option<transport::Delivery>,
}

struct Notification {
    uri: String,
    body: Vec<u8>,
    status: Arc<Mutex<Status>>,
}

impl Registry {
    pub fn register(&mut self, client: &str, origin: &str) -> Result<Registration, String> {
        self.slots.retain(|_, slot| {
            slot.registration.status.lock().unwrap().created.elapsed() < SESSION_LIFETIME
        });
        if self.slots.len() >= MAX_SESSIONS || self.slots.values().any(|slot| slot.client == client)
        {
            return Err("Push callback capacity unavailable".into());
        }
        let id = fresh_nonce().map_err(|_| "Push callback randomness unavailable")?;
        if self.slots.contains_key(&id) {
            return Err("Push callback registration collision".into());
        }
        let registration = Registration {
            uri: format!("{origin}/push-callback/{id}"),
            id: id.clone(),
            status: Arc::new(Mutex::new(Status {
                created: Instant::now(),
                received: false,
                queued: false,
                delivery: None,
            })),
        };
        self.slots.insert(
            id,
            Slot {
                client: client.into(),
                grant: None,
                registration: registration.clone(),
                outbox: None,
            },
        );
        Ok(registration)
    }

    pub fn bind(&mut self, registration: &Registration, grant: GrantId) -> Result<(), String> {
        let slot = self
            .slots
            .get_mut(&registration.id)
            .ok_or("Push registration unavailable")?;
        if slot.grant.is_some() {
            return Err("Push registration already bound".into());
        }
        slot.grant = Some(grant);
        Ok(())
    }

    pub fn remove_client(&mut self, client: &str) {
        self.slots.retain(|_, slot| slot.client != client);
    }

    fn admit(&mut self, at: Instant) -> bool {
        while self
            .attempts
            .front()
            .is_some_and(|first| at.duration_since(*first) >= Duration::from_secs(60))
        {
            self.attempts.pop_front();
        }
        if self.attempts.len() >= CALLBACKS_PER_MINUTE {
            return false;
        }
        self.attempts.push_back(at);
        true
    }
}

pub(super) fn is_push(request: &GrantRequest) -> bool {
    request
        .interact
        .as_ref()
        .and_then(|i| i.finish.as_ref())
        .is_some_and(|f| f.method == gnap_registry::InteractionFinishMethod::Push)
}

pub(super) fn acceptable_request(request: &GrantRequest, registry: &Registry) -> bool {
    if !is_push(request) {
        return true;
    }
    let Some(interact) = &request.interact else {
        return false;
    };
    let Some(client) = request.client.as_reference() else {
        return false;
    };
    request.subject.is_none()
        && request
            .access_token
            .as_ref()
            .is_some_and(|t| t.cardinality == gnap_types::token::Cardinality::Single)
        && interact.start.len() == 1
        && interact.start[0].method().as_str() == "redirect"
        && registry.slots.values().any(|slot| {
            slot.client == client
                && interact.finish.as_ref().and_then(|f| f.uri.as_deref())
                    == Some(slot.registration.uri.as_str())
        })
}

/// Commit the owner's choice first, then retain one typed notification privately.
pub(super) fn complete(
    server: &As,
    storage: &IndexedStorage,
    decisions: &Decisions,
    client: &str,
    session: &BrowserSession<'_>,
    choice: multiple::Choice,
) -> Result<(), String> {
    let registration = session.push.as_ref().ok_or("Push registration missing")?;
    if registration.status.lock().unwrap().created.elapsed() >= CALLBACK_WINDOW {
        return Err("Push callback window expired; start a fresh request".into());
    }
    let Finish::Push { uri, body } = consent_complete_choice(
        server,
        storage,
        decisions,
        client,
        session.grant_id,
        &session.handle,
        choice,
    )?
    else {
        return Err("Unexpected completion method".into());
    };
    let mut decisions = decisions.lock().map_err(|_| "Push state unavailable")?;
    let slot = decisions
        .push
        .slots
        .get_mut(&registration.id)
        .ok_or("Push registration unavailable")?;
    if slot.grant != Some(session.grant_id) || slot.client != client || uri != registration.uri {
        return Err("Push callback context mismatch".into());
    }
    registration.status.lock().unwrap().queued = true;
    slot.outbox = Some(Notification {
        uri,
        body,
        status: registration.status.clone(),
    });
    Ok(())
}

/// Called after a worker reply, with no worker or registry lock held during I/O.
pub(super) fn kick(app: &App, client: &str) {
    let job = app.decisions.lock().ok().and_then(|mut choices| {
        choices
            .push
            .slots
            .values_mut()
            .find(|slot| slot.client == client)?
            .outbox
            .take()
    });
    let Some(job) = job else {
        return;
    };
    let Ok(permit) = app.push_outbound.clone().try_acquire_owned() else {
        job.status.lock().unwrap().delivery = Some(transport::Delivery::RefusedBeforeSend);
        return;
    };
    let origin = app.origin.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let delivery = transport::send(&origin, &job.uri, job.body).await;
        job.status.lock().unwrap().delivery = Some(delivery);
    });
}

pub(super) struct Incoming {
    id: String,
    client: String,
    body: Vec<u8>,
    reply: tokio::sync::oneshot::Sender<Result<(), StatusCode>>,
}

pub(super) fn process(
    sessions: &mut HashMap<String, BrowserSession<'_>>,
    decisions: &Decisions,
    incoming: Incoming,
) {
    let result = (|| {
        let choices = decisions
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let slot = choices
            .push
            .slots
            .get(&incoming.id)
            .ok_or(StatusCode::NOT_FOUND)?;
        let session = sessions
            .get_mut(&incoming.client)
            .ok_or(StatusCode::NOT_FOUND)?;
        let registration = session.push.as_ref().ok_or(StatusCode::NOT_FOUND)?;
        if slot.client != incoming.client
            || slot.grant != Some(session.grant_id)
            || registration.id != incoming.id
            || session.state != "awaiting_push"
        {
            return Err(StatusCode::NOT_FOUND);
        }
        let mut status = registration
            .status
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if status.received || status.created.elapsed() >= CALLBACK_WINDOW {
            return Err(StatusCode::NOT_FOUND);
        }
        session
            .client
            .accept_push(&incoming.body, now())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        status.received = true;
        session.state = "ready";
        session.events.push("Client received an HTTP push and validated its interaction hash. Signed continuation is now available after the AS wait period.".into());
        Ok(())
    })();
    let _ = incoming.reply.send(result);
}

fn error(status: StatusCode) -> Response {
    match status {
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND => {
            (status, Json(json!({"error":"unknown_interaction"}))).into_response()
        }
        StatusCode::TOO_MANY_REQUESTS => (status, [("retry-after", "60")]).into_response(),
        _ => status.into_response(),
    }
}

pub(super) async fn receive(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(id) = uri.path().strip_prefix("/push-callback/") else {
        return error(StatusCode::NOT_FOUND);
    };
    if uri.query().is_some()
        || id.len() != 22
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return error(StatusCode::NOT_FOUND);
    }
    let client = {
        let Ok(mut choices) = app.decisions.lock() else {
            return error(StatusCode::SERVICE_UNAVAILABLE);
        };
        let Some(slot) = choices.push.slots.get(id) else {
            return error(StatusCode::NOT_FOUND);
        };
        let status = slot.registration.status.lock().unwrap();
        if status.received || status.created.elapsed() >= CALLBACK_WINDOW || slot.grant.is_none() {
            return error(StatusCode::NOT_FOUND);
        }
        let client = slot.client.clone();
        drop(status);
        if !choices.push.admit(Instant::now()) {
            return error(StatusCode::TOO_MANY_REQUESTS);
        }
        client
    };
    let mut types = headers.get_all("content-type").iter();
    if !types.next().and_then(|h| h.to_str().ok()).is_some_and(|t| {
        t.split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("application/json")
    }) || types.next().is_some()
    {
        return error(StatusCode::BAD_REQUEST);
    }
    if body.len() > MAX_CALLBACK_BODY {
        return error(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let (reply, received) = tokio::sync::oneshot::channel();
    let incoming = Incoming {
        id: id.into(),
        client,
        body: body.to_vec(),
        reply,
    };
    if app
        .commands
        .try_send(WorkerCommand::Push(incoming))
        .is_err()
    {
        return error(StatusCode::SERVICE_UNAVAILABLE);
    }
    match tokio::time::timeout(Duration::from_secs(4), received).await {
        Ok(Ok(Ok(()))) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(Err(status))) => error(status),
        _ => error(StatusCode::SERVICE_UNAVAILABLE),
    }
}

pub(super) fn view(registration: Option<&Registration>) -> Value {
    let Some(registration) = registration else {
        return Value::Null;
    };
    let status = registration.status.lock().unwrap();
    json!({
        "received": status.received,
        "expired": !status.received && status.created.elapsed() >= CALLBACK_WINDOW,
        "delivery": status.delivery.map_or(if status.queued { "queued" } else { "waiting_for_consent" }, transport::Delivery::name),
    })
}

#[cfg(test)]
mod tests;
