use super::{
    config::{self, Target},
    network::Network,
    oracle, Callback, Inner, Snapshot, WORK_LIMIT,
};
use gnap_client::{sign_request, ClientError, HttpRequest, HttpTransport, Session, Step};
use gnap_crypto::{proof::Signer, Ps256Signer};
use gnap_types::{token::TokenValue, GrantRequest};
use serde_json::{json, Value};
use std::{
    num::NonZeroU64,
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

fn now() -> u64 {
    gnap_types::unix_now()
}

fn continuation_deadline(received: Instant, wait: Option<u64>) -> Result<Instant, ()> {
    // RFC 9635 §3.1: omission means five seconds, measured from receipt.
    // Longer waits are outside this bounded interactive scenario's profile.
    let wait = wait.unwrap_or(5);
    if wait > 30 {
        return Err(());
    }
    received.checked_add(Duration::from_secs(wait)).ok_or(())
}

pub(super) fn run(
    inner: Arc<Inner>,
    target: Target,
    runtime: tokio::runtime::Handle,
    callbacks: mpsc::Receiver<Callback>,
    snapshot: Arc<Mutex<Snapshot>>,
) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let network = Network::new(target.clone(), inner.local, runtime);
        let mut client = Session::new(&network, inner.signer.as_ref(), &target.grant)
            .supporting(&["redirect"])
            .with_finish_timeout(NonZeroU64::new(300).unwrap());
        let mut checks = Vec::new();
        let result = exercise(
            &inner,
            &network,
            &mut client,
            callbacks,
            &snapshot,
            &mut checks,
        );
        // A bounded best-effort cleanup of the credentials this scenario owns.
        // It cannot promise remote deletion when networking has failed or when
        // the scenario's own call/deadline budget is exhausted.
        if result.is_err() {
            let _ = client.revoke_token(None, now());
            let _ = client.revoke_grant(now());
            checks.push(crate::check("lifecycle-completion", None,
                "Scenario incomplete: transport, deadline, callback or an unsupported response prevented completion. Earlier observed failures remain failures. Cleanup was attempted within the same bounded budget; remote deletion is not guaranteed.",
                "https://www.rfc-editor.org/rfc/rfc9635.html"));
        }
        if let Ok(mut state) = snapshot.lock() {
            state.status = result.unwrap_or("inconclusive");
            state.redirect = None;
            state.checks = checks;
            state.observation = crate::observation("live");
        }
    }));
    if outcome.is_err() {
        if let Ok(mut state) = snapshot.lock() {
            state.status = "inconclusive";
            state.redirect = None;
        }
    }
}

fn exercise(
    inner: &Inner,
    network: &Network,
    client: &mut Session<'_, Network, Ps256Signer>,
    callbacks: mpsc::Receiver<Callback>,
    snapshot: &Mutex<Snapshot>,
    checks: &mut Vec<crate::Check>,
) -> Result<&'static str, ()> {
    let started = Instant::now();
    let request: GrantRequest = serde_json::from_value(json!({
        "client":{"key":{"proof":"httpsig","jwk":inner.signer.public_jwk().map_err(|_| ())?}},
        "access_token":{"access":[config::RIGHT]},
        "interact":{"start":["redirect"],"finish":{"method":"redirect",
            "uri":format!("{}/lifecycle/callback", inner.origin),
            "nonce":gnap_crypto::httpsig::fresh_nonce().map_err(|_| ())?}}
    }))
    .map_err(|_| ())?;
    let step = client.start(&request, now());
    let received = Instant::now();
    let response = network.last().ok_or(())?;
    if !oracle::pending(&response, &network.target, checks) {
        return Err(());
    }
    let Step::Pending(step) = step.map_err(|_| ())? else {
        return Err(());
    };
    let redirect = step
        .interact
        .as_ref()
        .and_then(|i| i.redirect.clone())
        .ok_or(())?;
    if !config::member(&redirect, &network.target.interaction) {
        return Err(());
    }
    let continue_at =
        continuation_deadline(received, step.r#continue.as_ref().and_then(|c| c.wait))?;
    {
        let mut state = snapshot.lock().map_err(|_| ())?;
        state.status = "pending";
        state.redirect = Some(redirect);
        state.checks = checks.clone();
        state.observation = crate::observation("live");
    }
    let mut completed = false;
    for _ in 0..3 {
        let remaining = WORK_LIMIT.checked_sub(started.elapsed()).ok_or(())?;
        let callback = callbacks.recv_timeout(remaining).map_err(|_| ())?;
        let valid = client.accept_redirect(&callback.uri, now()).is_ok();
        let _ = callback.accepted.send(valid);
        if valid {
            completed = true;
            break;
        }
    }
    if !completed {
        return Err(());
    }
    {
        let mut state = snapshot.lock().map_err(|_| ())?;
        state.status = "running";
        state.redirect = None;
    }
    // This is an SDK cryptographic check, labelled separately from the HTTP
    // oracle. The full callback and interaction reference are never reported.
    checks.push(oracle::assertion("lifecycle-finish-binding-sdk", true,
        "The SDK accepted the finish callback for this browser's retained session and nonce. This verification reuses the client SDK; it is not an independent hash oracle."));
    // Respect the AS's initial continuation wait without polling it while the
    // resource owner is deciding. The wait remains inside the scenario budget.
    let delay = continue_at.saturating_duration_since(Instant::now());
    if started.elapsed() + delay >= WORK_LIMIT {
        return Err(());
    }
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
    let step = client.continue_grant(now());
    let response = network.last().ok_or(())?;
    if matches!(&step, Err(ClientError::Server(e)) if e.code == gnap_registry::ErrorCode::UserDenied)
    {
        oracle::headers(&response, checks, oracle::Phase::Denied);
        let body: Value = serde_json::from_slice(&response.body).map_err(|_| ())?;
        let error = body.get("error");
        let denied = error.and_then(Value::as_str) == Some("user_denied")
            || error.and_then(|e| e.get("code")).and_then(Value::as_str) == Some("user_denied");
        checks.push(oracle::assertion("lifecycle-owner-denial-no-token", denied && body.get("access_token").is_none() && body.get("continue").is_none(),
            "The manually denied scenario returned user_denied without an access token or a continuation in this closed-grant profile. Resource lifecycle checks were not executed."));
        return Ok("denied");
    }
    if !oracle::token(&response, &network.target, None, checks) {
        return Err(());
    }
    let Step::Approved(_) = step.map_err(|_| ())? else {
        return Err(());
    };
    let token = client
        .usable_tokens(now())
        .and_then(|t| t.first().map(|t| t.value.clone()))
        .ok_or(())?;
    let request = resource(network, inner.signer.as_ref(), &token)?;
    oracle::read(
        &network.send(request.clone()).map_err(|_| ())?,
        "lifecycle-valid-token-read",
        checks,
    );
    oracle::refusal(
        &network.send(request).map_err(|_| ())?,
        "lifecycle-replay-refused",
        checks,
    );
    let wrong = resource(network, inner.wrong_signer.as_ref(), &token)?;
    oracle::refusal(
        &network.send(wrong).map_err(|_| ())?,
        "lifecycle-other-key-refused",
        checks,
    );
    let fresh = resource(network, inner.signer.as_ref(), &token)?;
    oracle::read(
        &network.send(fresh).map_err(|_| ())?,
        "lifecycle-valid-after-negative-probes",
        checks,
    );
    let rotated = client.rotate_token(None, now());
    let response = network.last().ok_or(())?;
    if !oracle::token(&response, &network.target, Some(token.as_str()), checks) {
        return Err(());
    }
    let rotated = rotated.map_err(|_| ())?;
    let retired = resource(network, inner.signer.as_ref(), &token)?;
    oracle::refusal(
        &network.send(retired).map_err(|_| ())?,
        "lifecycle-rotated-value-refused",
        checks,
    );
    let fresh = resource(network, inner.signer.as_ref(), &rotated.value)?;
    oracle::read(
        &network.send(fresh).map_err(|_| ())?,
        "lifecycle-rotated-token-read",
        checks,
    );
    let revoked = client.revoke_token(None, now());
    oracle::revoked(&network.last().ok_or(())?, checks);
    revoked.map_err(|_| ())?;
    let retired = resource(network, inner.signer.as_ref(), &rotated.value)?;
    oracle::refusal(
        &network.send(retired).map_err(|_| ())?,
        "lifecycle-revoked-value-refused",
        checks,
    );
    Ok("complete")
}

fn resource(network: &Network, signer: &dyn Signer, token: &TokenValue) -> Result<HttpRequest, ()> {
    sign_request(
        HttpRequest::new("GET", &network.target.resource),
        signer,
        Some(token),
        now(),
    )
    .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_wait_starts_at_receipt_and_defaults_to_five_seconds() {
        let started = Instant::now();
        let received = started + Duration::from_secs(4);
        assert_eq!(
            continuation_deadline(received, None).unwrap(),
            started + Duration::from_secs(9)
        );
        assert_eq!(continuation_deadline(received, Some(0)).unwrap(), received);
        assert_eq!(
            continuation_deadline(received, Some(30)).unwrap(),
            received + Duration::from_secs(30)
        );
        assert!(continuation_deadline(received, Some(31)).is_err());
        assert!(continuation_deadline(received, Some(u64::MAX)).is_err());
    }
}
