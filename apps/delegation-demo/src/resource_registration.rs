//! One bounded, co-located bootstrap. Resource references are public names,
//! not credentials; the client receives them only after local AS confirmation.
use super::*;
use gnap_as::{MemoryResourceSetStore, ResourceSetLimits, ResourceSetStore, RsId};
use gnap_types::rs::{
    ResourceRegistrationRequest, ResourceRegistrationResponse, ResourceServer, RsDiscovery,
    RsErrorResponse,
};

pub(super) const PATH: &str = "/register-resources";
pub(super) const RS_OWNER: &str = "delegation-lab-resource-owner";
const ATTEMPTS: usize = 6;
pub(super) const BUDGET: Duration = Duration::from_secs(120);
const DELAY: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub(super) struct References {
    pub folder: String,
    pub both: String,
}
pub(super) type Bootstrap = Arc<std::sync::OnceLock<Result<References, &'static str>>>;

pub(super) fn store() -> Arc<MemoryResourceSetStore> {
    Arc::new(MemoryResourceSetStore::new(ResourceSetLimits {
        max_sets: 2,
        max_sets_per_owner: 2,
        max_access_items: 2,
        ..ResourceSetLimits::default()
    }))
}

pub(super) fn leaves(both: bool) -> Vec<AccessItem> {
    let mut rights = vec![AccessItem::Reference(FOLDER_READ.into())];
    if both {
        rights.push(AccessItem::Reference(ARCHIVE_READ.into()));
    }
    rights
}

pub(super) fn known_leaf(right: &AccessItem) -> bool {
    matches!(right, AccessItem::Reference(value) if matches!(value.as_str(), FOLDER_READ | ARCHIVE_READ))
}

#[derive(Debug)]
enum AttemptError {
    Retry,
    Stop,
}

fn decode<T: serde::de::DeserializeOwned>(response: HttpResponse) -> Result<T, AttemptError> {
    if response.status == 404 || (500..600).contains(&response.status) {
        return Err(AttemptError::Retry);
    }
    if response.status == 400
        && serde_json::from_slice::<RsErrorResponse>(&response.body).is_ok_and(|response| {
            response.error.code == gnap_registry::RsErrorCode::InvalidResourceServer
        })
    {
        return Err(AttemptError::Retry);
    }
    introspection::json_response(response).map_err(|_| AttemptError::Stop)
}

// This test seam is specific to this startup sequence, not a general retry
// framework. Real time is Instant-based; tests advance elapsed time explicitly.
pub(super) fn bootstrap(
    app: &App,
    elapsed: impl Fn() -> Duration,
    delay: impl Fn(Duration),
) -> Result<References, &'static str> {
    let mut previous = Duration::ZERO;
    let mut check_budget = || {
        let current = elapsed();
        if current < previous || current >= BUDGET {
            return Err(AttemptError::Stop);
        }
        previous = current;
        Ok(current)
    };
    for attempt in 0..ATTEMPTS {
        let result = (|| {
            check_budget()?;
            let discovery: RsDiscovery = decode(
                app.resource_client
                    .transport
                    .send(HttpRequest::new(
                        "GET",
                        format!("{}/.well-known/gnap-as-rs", app.origin),
                    ))
                    .map_err(|_| AttemptError::Retry)?,
            )?;
            check_budget()?;
            let expected = format!("{}{PATH}", app.origin);
            let valid = if app.origin.starts_with("http:") {
                discovery.discovery_url_for_local_development()
            } else {
                discovery.discovery_url()
            };
            if valid.is_err()
                || discovery.grant_request_endpoint != format!("{}/gnap", app.origin)
                || discovery
                    .resource_registration_endpoint
                    .as_deref()
                    .is_some_and(|endpoint| endpoint != expected)
                || discovery
                    .introspection_endpoint
                    .as_deref()
                    .is_some_and(|endpoint| endpoint != format!("{}/introspect", app.origin))
            {
                return Err(AttemptError::Stop);
            }
            if discovery.resource_registration_endpoint.is_none()
                || discovery.introspection_endpoint.is_none()
            {
                return Err(AttemptError::Retry);
            }
            let mut references = Vec::new();
            for both in [false, true] {
                check_budget()?;
                let context = ResourceRegistrationRequest {
                    access: leaves(both),
                    resource_server: ResourceServer::ByReference(introspection::RS_ID.into()),
                    token_formats_supported: None,
                    token_introspection_required: Some(true),
                    extra: Default::default(),
                };
                let mut request = HttpRequest::new("POST", &expected);
                request
                    .headers
                    .push(("content-type".into(), "application/json".into()));
                request.body = Some(serde_json::to_vec(&context).map_err(|_| AttemptError::Stop)?);
                let request =
                    sign_request(request, app.resource_client.signer.as_ref(), None, now())
                        .map_err(|_| AttemptError::Stop)?;
                check_budget()?;
                let response: ResourceRegistrationResponse = decode(
                    app.resource_client
                        .transport
                        .send(request)
                        .map_err(|_| AttemptError::Retry)?,
                )?;
                check_budget()?;
                if response
                    .instance_id
                    .as_ref()
                    .is_some_and(|id| id != introspection::RS_ID)
                    || response
                        .introspection_endpoint
                        .as_deref()
                        .is_some_and(|url| url != format!("{}/introspect", app.origin))
                    || !response.extra.is_empty()
                {
                    return Err(AttemptError::Stop);
                }
                // The canonical route may still point at the old process during
                // replacement. Only a record in this AS instance is publishable.
                let local = app
                    .rs_registration
                    .resources
                    .lookup(&response.resource_reference)
                    .map_err(|_| AttemptError::Stop)?;
                let Some(local) = local else {
                    return Err(AttemptError::Retry);
                };
                let expected_leaves = leaves(both);
                if local.owner != RsId(RS_OWNER.into())
                    || local.access.len() != expected_leaves.len()
                    || !expected_leaves
                        .iter()
                        .all(|right| local.access.contains(right))
                {
                    return Err(AttemptError::Stop);
                }
                references.push(response.resource_reference);
            }
            check_budget()?;
            Ok(References {
                folder: references.remove(0),
                both: references.remove(0),
            })
        })();
        match result {
            Ok(references) => return Ok(references),
            Err(AttemptError::Stop) => break,
            Err(AttemptError::Retry) if attempt + 1 < ATTEMPTS => {
                let Ok(current) = check_budget() else {
                    break;
                };
                delay(DELAY.min(BUDGET.saturating_sub(current)));
            }
            Err(AttemptError::Retry) => break,
        }
    }
    Err("Resource registration bootstrap failed")
}

pub(super) fn state(bootstrap: &Bootstrap) -> &'static str {
    match bootstrap.get() {
        None => "starting",
        Some(Ok(_)) => "ready",
        Some(Err(_)) => "failed",
    }
}

#[cfg(test)]
pub(super) fn fixture(resources: &MemoryResourceSetStore) -> References {
    let owner = RsId(RS_OWNER.into());
    References {
        folder: resources
            .register_or_get(&owner, "rsr_fixture_folder", &leaves(false))
            .unwrap()
            .reference,
        both: resources
            .register_or_get(&owner, "rsr_fixture_both", &leaves(true))
            .unwrap()
            .reference,
    }
}
