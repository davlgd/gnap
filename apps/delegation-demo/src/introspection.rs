//! The demo's opaque-token RS: fixed AS discovery, authenticated introspection,
//! then local verification of the exact resource request. No token-store access.
use super::*;
use gnap_as::{
    IntrospectionDecision, IntrospectionPolicy, MemoryResourceSetStore, ResolvedResourceServer,
    ResourceRegistrationPolicy, ResourceServerResolver, RsId, TokenRecord,
};
use gnap_registry::KeyProofingMethod;
use gnap_types::{key::KeyObject, rs::ResourceServer};

pub(super) const RS_ID: &str = "delegation-demo-rs";
pub(super) const RS2_ID: &str = "delegation-demo-metadata-rs";
pub(super) const RS2_OWNER: &str = "demo-metadata-owner";
pub(super) const RS3_ID: &str = "delegation-demo-reports-rs";
pub(super) const RS3_OWNER: &str = "demo-reports-owner";
const MAX_RESPONSE: usize = 8192;
type Transport = dyn HttpTransport<Error = &'static str> + Send + Sync;

pub(super) struct Registration {
    pub key: KeyObject,
    pub metadata_key: KeyObject,
    pub reports_key: KeyObject,
    pub client_key: KeyObject,
    pub decisions: Decisions,
    pub nonces: MemoryStorage,
    pub derivation_nonces: MemoryStorage,
    pub resources: Arc<MemoryResourceSetStore>,
}

pub(super) fn public_key(signer: &Ps256Signer) -> KeyObject {
    KeyObject {
        proof: gnap_types::key::Proof::Named(KeyProofingMethod::Httpsig),
        jwk: Some(signer.public_jwk().expect("generated public RSA key")),
        cert: None,
        cert_s256: None,
    }
}

impl ResourceServerResolver for Registration {
    fn resolve(&self, rs: &ResourceServer) -> Option<ResolvedResourceServer> {
        match rs.as_reference()? {
            RS_ID => Some(ResolvedResourceServer {
                id: RsId(resource_registration::RS_OWNER.into()),
                key: self.key.clone(),
            }),
            RS2_ID => Some(ResolvedResourceServer {
                id: RsId(RS2_OWNER.into()),
                key: self.metadata_key.clone(),
            }),
            RS3_ID => Some(ResolvedResourceServer {
                id: RsId(RS3_OWNER.into()),
                key: self.reports_key.clone(),
            }),
            _ => None,
        }
    }
}

impl ResourceRegistrationPolicy for Registration {
    fn authorize(&self, rs: &ResolvedResourceServer, access: &[AccessItem]) -> bool {
        rs.id == RsId(resource_registration::RS_OWNER.into())
            && !access.is_empty()
            && access.len() <= 2
            && access.iter().all(resource_registration::known_leaf)
    }
}

impl IntrospectionPolicy for Registration {
    fn evaluate(
        &self,
        rs: &ResourceServer,
        token: &TokenRecord,
        minimum: Option<&[AccessItem]>,
    ) -> IntrospectionDecision {
        if token.client.as_value().is_some() {
            if rs.as_reference() != Some(RS_ID)
                || minimum
                    .is_some_and(|rights| rights != [AccessItem::Reference(FOLDER_READ.into())])
            {
                return IntrospectionDecision::Inactive;
            }
            return self
                .decisions
                .lock()
                .ok()
                .and_then(|registry| registry.external.introspect(token))
                .map_or(IntrospectionDecision::Inactive, |key| {
                    IntrospectionDecision::Active {
                        access: vec![AccessItem::Reference(FOLDER_READ.into())],
                        key: Some(key),
                    }
                });
        }
        if rs.as_reference() == Some(RS2_ID) {
            let expected = vec![AccessItem::Reference(derivation::METADATA_READ.into())];
            let accepted = token
                .derivation
                .as_ref()
                .is_some_and(|derived| derived.audience == RsId(RS2_OWNER.into()))
                && token.client.as_reference() == Some(RS_ID)
                && token.token.access.as_ref() == Some(&expected)
                && token
                    .token
                    .key
                    .as_ref()
                    .is_none_or(|key| key.as_value() == Some(&self.key))
                && minimum.is_none_or(|rights| rights == expected);
            return if accepted {
                IntrospectionDecision::Active {
                    access: expected,
                    key: Some(self.key.clone()),
                }
            } else {
                IntrospectionDecision::Inactive
            };
        }
        if rs.as_reference() == Some(RS3_ID) {
            // The reports RS knows one right. A token of the documents RS,
            // whatever its label, is not active here; nor is a derived child.
            let expected = vec![AccessItem::Reference(multiple::REPORTS_READ.into())];
            let registered = self
                .decisions
                .lock()
                .map(|registry| registry.clients.contains(&client_id(&token.client)))
                .unwrap_or(false);
            let accepted = token.derivation.is_none()
                && registered
                && token.token.access.as_ref() == Some(&expected)
                && token
                    .token
                    .key
                    .as_ref()
                    .is_none_or(|key| key.as_value() == Some(&self.client_key))
                && minimum.is_none_or(|rights| rights == expected);
            return if accepted {
                IntrospectionDecision::Active {
                    access: expected,
                    key: Some(self.client_key.clone()),
                }
            } else {
                IntrospectionDecision::Inactive
            };
        }
        // These two synthetic rights are this pre-registered RS's audience.
        // Unknown descriptions are never silently ignored or mapped to a right.
        let known = |right: &AccessItem| matches!(right, AccessItem::Reference(value) if matches!(value.as_str(), FOLDER_READ | ARCHIVE_READ));
        let Some(access) = token.token.access.as_ref() else {
            return IntrospectionDecision::Inactive;
        };
        let registered = self
            .decisions
            .lock()
            .map(|registry| registry.clients.contains(&client_id(&token.client)))
            .unwrap_or(false);
        if rs.as_reference() != Some(RS_ID)
            || token.derivation.is_some()
            || !registered
            || token
                .token
                .key
                .as_ref()
                .is_some_and(|key| key.as_value() != Some(&self.client_key))
            || access.is_empty()
            || !access.iter().all(known)
            || minimum.is_some_and(|rights| {
                rights.is_empty()
                    || !rights
                        .iter()
                        .all(|right| known(right) && access.contains(right))
            })
        {
            return IntrospectionDecision::Inactive;
        }
        IntrospectionDecision::Active {
            access: access.clone(),
            key: Some(self.client_key.clone()),
        }
    }
}

pub(super) struct ResourceClient {
    pub origin: String,
    pub signer: Arc<Ps256Signer>,
    pub transport: Arc<Transport>,
    pub nonces: MemoryStorage,
}

#[derive(Clone, Copy)]
pub(super) enum Profile {
    Documents,
    Metadata,
    Reports,
}
impl Profile {
    fn rs_id(self) -> &'static str {
        match self {
            Self::Documents => RS_ID,
            Self::Metadata => RS2_ID,
            Self::Reports => RS3_ID,
        }
    }
    fn accepts_lifetime(self, duration: Option<u64>) -> bool {
        match self {
            Self::Documents => matches!(duration, Some(300 | 1200)),
            Self::Reports => duration == Some(1200),
            Self::Metadata => duration.is_some_and(|seconds| (1..=60).contains(&seconds)),
        }
    }
    fn accepts_rights(self, access: &[AccessItem]) -> bool {
        match self {
            Self::Documents => access.len() <= 2 && access.iter().all(|right| matches!(right, AccessItem::Reference(value) if matches!(value.as_str(), FOLDER_READ | ARCHIVE_READ))),
            Self::Metadata => access == [AccessItem::Reference(derivation::METADATA_READ.into())],
            Self::Reports => access == [AccessItem::Reference(multiple::REPORTS_READ.into())],
        }
    }
}

#[test]
fn external_lifetime_is_not_a_relaxation_of_the_reports_profile() {
    assert!(Profile::Documents.accepts_lifetime(Some(300)));
    assert!(Profile::Documents.accepts_lifetime(Some(1200)));
    for duration in [None, Some(0), Some(299), Some(301), Some(1199), Some(1201)] {
        assert!(!Profile::Documents.accepts_lifetime(duration));
    }
    assert!(!Profile::Reports.accepts_lifetime(Some(300)));
    assert!(Profile::Reports.accepts_lifetime(Some(1200)));
}

// This transport owns no blocking runtime: constructing/dropping a reqwest
// blocking client happens only inside the bounded blocking resource task.
pub(super) struct Http {
    pub origin: String,
}
impl HttpTransport for Http {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        if ![
            format!("{}/.well-known/gnap-as-rs", self.origin),
            format!("{}/introspect", self.origin),
            format!("{}{}", self.origin, resource_registration::PATH),
            format!("{}/gnap", self.origin),
            format!("{}{}", self.origin, derivation::RS2_PATH),
        ]
        .contains(&request.url)
            && !derivation::management_destination(&self.origin, &request.url)
        {
            return Err("untrusted introspection destination");
        }
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| "introspection transport unavailable")?;
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| "invalid introspection method")?;
        let mut outgoing = client.request(method, &request.url);
        for (name, value) in request.headers {
            outgoing = outgoing.header(name, value);
        }
        if let Some(body) = request.body {
            outgoing = outgoing.body(body);
        }
        let response = outgoing
            .send()
            .map_err(|_| "introspection transport unavailable")?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| "introspection response unavailable")?;
        if body.len() > MAX_RESPONSE {
            return Err("introspection response too large");
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

pub(super) fn json_response<T: serde::de::DeserializeOwned>(
    response: HttpResponse,
) -> Result<T, ResourceError> {
    if response.status != 200 {
        return Err(ResourceError::Unavailable);
    }
    json_body(&response)
}

pub(super) fn json_body<T: serde::de::DeserializeOwned>(
    response: &HttpResponse,
) -> Result<T, ResourceError> {
    let types: Vec<_> = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .collect();
    if response.body.len() > MAX_RESPONSE
        || types.len() != 1
        || !types[0]
            .1
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(ResourceError::Unavailable);
    }
    serde_json::from_slice(&response.body).map_err(|_| ResourceError::Unavailable)
}

impl ResourceClient {
    pub fn authorize(
        &self,
        request: &HttpRequest,
        right: &str,
        clock: impl Fn() -> u64,
    ) -> Result<(), ResourceError> {
        self.authorize_profile(request, right, Profile::Documents, clock)
    }

    pub fn authorize_profile(
        &self,
        request: &HttpRequest,
        right: &str,
        profile: Profile,
        clock: impl Fn() -> u64,
    ) -> Result<(), ResourceError> {
        let grant = format!("{}/gnap", self.origin);
        let introspection = format!("{}/introspect", self.origin);
        let trusted = if self.origin.starts_with("http:") {
            gnap_rs::TrustedAs::for_local_development(grant, introspection)
        } else {
            gnap_rs::TrustedAs::new(grant, introspection)
        }
        .map_err(|_| ResourceError::Unavailable)?;
        let identity = ResourceServer::ByReference(profile.rs_id().into());
        let nonces = |nonce: &str, time: u64| self.nonces.remember_nonce(nonce, time);
        let authorizer = gnap_rs::Authorizer::new(
            &trusted,
            &identity,
            self.transport.as_ref(),
            self.signer.as_ref(),
            &nonces,
            &gnap_rs::AudiencePolicy::IntrospectionContext,
        );
        // The SDK verifies trust, binding and presentation. This application
        // additionally retains its existing, deliberately narrow token profile.
        let policy = |token: &gnap_rs::TokenInfo<'_>| {
            if !profile.accepts_lifetime(token.expires_at.checked_sub(token.issued_at))
                || !profile.accepts_rights(token.access)
                || token.not_before.is_some()
                || token.audience.is_some()
                || token.subject.is_some()
                || token.instance_id.is_some()
            {
                Err(gnap_rs::AuthorizationError::Unavailable)
            } else {
                Ok(())
            }
        };
        authorizer
            .authorize(
                request,
                &[AccessItem::Reference(right.into())],
                &policy,
                clock,
            )
            .map_err(|error| match error {
                gnap_rs::AuthorizationError::Denied => ResourceError::Denied,
                gnap_rs::AuthorizationError::Unavailable => ResourceError::Unavailable,
            })
    }
}

pub(super) fn handle(app: &App, request: &HttpRequest, time: u64) -> HttpResponse {
    let registration = &app.rs_registration;
    let registration_endpoint = format!("{}{}", app.origin, resource_registration::PATH);
    match app
        .server
        .resource_server_api(
            registration.as_ref(),
            registration.as_ref(),
            &registration.nonces,
            &format!("{}/introspect", app.origin),
        )
        .and_then(|api| {
            api.with_resource_registration(
                &registration_endpoint,
                registration.as_ref(),
                registration.resources.as_ref(),
                &OsNonces,
            )
        }) {
        Ok(api) => api.handle(request, time),
        Err(_) => HttpResponse {
            status: 503,
            // Construction failed before any RS protocol request was handled.
            // Do not disguise this deployment failure as a GNAP error object.
            headers: vec![
                ("content-type".into(), "text/plain; charset=utf-8".into()),
                ("cache-control".into(), "no-store".into()),
            ],
            body: b"Resource-server API configuration unavailable".to_vec(),
        },
    }
}

#[cfg(test)]
pub(super) struct Direct {
    pub server: Arc<As>,
    pub storage: Arc<IndexedStorage>,
    pub registration: Arc<Registration>,
    pub origin: String,
}
#[cfg(test)]
impl HttpTransport for Direct {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        // Match the HTTP adapter's pre-handler maintenance. This is not an
        // override of an active:false response returned by the SDK.
        self.storage
            .cleanup()
            .map_err(|_| "test AS maintenance unavailable")?;
        let rs = &self.registration;
        let endpoint = format!("{}/introspect", self.origin);
        let api = self
            .server
            .resource_server_api(rs.as_ref(), rs.as_ref(), &rs.nonces, &endpoint)
            .map_err(|_| "test AS configuration")?;
        let registration_endpoint = format!("{}{}", self.origin, resource_registration::PATH);
        let api = api
            .with_resource_registration(
                &registration_endpoint,
                rs.as_ref(),
                rs.resources.as_ref(),
                &OsNonces,
            )
            .map_err(|_| "test resource registration configuration")?;
        Ok(api.handle(&request, now()))
    }
}
