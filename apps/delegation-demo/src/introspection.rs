//! The demo's opaque-token RS: fixed AS discovery, authenticated introspection,
//! then local verification of the exact resource request. No token-store access.
use super::*;
use gnap_as::{IntrospectionDecision, IntrospectionPolicy, ResourceServerResolver, TokenRecord};
use gnap_crypto::verify::{verify_request_with_policy, Expectations, SignedRequest};
use gnap_crypto::Ps256Verifier;
use gnap_registry::KeyProofingMethod;
use gnap_types::{
    key::KeyObject,
    rs::{IntrospectionRequest, IntrospectionResponse, ResourceServer, RsDiscovery},
};

const RS_ID: &str = "delegation-demo-rs";
const MAX_RESPONSE: usize = 8192;
type Transport = dyn HttpTransport<Error = &'static str> + Send + Sync;

pub(super) struct Registration {
    pub key: KeyObject,
    pub client_key: KeyObject,
    pub decisions: Decisions,
    pub nonces: MemoryStorage,
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
    fn resolve(&self, rs: &ResourceServer) -> Option<KeyObject> {
        (rs.as_reference() == Some(RS_ID)).then(|| self.key.clone())
    }
}

impl IntrospectionPolicy for Registration {
    fn evaluate(
        &self,
        rs: &ResourceServer,
        token: &TokenRecord,
        minimum: Option<&[AccessItem]>,
    ) -> IntrospectionDecision {
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
        ]
        .contains(&request.url)
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

fn json_response<T: serde::de::DeserializeOwned>(
    response: HttpResponse,
) -> Result<T, ResourceError> {
    let types: Vec<_> = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .collect();
    if response.status != 200
        || response.body.len() > MAX_RESPONSE
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
        let auth: Vec<_> = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str())
            .collect();
        if auth.len() != 1 {
            return Err(ResourceError::Denied);
        }
        let (scheme, value) = auth[0].split_once(' ').ok_or(ResourceError::Denied)?;
        let value = value.trim_start_matches(' ');
        if !scheme.eq_ignore_ascii_case("gnap")
            || value.is_empty()
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ResourceError::Denied);
        }
        let before = clock();
        let discovery_url = format!("{}/.well-known/gnap-as-rs", self.origin);
        let metadata: RsDiscovery = json_response(
            self.transport
                .send(HttpRequest::new("GET", &discovery_url))
                .map_err(|_| ResourceError::Unavailable)?,
        )?;
        let validated_url = if self.origin.starts_with("http:") {
            metadata.discovery_url_for_local_development()
        } else {
            metadata.discovery_url()
        }
        .map_err(|_| ResourceError::Unavailable)?;
        let endpoint = format!("{}/introspect", self.origin);
        if validated_url != discovery_url
            || metadata.grant_request_endpoint != format!("{}/gnap", self.origin)
            || metadata.introspection_endpoint.as_deref() != Some(&endpoint)
            || metadata
                .key_proofs_supported
                .as_ref()
                .is_some_and(|proofs| !proofs.contains(&KeyProofingMethod::Httpsig))
        {
            return Err(ResourceError::Unavailable);
        }
        let context = IntrospectionRequest {
            access_token: TokenValue::new(value).map_err(|_| ResourceError::Denied)?,
            resource_server: ResourceServer::ByReference(RS_ID.into()),
            proof: Some(KeyProofingMethod::Httpsig),
            access: Some(vec![AccessItem::Reference(right.into())]),
            extra: Default::default(),
        };
        let mut outgoing = HttpRequest::new("POST", &endpoint);
        outgoing
            .headers
            .push(("content-type".into(), "application/json".into()));
        outgoing.body = Some(serde_json::to_vec(&context).map_err(|_| ResourceError::Unavailable)?);
        let outgoing = sign_request(outgoing, self.signer.as_ref(), None, before)
            .map_err(|_| ResourceError::Unavailable)?;
        let response: IntrospectionResponse = json_response(
            self.transport
                .send(outgoing)
                .map_err(|_| ResourceError::Unavailable)?,
        )?;
        let IntrospectionResponse::Active(active) = response else {
            return Err(ResourceError::Denied);
        };
        let key = active
            .key
            .as_ref()
            .and_then(|key| key.as_value())
            .ok_or(ResourceError::Unavailable)?;
        // iat/exp are optional in RFC 9767, but mandatory in this fixed demo
        // profile. A changed AS profile must not silently remove our deadline.
        let (Some(issued), Some(expires)) = (active.iat, active.exp) else {
            return Err(ResourceError::Unavailable);
        };
        if active.iss != format!("{}/gnap", self.origin)
            || expires.checked_sub(issued) != Some(1200)
            || key.validate().is_err()
            || key.proof.method() != &KeyProofingMethod::Httpsig
            || matches!(&key.proof, gnap_types::key::Proof::Detailed { params, .. } if !params.is_empty())
            || active.flags.as_ref().is_some_and(|flags| !flags.is_empty())
            || !active.extra.is_empty()
            || active.access.len() > 2
            || active.access.iter().any(|right| !matches!(right, AccessItem::Reference(value) if matches!(value.as_str(), FOLDER_READ | ARCHIVE_READ)))
        {
            return Err(ResourceError::Unavailable);
        }
        let right = AccessItem::Reference(right.into());
        if !active.access.contains(&right) {
            return Err(ResourceError::Denied);
        }
        let verifier =
            Ps256Verifier::from_public_jwk(key.jwk.as_ref().ok_or(ResourceError::Unavailable)?)
                .map_err(|_| ResourceError::Unavailable)?;
        let verification_time = clock();
        if verification_time < before || verification_time < issued || verification_time >= expires
        {
            return Err(ResourceError::Denied);
        }
        verify_request_with_policy(
            &SignedRequest {
                method: &request.method,
                target_uri: &request.url,
                headers: &request.headers,
                body: request.body.as_deref(),
            },
            &verifier,
            &Expectations {
                now: verification_time,
                max_clock_skew: 300,
                key_id: None,
            },
            &|nonce: &str, time: u64| self.nonces.remember_nonce(nonce, time),
            &|params| params.nonce.as_ref().is_some_and(|nonce| !nonce.is_empty()),
        )
        .map_err(|_| ResourceError::Denied)?;
        let final_time = clock();
        if final_time < verification_time || final_time >= expires {
            return Err(ResourceError::Denied);
        }
        // A concurrent revocation after the AS decision can race this read.
        // No positive result is retained for a subsequent resource request.
        Ok(())
    }
}

pub(super) fn handle(app: &App, request: &HttpRequest, time: u64) -> HttpResponse {
    let registration = &app.rs_registration;
    match app.server.resource_server_api(
        registration.as_ref(),
        registration.as_ref(),
        &registration.nonces,
        &format!("{}/introspect", app.origin),
    ) {
        Ok(api) => api.handle(request, time),
        Err(_) => HttpResponse {
            status: 503,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"error":"introspection_unavailable"}"#.to_vec(),
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
        Ok(api.handle(&request, now()))
    }
}
