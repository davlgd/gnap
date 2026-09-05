//! Fixed-origin transport and bounded, off-runtime HTTP dispatch.
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{uri::Authority, StatusCode, Version},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Router,
};
use gnap_client::{HttpRequest, HttpResponse, HttpTransport};
use std::{io::Read, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct Origin {
    pub value: String,
    scheme: String,
    authority: (String, u16),
}
impl Origin {
    pub fn parse(value: &str) -> Result<Self, String> {
        let u = reqwest::Url::parse(value).map_err(|_| "invalid origin")?;
        if u.origin().ascii_serialization() != value
            || u.path() != "/"
            || u.query().is_some()
            || u.fragment().is_some()
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return Err("origin must be canonical, without path or credentials".into());
        }
        if u.scheme() != "https"
            && !(u.scheme() == "http"
                && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
        {
            return Err("HTTPS required except explicit loopback origins".into());
        }
        Ok(Self {
            value: value.into(),
            scheme: u.scheme().into(),
            authority: (
                u.host_str().ok_or("missing host")?.into(),
                u.port_or_known_default().ok_or("missing port")?,
            ),
        })
    }
    fn authority(&self, value: &str) -> Result<(String, u16), StatusCode> {
        let bad = StatusCode::BAD_REQUEST;
        if !value.is_ascii()
            || value
                .bytes()
                .any(|c| c.is_ascii_whitespace() || b"@\\%/?#".contains(&c))
        {
            return Err(bad);
        }
        let a: Authority = value.parse().map_err(|_| bad)?;
        let suffix = &value[a.host().len()..];
        let port = match suffix.strip_prefix(':') {
            Some(p) if !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => {
                p.parse().map_err(|_| bad)?
            }
            None if suffix.is_empty() => {
                if self.scheme == "https" {
                    443
                } else {
                    80
                }
            }
            _ => return Err(bad),
        };
        Ok((a.host().to_ascii_lowercase(), port))
    }
    fn matches(&self, r: &Request) -> Result<bool, StatusCode> {
        let mut hosts = r.headers().get_all("host").iter();
        let host = hosts
            .next()
            .map(|h| self.authority(h.to_str().map_err(|_| StatusCode::BAD_REQUEST)?))
            .transpose()?;
        if hosts.next().is_some() || (host.is_none() && r.version() != Version::HTTP_2) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let uri = r
            .uri()
            .authority()
            .map(|a| self.authority(a.as_str()))
            .transpose()?;
        if host.is_some() && uri.is_some() && host != uri
            || r.uri()
                .scheme_str()
                .is_some_and(|s| !matches!(s, "http" | "https"))
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(host.or(uri).ok_or(StatusCode::BAD_REQUEST)? == self.authority)
    }
}
async fn guard(State(origin): State<Origin>, request: Request, next: Next) -> Response {
    let mut response = if request.uri().path() == "/health" {
        next.run(request).await
    } else {
        match origin.matches(&request) {
            Ok(true) => next.run(request).await,
            Ok(false) => StatusCode::MISDIRECTED_REQUEST.into_response(),
            Err(s) => s.into_response(),
        }
    };
    let security_headers = [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; \
             connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    ];
    for (name, value) in security_headers {
        response.headers_mut().insert(name, value.parse().unwrap());
    }
    response
}
pub fn guarded(router: Router, origin: Origin) -> Router {
    router.layer(middleware::from_fn_with_state(origin, guard))
}

pub fn reply(response: HttpResponse) -> Response {
    let mut out = Response::builder().status(response.status);
    for (name, value) in response.headers {
        out = out.header(name, value);
    }
    out.body(Body::from(response.body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
pub fn answer(status: u16, body: serde_json::Value) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("cache-control".into(), "no-store".into()),
        ],
        body: serde_json::to_vec(&body).unwrap(),
    }
}
pub fn denied(status: u16) -> HttpResponse {
    answer(status, serde_json::json!({"error":"request refused"}))
}
pub fn signed(request: &HttpRequest) -> gnap_crypto::SignedRequest<'_> {
    gnap_crypto::SignedRequest {
        method: &request.method,
        target_uri: &request.url,
        headers: &request.headers,
        body: request.body.as_deref(),
    }
}

/// Admission is non-waiting: four workers, no unbounded work queue. The owned
/// permit lives inside the blocking job even if its HTTP client disconnects.
pub async fn dispatch(
    request: Request,
    origin: &Origin,
    workers: Arc<Semaphore>,
    work: impl FnOnce(HttpRequest) -> HttpResponse + Send + 'static,
) -> Response {
    let Ok(permit) = workers.try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let bytes =
        match tokio::time::timeout(Duration::from_secs(3), to_bytes(body, crate::MAX_BODY)).await {
            Ok(Ok(b)) => b,
            _ => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        };
    let mut headers = Vec::new();
    for (name, value) in &parts.headers {
        let Ok(value) = value.to_str() else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        headers.push((name.to_string(), value.into()));
    }
    let request = HttpRequest {
        method: parts.method.to_string(),
        url: format!(
            "{}{}",
            origin.value,
            parts.uri.path_and_query().map_or("/", |p| p.as_str())
        ),
        headers,
        // Content-Length: 0 alone cannot distinguish an absent body from an
        // explicitly signed empty one. Content-Digest preserves the latter.
        body: (!bytes.is_empty() || parts.headers.contains_key("content-digest"))
            .then(|| bytes.to_vec()),
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work(request)
    })
    .await
    {
        Ok(r) => reply(r),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub struct Network {
    client: reqwest::blocking::Client,
    origin: Origin,
}
impl Network {
    pub fn new(origin: Origin) -> Result<Self, String> {
        Ok(Self {
            origin,
            client: reqwest::blocking::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .map_err(|_| "HTTP configuration failed")?,
        })
    }
}
impl HttpTransport for Network {
    type Error = String;
    fn send(&self, r: HttpRequest) -> Result<HttpResponse, String> {
        let u = reqwest::Url::parse(&r.url).map_err(|_| "invalid destination")?;
        if u.origin().ascii_serialization() != self.origin.value
            || !u.username().is_empty()
            || u.password().is_some()
            || u.fragment().is_some()
        {
            return Err("destination outside fixed origin".into());
        }
        let mut b = self.client.request(
            reqwest::Method::from_bytes(r.method.as_bytes()).map_err(|_| "invalid method")?,
            &r.url,
        );
        for (k, v) in r.headers {
            b = b.header(k, v);
        }
        if let Some(body) = r.body {
            b = b.body(body);
        }
        let response = b.send().map_err(|_| "upstream unavailable")?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().into()))
            .collect();
        let mut body = Vec::new();
        response
            .take((crate::MAX_BODY + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|_| "upstream body unavailable")?;
        if body.len() > crate::MAX_BODY {
            return Err("upstream response too large".into());
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
