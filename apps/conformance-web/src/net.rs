//! A bounded HTTP transport, shared by the workbench and the command line.
//!
//! Each call is checked against the caller's [`Destinations`] and canonical
//! [`endpoint`] rules, then resolved, pinned to the public addresses it
//! resolved to, and sent without proxy, redirect, or retry. Resolution, TLS,
//! and the streamed response read share one deadline, and [`Limits`] bound
//! the calls, the time, and every size. This is the transport of operator
//! tools, not an SSRF-safe client for arbitrary input.

use gnap_client::{HttpRequest, HttpResponse, HttpTransport};
use reqwest::Url;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

/// The bounds of one transport: its calls, its time, and its sizes.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Most requests the transport sends.
    pub calls: usize,
    /// Total time the transport may spend, from its creation.
    pub budget: Duration,
    /// Longest exchange: resolution, connection, TLS, and response read.
    pub exchange: Duration,
    /// Longest connection setup.
    pub connect: Duration,
    /// Longest request, once connected.
    pub request: Duration,
    /// Largest request body, in bytes.
    pub request_body: usize,
    /// Largest response body, in bytes.
    pub response_body: usize,
    /// Most response header fields.
    pub headers: usize,
    /// Longest response header name, in bytes.
    pub header_name: usize,
    /// Longest response header value, in bytes.
    pub header_value: usize,
    /// Most addresses a host may resolve to.
    pub addresses: usize,
}

impl Limits {
    /// The authenticated lifecycle scenario of the workbench.
    pub const LIFECYCLE: Self = Self {
        calls: 16,
        budget: Duration::from_secs(300),
        exchange: Duration::from_secs(4),
        connect: Duration::from_secs(2),
        request: Duration::from_secs(3),
        request_body: 8192,
        response_body: 8192,
        headers: 64,
        header_name: 128,
        header_value: 4096,
        addresses: 16,
    };

    /// The command line's discovery and probe checks: one or two requests,
    /// and a discovery document of up to 32 KiB.
    pub const DIAGNOSTIC: Self = Self {
        calls: 2,
        budget: Duration::from_secs(30),
        exchange: Duration::from_secs(10),
        connect: Duration::from_secs(3),
        request: Duration::from_secs(8),
        request_body: 8192,
        response_body: 32_768,
        headers: 64,
        header_name: 128,
        header_value: 4096,
        addresses: 16,
    };
}

/// Which requests a transport may send: an exact list, never an origin.
pub trait Destinations {
    /// Whether the transport may send `method` to `url`.
    fn permits(&self, method: &str, url: &str) -> bool;
}

/// A bounded transport for the requests `target` permits.
///
/// Used from a dedicated thread: each call blocks on `runtime`.
pub struct Bounded<D> {
    pub target: D,
    limits: Limits,
    runtime: tokio::runtime::Handle,
    local: bool,
    started: Instant,
    calls: Mutex<usize>,
    pub observed: Mutex<Vec<HttpResponse>>,
}

impl<D: Destinations> Bounded<D> {
    /// A transport for `target`, within `limits`; `local` admits explicit
    /// HTTP loopback endpoints.
    pub fn with_limits(
        target: D,
        limits: Limits,
        local: bool,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            target,
            limits,
            local,
            runtime,
            started: Instant::now(),
            calls: Mutex::new(0),
            observed: Mutex::new(Vec::new()),
        }
    }

    /// The last response, which the transport keeps for assertions only.
    pub fn last(&self) -> Option<HttpResponse> {
        self.observed.lock().ok()?.last().cloned()
    }

    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ()> {
        let limits = self.limits;
        let url = endpoint(&request.url, self.local).map_err(|_| ())?;
        let host = url.host_str().ok_or(())?;
        let port = url.port_or_known_default().ok_or(())?;
        let addresses = if url.scheme() == "http" {
            let address = if host == "[::1]" {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            };
            vec![SocketAddr::new(address, port)]
        } else {
            let addresses: Vec<_> = tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| ())?
                .take(limits.addresses + 1)
                .collect();
            if addresses.is_empty()
                || addresses.len() > limits.addresses
                || addresses.iter().any(|a| !gnap_net::public_ip(a.ip()))
            {
                return Err(());
            }
            addresses
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .https_only(url.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            .resolve_to_addrs(host, &addresses)
            .connect_timeout(limits.connect)
            .timeout(limits.request)
            .build()
            .map_err(|_| ())?;
        let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|_| ())?;
        let mut outgoing = client.request(method, url);
        for (name, value) in request.headers {
            outgoing = outgoing.header(name, value);
        }
        if let Some(body) = request.body {
            outgoing = outgoing.body(body);
        }
        let mut response = outgoing.send().await.map_err(|_| ())?;
        let status = response.status().as_u16();
        let headers: Vec<_> = response
            .headers()
            .iter()
            .map(|(n, v)| {
                v.to_str()
                    .map(|v| (n.to_string(), v.to_owned()))
                    .map_err(|_| ())
            })
            .collect::<Result<_, _>>()?;
        if headers.len() > limits.headers
            || headers
                .iter()
                .any(|(n, v)| n.len() > limits.header_name || v.len() > limits.header_value)
            || response
                .content_length()
                .is_some_and(|n| n > limits.response_body as u64)
        {
            return Err(());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            if body.len() + chunk.len() > limits.response_body {
                return Err(());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

impl<D: Destinations> HttpTransport for Bounded<D> {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        const ERROR: &str = "Lifecycle network operation unavailable";
        let limits = self.limits;
        self.observed.lock().map_err(|_| ERROR)?.clear();
        if !self.target.permits(&request.method, &request.url)
            || request
                .body
                .as_ref()
                .is_some_and(|b| b.len() > limits.request_body)
            || self.started.elapsed() >= limits.budget
        {
            return Err(ERROR);
        }
        {
            let mut calls = self.calls.lock().map_err(|_| ERROR)?;
            if *calls >= limits.calls {
                return Err(ERROR);
            }
            *calls += 1;
        }
        let remaining = limits
            .budget
            .checked_sub(self.started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ERROR)?;
        let response = self
            .runtime
            .block_on(async {
                tokio::time::timeout(remaining.min(limits.exchange), self.request(request))
                    .await
                    .map_err(|_| ())?
            })
            .map_err(|_| ERROR)?;
        // Keep only the most recent bounded response for the independent
        // assertion layer. It is never part of a downloadable report.
        let mut observed = self.observed.lock().map_err(|_| ERROR)?;
        observed.clear();
        observed.push(response.clone());
        Ok(response)
    }
}

/// A canonical endpoint: no credentials, query, or fragment, and HTTPS on
/// port 443 to a public DNS name, or HTTP loopback when `local` allows it.
pub fn endpoint(raw: &str, local: bool) -> Result<Url, &'static str> {
    let url = Url::parse(raw).map_err(|_| "Invalid lifecycle endpoint")?;
    if raw.len() > 2048
        || url.as_str() != raw
        || !url.username().is_empty()
        || url.password().is_some()
        || raw
            .split("://")
            .nth(1)
            .is_some_and(|s| s.split('/').next().is_some_and(|a| a.contains('@')))
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Lifecycle endpoint must be canonical without credentials, query or fragment");
    }
    if local && url.scheme() == "http" && loopback(&url) {
        return Ok(url);
    }
    let host = url.host_str().ok_or("Lifecycle endpoint needs a host")?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !host.contains('.')
        || host.starts_with('[')
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return Err("Lifecycle HTTPS endpoint requires a public DNS name on port 443");
    }
    Ok(url)
}

/// Whether a URL names the loopback host.
pub fn loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}
