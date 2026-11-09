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
    /// Total time the transport may spend, from its first request, so that
    /// a transport created ahead of its phase keeps its whole budget.
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

    /// Cleanup after a command-line scenario: a reserved budget that the
    /// scenario's own calls never spend.
    pub const CLEANUP: Self = Self {
        calls: 2,
        budget: Duration::from_secs(10),
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

    /// A command-line scenario that waits up to `wait` for an operator:
    /// `wait` plus two minutes of exchanges, within at most 32 calls.
    #[must_use]
    pub const fn scenario(wait: Duration) -> Self {
        Self {
            calls: 32,
            budget: Duration::from_secs(wait.as_secs() + 120),
            ..Self::LIFECYCLE
        }
    }

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

/// Exactly one request: one method to one URL, compared byte for byte.
#[derive(Debug, Clone)]
pub struct Exact {
    pub method: &'static str,
    pub url: String,
}

impl Destinations for Exact {
    fn permits(&self, method: &str, url: &str) -> bool {
        method == self.method && url == self.url
    }
}

impl<D: Destinations + ?Sized> Destinations for std::sync::Arc<D> {
    fn permits(&self, method: &str, url: &str) -> bool {
        (**self).permits(method, url)
    }
}

/// Requests admitted one by one: the command's own, then the exact URIs a
/// scenario reads from responses it accepted, when they share the grant
/// endpoint's origin. An origin is never admitted as a whole.
#[derive(Debug)]
pub struct Admitted {
    origin: String,
    local: bool,
    exact: Mutex<Vec<(&'static str, String)>>,
}

impl Admitted {
    /// The admissions of a scenario against `grant`, which must be a
    /// canonical [`endpoint`].
    ///
    /// # Errors
    ///
    /// Fails for an endpoint [`endpoint`] refuses.
    pub fn new(grant: &str, local: bool) -> Result<Self, &'static str> {
        let origin = endpoint(grant, local)?.origin().ascii_serialization();
        Ok(Self {
            origin,
            local,
            exact: Mutex::new(Vec::new()),
        })
    }

    /// Admits `method` to `url`, which the caller supplied itself.
    pub fn allow(&self, method: &'static str, url: &str) {
        if let Ok(mut exact) = self.exact.lock() {
            exact.push((method, url.to_owned()));
        }
    }

    /// Admits `method` to a URI a response supplied, if it is a canonical
    /// endpoint of the grant endpoint's origin; returns whether it did.
    pub fn admit_same_origin(&self, method: &'static str, url: &str) -> bool {
        let same = endpoint(url, self.local)
            .is_ok_and(|parsed| parsed.origin().ascii_serialization() == self.origin);
        if same {
            self.allow(method, url);
        }
        same
    }
}

impl Destinations for Admitted {
    fn permits(&self, method: &str, url: &str) -> bool {
        self.exact
            .lock()
            .is_ok_and(|exact| exact.iter().any(|(m, u)| *m == method && u == url))
    }
}

/// Two transports in sequence: the scenario's, then, once
/// [`Phased::clean_up`] is called, a separate one with its own reserved
/// budget, so that cleanup never depends on what the scenario spent.
pub struct Phased<A, B> {
    scenario: A,
    cleanup: B,
    cleaning: std::sync::atomic::AtomicBool,
}

impl<A, B> Phased<A, B> {
    pub const fn new(scenario: A, cleanup: B) -> Self {
        Self {
            scenario,
            cleanup,
            cleaning: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Sends every later request through the cleanup transport.
    pub fn clean_up(&self) {
        self.cleaning
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl<A, B> HttpTransport for Phased<A, B>
where
    A: HttpTransport<Error = &'static str>,
    B: HttpTransport<Error = &'static str>,
{
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        if self.cleaning.load(std::sync::atomic::Ordering::SeqCst) {
            self.cleanup.send(request)
        } else {
            self.scenario.send(request)
        }
    }
}

/// A bounded transport for the requests `target` permits.
///
/// Used from a dedicated thread: each call blocks on `runtime`.
pub struct Bounded<D> {
    pub target: D,
    limits: Limits,
    runtime: tokio::runtime::Handle,
    local: bool,
    started: std::sync::OnceLock<Instant>,
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
            started: std::sync::OnceLock::new(),
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
        let started = *self.started.get_or_init(Instant::now);
        self.observed.lock().map_err(|_| ERROR)?.clear();
        if !self.target.permits(&request.method, &request.url)
            || request
                .body
                .as_ref()
                .is_some_and(|b| b.len() > limits.request_body)
            || started.elapsed() >= limits.budget
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
            .checked_sub(started.elapsed())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport whose runtime is never reached: every refusal below is
    /// decided before any network work.
    fn exact(runtime: &tokio::runtime::Runtime) -> Bounded<Exact> {
        Bounded::with_limits(
            Exact {
                method: "OPTIONS",
                url: "https://as.example/gnap".into(),
            },
            Limits::DIAGNOSTIC,
            false,
            runtime.handle().clone(),
        )
    }

    #[test]
    fn an_exact_destination_permits_only_its_request() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let transport = exact(&runtime);
        for (method, url) in [
            ("POST", "https://as.example/gnap"),
            ("OPTIONS", "https://as.example/gnap/"),
            ("OPTIONS", "https://as.example/continue"),
            ("OPTIONS", "https://other.example/gnap"),
            ("OPTIONS", "https://as.example/gnap?x=1"),
        ] {
            assert!(
                transport.send(HttpRequest::new(method, url)).is_err(),
                "{method} {url}"
            );
        }
        assert!(transport.last().is_none(), "nothing was sent");
    }

    /// A cleanup transport is created with the scenario, and used after it:
    /// its budget counts from its first request.
    #[test]
    fn the_budget_counts_from_the_first_request() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://127.0.0.1:{}/x",
            listener.local_addr().unwrap().port()
        );
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let transport = Bounded::with_limits(
            Exact {
                method: "DELETE",
                url: url.clone(),
            },
            Limits {
                budget: Duration::from_millis(300),
                ..Limits::CLEANUP
            },
            true,
            runtime.handle().clone(),
        );
        std::thread::sleep(Duration::from_millis(400));
        let response = transport.send(HttpRequest::new("DELETE", &url)).unwrap();
        assert_eq!(response.status, 204);
        server.join().unwrap();
    }

    #[test]
    fn the_limits_are_project_constants() {
        for limits in [Limits::LIFECYCLE, Limits::DIAGNOSTIC] {
            assert!(limits.calls > 0 && limits.exchange <= limits.budget);
            assert!(limits.connect <= limits.exchange && limits.request <= limits.exchange);
        }
        assert_eq!(
            Limits::LIFECYCLE.response_body,
            8192,
            "the workbench's bound is kept"
        );
        assert_eq!(Limits::LIFECYCLE.calls, 16);
    }
}
