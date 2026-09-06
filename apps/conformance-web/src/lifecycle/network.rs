use super::config::{self, Target};
use gnap_client::{HttpRequest, HttpResponse, HttpTransport};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

/// Used only on the lifecycle's dedicated worker thread. The async bridge
/// bounds DNS as well as TLS and streaming response reads within one deadline.
pub struct Network {
    pub target: Target,
    runtime: tokio::runtime::Handle,
    local: bool,
    started: Instant,
    calls: Mutex<usize>,
    pub observed: Mutex<Vec<HttpResponse>>,
}

impl Network {
    pub fn new(target: Target, local: bool, runtime: tokio::runtime::Handle) -> Self {
        Self {
            target,
            local,
            runtime,
            started: Instant::now(),
            calls: Mutex::new(0),
            observed: Mutex::new(Vec::new()),
        }
    }

    pub fn last(&self) -> Option<HttpResponse> {
        self.observed.lock().ok()?.last().cloned()
    }

    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ()> {
        let url = config::endpoint(&request.url, self.local).map_err(|_| ())?;
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
                .take(17)
                .collect();
            if addresses.is_empty()
                || addresses.len() > 16
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
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
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
        if headers.len() > 64
            || headers.iter().any(|(n, v)| n.len() > 128 || v.len() > 4096)
            || response.content_length().is_some_and(|n| n > 8192)
        {
            return Err(());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            if body.len() + chunk.len() > 8192 {
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

impl HttpTransport for Network {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        const ERROR: &str = "Lifecycle network operation unavailable";
        self.observed.lock().map_err(|_| ERROR)?.clear();
        if !self.target.permits(&request.method, &request.url)
            || request.body.as_ref().is_some_and(|b| b.len() > 8192)
            || self.started.elapsed() >= Duration::from_secs(300)
        {
            return Err(ERROR);
        }
        {
            let mut calls = self.calls.lock().map_err(|_| ERROR)?;
            if *calls >= 16 {
                return Err(ERROR);
            }
            *calls += 1;
        }
        let remaining = Duration::from_secs(300)
            .checked_sub(self.started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ERROR)?;
        let response = self
            .runtime
            .block_on(async {
                tokio::time::timeout(remaining.min(Duration::from_secs(4)), self.request(request))
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
