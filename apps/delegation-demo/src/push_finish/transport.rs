//! One bounded delivery attempt to this deployment's pre-registered callback.
//!
//! The caller commits the interaction and checks slot/client ownership before
//! calling this module. Neither failure nor uncertainty rolls that commit back.
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

const BODY_LIMIT: usize = 1024;
const DEADLINE: Duration = Duration::from_secs(4);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Delivery {
    Delivered,
    Uncertain,
    RefusedBeforeSend,
}

impl Delivery {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Uncertain => "uncertain",
            Self::RefusedBeforeSend => "refused_before_send",
        }
    }
}

struct Target {
    url: reqwest::Url,
    development: bool,
}

impl Target {
    fn parse(origin: &str, callback: &str) -> Option<Self> {
        crate::CanonicalOrigin::parse(origin).ok()?;
        let prefix = format!("{origin}/push-callback/");
        let slot = callback.strip_prefix(&prefix)?;
        if slot.len() != 22
            || !slot
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return None;
        }
        let url = reqwest::Url::parse(callback).ok()?;
        // Do not silently accept URL-parser normalization, even on loopback.
        if url.as_str() != callback {
            return None;
        }
        Some(Self {
            development: url.scheme() == "http",
            url,
        })
    }

    async fn addresses(&self) -> Option<Vec<SocketAddr>> {
        let host = self.url.host_str()?;
        let port = self.url.port_or_known_default()?;
        if self.development {
            // No DNS, including for localhost. Preserve that hostname in the
            // HTTP request while connecting only to its fixed local address.
            return local_address(host, port).map(|address| vec![address]);
        }
        let literal = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>();
        let addresses = if let Ok(ip) = literal {
            vec![SocketAddr::new(ip, port)]
        } else {
            tokio::net::lookup_host((host, port))
                .await
                .ok()?
                .take(17)
                .collect()
        };
        checked_public_addresses(addresses)
    }
}

fn local_address(host: &str, port: u16) -> Option<SocketAddr> {
    let ip = match host {
        "127.0.0.1" | "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
        "[::1]" => IpAddr::V6(Ipv6Addr::LOCALHOST),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn checked_public_addresses(addresses: Vec<SocketAddr>) -> Option<Vec<SocketAddr>> {
    (!addresses.is_empty()
        && addresses.len() <= 16
        && addresses
            .iter()
            .all(|address| gnap_net::public_ip(address.ip())))
    .then_some(addresses)
}

pub(super) async fn send(origin: &str, callback_uri: &str, body: Vec<u8>) -> Delivery {
    if body.len() > BODY_LIMIT {
        return Delivery::RefusedBeforeSend;
    }
    let Some(target) = Target::parse(origin, callback_uri) else {
        return Delivery::RefusedBeforeSend;
    };
    // Covers DNS, connection, TLS, request and the entire response body. A
    // timeout is conservatively uncertain, even if it may have preceded send.
    tokio::time::timeout(DEADLINE, attempt(target, body))
        .await
        .unwrap_or(Delivery::Uncertain)
}

async fn attempt(target: Target, body: Vec<u8>) -> Delivery {
    let Some(addresses) = target.addresses().await else {
        return Delivery::RefusedBeforeSend;
    };
    let Some(host) = target.url.host_str() else {
        return Delivery::RefusedBeforeSend;
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .https_only(!target.development)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .resolve_to_addrs(host, &addresses)
        .connect_timeout(Duration::from_secs(2))
        .timeout(DEADLINE)
        .pool_max_idle_per_host(0)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build();
    let Ok(client) = client else {
        return Delivery::RefusedBeforeSend;
    };
    // A fresh client has no cookie store or credentials. The checked URL
    // cannot contain userinfo; caller-supplied headers are never accepted.
    let response = client
        .post(target.url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await;
    let Ok(mut response) = response else {
        return Delivery::Uncertain;
    };
    let success = response.status().is_success();
    if response
        .content_length()
        .is_some_and(|length| length > BODY_LIMIT as u64)
    {
        return Delivery::Uncertain;
    }
    let mut received = 0;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if chunk.len() <= BODY_LIMIT - received => received += chunk.len(),
            Ok(None) => break,
            Ok(Some(_)) | Err(_) => return Delivery::Uncertain,
        }
    }
    if success {
        Delivery::Delivered
    } else {
        Delivery::Uncertain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Bytes,
        http::{HeaderMap, StatusCode},
        routing::post,
        Router,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const SLOT: &str = "abcdefghijklmnopqrstuv";

    #[test]
    fn callback_scope_is_exact_and_never_normalized() {
        for origin in [
            "https://demo.example",
            "https://demo.example:8443",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(Target::parse(origin, &format!("{origin}/push-callback/{SLOT}")).is_some());
        }
        for origin in [
            "http://demo.example",
            "http://127.1",
            "http://2130706433",
            "http://LOCALHOST",
            "https://DEMO.example",
            "https://demo.example:443",
            "https://demo.example/",
            "https://user@demo.example",
            "https://demo.example?x",
            "https://demo.example#x",
        ] {
            assert!(Target::parse(origin, &format!("{origin}/push-callback/{SLOT}")).is_none());
        }
        let origin = "https://demo.example";
        for uri in [
            format!("https://other.example/push-callback/{SLOT}"),
            format!("{origin}:8443/push-callback/{SLOT}"),
            format!("{origin}/push-callback/{SLOT}?x"),
            format!("{origin}/push-callback/{SLOT}#x"),
            format!("{origin}/push-callback/../{SLOT}"),
            format!("{origin}/push-callback/%61bcdefghijklmnopqrstuv"),
            format!("{origin}/push-callback/{SLOT}/"),
            format!("{origin}/push-callback/short"),
            format!("{origin}/push-callback/abcdefghijklmnopqrstu+"),
        ] {
            assert!(Target::parse(origin, &uri).is_none());
        }
    }

    #[tokio::test]
    async fn address_policy_checks_every_result_and_confines_development() {
        let public: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let private: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert!(checked_public_addresses(vec![]).is_none());
        assert!(checked_public_addresses(vec![public; 16]).is_some());
        assert!(checked_public_addresses(vec![public; 17]).is_none());
        assert!(checked_public_addresses(vec![public, private]).is_none());
        for host in ["127.0.0.2", "localtest.me", "::1", "[::ffff:127.0.0.1]"] {
            assert!(local_address(host, 8080).is_none());
        }
        for (origin, expected) in [
            ("http://localhost:8080", "127.0.0.1:8080"),
            ("http://[::1]:8080", "[::1]:8080"),
        ] {
            let target = Target::parse(origin, &format!("{origin}/push-callback/{SLOT}")).unwrap();
            assert_eq!(
                target.addresses().await.unwrap(),
                [expected.parse::<SocketAddr>().unwrap()]
            );
        }
        for origin in [
            "https://127.0.0.1",
            "https://[::1]",
            "https://169.254.169.254",
        ] {
            assert_eq!(
                send(origin, &format!("{origin}/push-callback/{SLOT}"), vec![]).await,
                Delivery::RefusedBeforeSend
            );
        }
        assert_eq!(
            send(
                "https://demo.example",
                &format!("https://demo.example/push-callback/{SLOT}"),
                vec![0; BODY_LIMIT + 1]
            )
            .await,
            Delivery::RefusedBeforeSend
        );
    }

    #[tokio::test]
    async fn local_post_keeps_exact_body_and_never_follows_redirects() {
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        let redirected = calls.clone();
        let router = Router::new()
            .route(
                "/push-callback/{slot}",
                post(move |headers: HeaderMap, body: Bytes| {
                    recorded.fetch_add(1, Ordering::SeqCst);
                    async move {
                        assert_eq!(headers["content-type"], "application/json");
                        for name in ["authorization", "cookie", "referer"] {
                            assert!(!headers.contains_key(name));
                        }
                        assert!(headers["host"].to_str().unwrap().starts_with("localhost:"));
                        match body.as_ref() {
                            b"{ \"hash\": \"unchanged\" }" => (
                                StatusCode::NO_CONTENT,
                                [("location", "/unexpected")],
                                vec![],
                            ),
                            b"redirect" => (
                                StatusCode::TEMPORARY_REDIRECT,
                                [("location", "/unexpected")],
                                vec![],
                            ),
                            b"boundary" => (
                                StatusCode::OK,
                                [("location", "/unexpected")],
                                vec![0; BODY_LIMIT],
                            ),
                            b"oversized" => (
                                StatusCode::OK,
                                [("location", "/unexpected")],
                                vec![0; BODY_LIMIT + 1],
                            ),
                            _ => panic!("unexpected outbound body"),
                        }
                    }
                }),
            )
            .route(
                "/unexpected",
                post(move || {
                    redirected.fetch_add(1, Ordering::SeqCst);
                    async { StatusCode::NO_CONTENT }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://localhost:{}", listener.local_addr().unwrap().port());
        let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let uri = format!("{origin}/push-callback/{SLOT}");
        for (body, expected) in [
            (
                b"{ \"hash\": \"unchanged\" }".as_slice(),
                Delivery::Delivered,
            ),
            (b"redirect".as_slice(), Delivery::Uncertain),
            (b"boundary".as_slice(), Delivery::Delivered),
            (b"oversized".as_slice(), Delivery::Uncertain),
        ] {
            assert_eq!(send(&origin, &uri, body.to_vec()).await, expected);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        serving.abort();
        let _ = serving.await;
    }

    #[tokio::test]
    async fn a_slow_response_is_uncertain_without_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        let router = Router::new().route(
            "/push-callback/{slot}",
            post(move || {
                recorded.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_secs(8)).await;
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let started = std::time::Instant::now();
        assert_eq!(
            send(&origin, &format!("{origin}/push-callback/{SLOT}"), vec![]).await,
            Delivery::Uncertain
        );
        assert!(started.elapsed() < Duration::from_secs(6));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        serving.abort();
        let _ = serving.await;
    }

    #[tokio::test]
    async fn response_chunks_and_body_wait_are_bounded_after_success_headers() {
        use std::io::{Read, Write};
        for slow in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let (finished, completion) = std::sync::mpsc::channel();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut received = Vec::new();
                while !received.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let mut chunk = [0; 512];
                    let count = socket.read(&mut chunk).unwrap();
                    assert!(count > 0 && received.len() + count <= 4096);
                    received.extend_from_slice(&chunk[..count]);
                }
                if slow {
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                    socket.flush().unwrap();
                    // Stop immediately after the client's four-second timeout;
                    // no orphan server or extra eight-second join is needed.
                    let _ = completion.recv_timeout(Duration::from_secs(8));
                } else {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n401\r\n").unwrap();
                    socket.write_all(&vec![0; BODY_LIMIT + 1]).unwrap();
                    socket.write_all(b"\r\n0\r\n\r\n").unwrap();
                }
            });
            let outcome = send(&origin, &format!("{origin}/push-callback/{SLOT}"), vec![]).await;
            let _ = finished.send(());
            server.join().unwrap();
            assert_eq!(outcome, Delivery::Uncertain);
        }
    }
}
