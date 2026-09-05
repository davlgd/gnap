//! Real OS processes and HTTP, including a live-channel outage after success.
use gnap_biscuit_files::{
    config::{self, Config},
    http::Network,
    resource_check,
};
use gnap_client::HttpTransport;
use serde_json::{json, Value};
use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Processes {
    children: Vec<Child>,
    keys: PathBuf,
}
impl Drop for Processes {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.keys);
    }
}
fn port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn start(binary: &str, port: u16, origins: &[String; 3], keys: &std::path::Path) -> Child {
    Command::new(binary)
        .env_clear()
        .env("PORT", port.to_string())
        .env("AS_ORIGIN", &origins[0])
        .env("RS_ORIGIN", &origins[1])
        .env("CLIENT_ORIGIN", &origins[2])
        .env("KEY_DIRECTORY", keys)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}
fn start_environment(
    binary: &str,
    port: u16,
    origins: &[String; 3],
    keys: &std::path::Path,
    role: config::Role,
) -> Child {
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("PORT", port.to_string())
        .env("AS_ORIGIN", &origins[0])
        .env("RS_ORIGIN", &origins[1])
        .env("CLIENT_ORIGIN", &origins[2])
        .env("KEY_SOURCE", "environment")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let material = match role {
        config::Role::As => vec![
            ("BISCUIT_AS_ROOT_PRIVATE_KEY_HEX", "root.key"),
            ("BISCUIT_AS_CLIENT_PUBLIC_JWK", "client.jwk"),
            ("BISCUIT_AS_RS_PUBLIC_JWK", "rs.jwk"),
        ],
        config::Role::Rs => vec![
            ("BISCUIT_RS_PRIVATE_KEY_PEM", "rs.pem"),
            ("BISCUIT_RS_ROOT_PUBLIC_KEY_HEX", "root.pub"),
        ],
        config::Role::Client => vec![
            ("BISCUIT_CLIENT_PRIVATE_KEY_PEM", "client.pem"),
            ("BISCUIT_CLIENT_ROOT_PUBLIC_KEY_HEX", "root.pub"),
        ],
    };
    // These files belong to the test fixture. The child receives only its
    // role's environment values, no KEY_DIRECTORY and no key-file path.
    for (name, file) in material {
        command.env(name, std::fs::read_to_string(keys.join(file)).unwrap());
    }
    command.spawn().unwrap()
}
fn ready(client: &reqwest::blocking::Client, url: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if client
            .get(format!("{url}/health"))
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("local process did not become ready");
}
fn action(
    client: &reqwest::blocking::Client,
    origin: &str,
    cookie: &str,
    name: &str,
    body: Value,
) -> (String, Value) {
    let response = client
        .post(format!("{origin}/action/{name}"))
        .header("origin", origin)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap())
        .send()
        .unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .to_owned();
    let bytes = response.bytes().unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status.as_u16(), 200, "operation {name} failed: {value}");
    (cookie, value)
}

/// Two backend listeners can serve the same configured public authority, as
/// behind a reverse proxy. The signed target stays the public URI, not backend.
fn resource_call(
    client: &reqwest::blocking::Client,
    request: &gnap_client::HttpRequest,
    backend: &str,
    public_authority: &str,
) -> u16 {
    let path = reqwest::Url::parse(&request.url).unwrap().path().to_owned();
    let mut call = client
        .request(
            reqwest::Method::from_bytes(request.method.as_bytes()).unwrap(),
            format!("{backend}{path}"),
        )
        .header("host", public_authority);
    for (name, value) in &request.headers {
        call = call.header(name, value);
    }
    if let Some(body) = &request.body {
        call = call.body(body.clone());
    }
    call.send().unwrap().status().as_u16()
}

#[test]
fn three_process_flow_and_authority_outage_fail_closed() {
    let keys = std::env::temp_dir().join(format!(
        "gnap-biscuit-files-test-{}",
        gnap_crypto::httpsig::fresh_nonce().unwrap()
    ));
    config::initialize(&keys).unwrap();
    let ports = [port(), port(), port()];
    assert!(ports[0] != ports[1] && ports[0] != ports[2] && ports[1] != ports[2]);
    let origins = ports.map(|p| format!("http://127.0.0.1:{p}"));
    let mut processes = Processes {
        children: vec![],
        keys,
    };
    for (binary, p) in [
        env!("CARGO_BIN_EXE_as"),
        env!("CARGO_BIN_EXE_rs"),
        env!("CARGO_BIN_EXE_client"),
    ]
    .into_iter()
    .zip(ports)
    {
        processes
            .children
            .push(start(binary, p, &origins, &processes.keys));
    }
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for origin in &origins {
        ready(&client, origin);
    }
    assert_eq!(
        client
            .get(format!("{}/files/notes", origins[1]))
            .send()
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(format!("{}/files/notes", origins[1]))
            .header("host", "unexpected.example")
            .header("forwarded", format!("host={}", &origins[1][7..]))
            .send()
            .unwrap()
            .status(),
        421
    );
    assert_eq!(
        client
            .post(format!("{}/action/start", origins[2]))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(format!("{}/action/read", origins[2]))
            .header("origin", &origins[2])
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .unwrap()
            .status(),
        401
    );
    let (cookie, _) = action(&client, &origins[2], "", "start", json!({}));
    assert!(!cookie.is_empty());
    for (name, expected) in [
        ("read", 200),
        ("write", 200),
        ("read-draft", 403),
        ("write-notes", 403),
    ] {
        assert_eq!(
            action(&client, &origins[2], &cookie, name, json!({})).1["status"],
            expected
        );
    }
    action(
        &client,
        &origins[2],
        &cookie,
        "attenuate",
        json!({"file":"notes","seconds":120}),
    );
    assert_eq!(
        action(&client, &origins[2], &cookie, "read", json!({})).1["status"],
        200
    );
    assert_eq!(
        action(&client, &origins[2], &cookie, "write", json!({})).1["status"],
        403
    );
    action(&client, &origins[2], &cookie, "rotate", json!({}));
    assert_eq!(
        action(&client, &origins[2], &cookie, "check-retired", json!({})).1["status"],
        403
    );
    assert_eq!(
        action(&client, &origins[2], &cookie, "read", json!({})).1["status"],
        200
    );
    action(
        &client,
        &origins[2],
        &cookie,
        "attenuate",
        json!({"file":"notes","seconds":120}),
    );
    action(&client, &origins[2], &cookie, "revoke", json!({}));
    assert_eq!(
        action(&client, &origins[2], &cookie, "check-retired", json!({})).1["status"],
        403
    );

    let values = std::collections::BTreeMap::from([
        ("AS_ORIGIN", origins[0].clone()),
        ("RS_ORIGIN", origins[1].clone()),
        ("CLIENT_ORIGIN", origins[2].clone()),
        ("KEY_DIRECTORY", processes.keys.to_str().unwrap().to_owned()),
    ]);
    let load = |role| {
        Config::load_with(
            role,
            |name| values.get(name).cloned(),
            |name| values.contains_key(name),
            |path| std::fs::read_to_string(path).map_err(|_| config::ConfigError::Keys),
        )
        .unwrap()
    };
    let config = load(config::Role::Client);
    let rs_config = load(config::Role::Rs);
    let network = Network::new(config.as_origin.clone()).unwrap();
    let endpoint = format!("{}/resource-check", origins[0]);
    let now = gnap_biscuit_files::now().unwrap();
    let wrong = resource_check::check_request(
        &endpoint,
        &[9; 64],
        "resource-nonce",
        now,
        &config.signer("client").unwrap(),
        now,
    )
    .unwrap();
    assert_eq!(network.send(wrong).unwrap().status, 401);
    let request = resource_check::check_request(
        &endpoint,
        &[9; 64],
        "resource-nonce",
        now,
        &rs_config.signer("rs").unwrap(),
        now,
    )
    .unwrap();
    let response = network.send(request.clone()).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        resource_check::check_response(
            &response,
            &request,
            &resource_check::request_nonce(&request).unwrap()
        ),
        gnap_biscuit::LiveDecision::Denied
    );
    assert_eq!(network.send(request).unwrap().status, 401);

    // Obtain a real token independently of the UI, retaining one exact signed
    // descendant request to replay after the OS process is restarted.
    let client_key = config.signer("client").unwrap();
    let mut session =
        gnap_client::Session::new(&network, &client_key, format!("{}/gnap", origins[0]));
    let step = session
        .start(
            &gnap_biscuit_files::client::grant(&client_key, &origins[1]).unwrap(),
            gnap_biscuit_files::now().unwrap(),
        )
        .unwrap();
    let parent = &step.response().access_token.as_ref().unwrap().tokens[0].value;
    let mut empty_put = gnap_client::HttpRequest::new("PUT", format!("{}/files/draft", origins[1]))
        .header("content-type", "text/plain");
    empty_put.body = Some(Vec::new());
    let empty_put = gnap_client::sign_request(
        empty_put,
        &client_key,
        Some(parent),
        gnap_biscuit_files::now().unwrap(),
    )
    .unwrap();
    assert_eq!(
        resource_call(&client, &empty_put, &origins[1], &origins[1][7..]),
        200,
        "a signed empty PUT must reach RS as an explicit empty body"
    );
    let descendant = gnap_biscuit::VerifiedToken::from_token(parent, &config.roots().unwrap())
        .unwrap()
        .attenuate(Some(&format!("{}/files/notes", origins[1])), None)
        .unwrap();
    let resource_request = || {
        gnap_client::sign_request(
            gnap_client::HttpRequest::new("GET", format!("{}/files/notes", origins[1])),
            &client_key,
            Some(&descendant),
            gnap_biscuit_files::now().unwrap(),
        )
        .unwrap()
    };
    let public_authority = &origins[1][7..];
    let exact = resource_request();
    assert_eq!(
        resource_call(&client, &exact, &origins[1], public_authority),
        200
    );
    processes.children[1].kill().unwrap();
    processes.children[1].wait().unwrap();
    processes.children[1] = start(
        env!("CARGO_BIN_EXE_rs"),
        ports[1],
        &origins,
        &processes.keys,
    );
    ready(&client, &origins[1]);
    assert_eq!(
        resource_call(&client, &exact, &origins[1], public_authority),
        403,
        "RS restart must not reopen a spent request"
    );
    assert_eq!(
        resource_call(&client, &resource_request(), &origins[1], public_authority),
        200,
        "a fresh proof with the same still-active authority remains usable"
    );

    let second_port = port();
    let second_backend = format!("http://127.0.0.1:{second_port}");
    processes.children.push(start(
        env!("CARGO_BIN_EXE_rs"),
        second_port,
        &origins,
        &processes.keys,
    ));
    ready(&client, &second_backend);
    let exact = resource_request();
    let mut outcomes = std::thread::scope(|scope| {
        let first = scope.spawn(|| resource_call(&client, &exact, &origins[1], public_authority));
        let second =
            scope.spawn(|| resource_call(&client, &exact, &second_backend, public_authority));
        vec![first.join().unwrap(), second.join().unwrap()]
    });
    outcomes.sort_unstable();
    assert_eq!(
        outcomes,
        [200, 403],
        "two RS instances must reserve a client nonce only once at their shared AS"
    );

    let (cookie, _) = action(&client, &origins[2], "", "start", json!({}));
    assert_eq!(
        action(&client, &origins[2], &cookie, "read", json!({})).1["status"],
        200
    );
    processes.children[0].kill().unwrap();
    processes.children[0].wait().unwrap();
    let refused = client
        .post(format!("{}/action/rotate", origins[2]))
        .header("origin", &origins[2])
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .unwrap();
    assert_eq!(refused.status(), 400);
    assert_eq!(
        action(&client, &origins[2], &cookie, "status", json!({})).1["retired_available"],
        false,
        "a failed management call must not label the current token retired"
    );
    assert_eq!(
        action(&client, &origins[2], &cookie, "read", json!({})).1["status"],
        503,
        "a previous positive status must not survive loss of the AS"
    );
    processes.children[0] = start(
        env!("CARGO_BIN_EXE_as"),
        ports[0],
        &origins,
        &processes.keys,
    );
    ready(&client, &origins[0]);
    assert_eq!(
        resource_call(&client, &resource_request(), &origins[1], public_authority),
        403,
        "AS restart drops authorities as well as reservations"
    );
    let (cookie, _) = action(&client, &origins[2], "", "start", json!({}));
    assert_eq!(
        action(&client, &origins[2], &cookie, "read", json!({})).1["status"],
        200
    );
    // Start all three roles with the deployment-oriented environment contract.
    // Their previous in-memory grants/sessions disappear as expected.
    for child in &mut processes.children {
        let _ = child.kill();
        let _ = child.wait();
    }
    processes.children.clear();
    for (binary, port, role) in [
        (env!("CARGO_BIN_EXE_as"), ports[0], config::Role::As),
        (env!("CARGO_BIN_EXE_rs"), ports[1], config::Role::Rs),
        (env!("CARGO_BIN_EXE_client"), ports[2], config::Role::Client),
    ] {
        processes.children.push(start_environment(
            binary,
            port,
            &origins,
            &processes.keys,
            role,
        ));
    }
    for origin in &origins {
        ready(&client, origin);
    }
    let (cookie, _) = action(&client, &origins[2], "", "start", json!({}));
    assert_eq!(
        action(&client, &origins[2], &cookie, "read", json!({})).1["status"],
        200
    );
    assert_eq!(
        action(&client, &origins[2], &cookie, "write", json!({})).1["status"],
        200
    );
}

#[test]
fn each_role_serves_localhost_and_ipv6_without_binding_other_interfaces() {
    let keys = std::env::temp_dir().join(format!(
        "gnap-biscuit-listeners-{}",
        gnap_crypto::httpsig::fresh_nonce().unwrap()
    ));
    config::initialize(&keys).unwrap();
    let mut processes = Processes {
        children: vec![],
        keys,
    };
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    for (index, binary) in [
        env!("CARGO_BIN_EXE_as"),
        env!("CARGO_BIN_EXE_rs"),
        env!("CARGO_BIN_EXE_client"),
    ]
    .into_iter()
    .enumerate()
    {
        for host in ["localhost", "[::1]"] {
            let probe = TcpListener::bind((if host == "[::1]" { "::1" } else { "127.0.0.1" }, 0))
                .expect("listener regression requires IPv4 and IPv6 loopback");
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            // A wrong role's HTTPS origin would select a wildcard IPv4 bind.
            let mut origins = [
                "https://as.example".into(),
                "https://rs.example".into(),
                "https://client.example".into(),
            ];
            origins[index] = format!("http://{host}:{port}");
            processes
                .children
                .push(start(binary, port, &origins, &processes.keys));
            ready(&client, &origins[index]);
            // A forged canonical Host cannot turn an IPv4 wildcard destination
            // into a loopback-only listener. No LAN address or traffic is used.
            // Linux routes 127/8 to loopback, so this catches a wildcard bind
            // in CI. macOS may not configure 127.0.0.2: there, the local_addr
            // assertions in config's socket test establish the bind boundary.
            assert!(
                client
                    .get(format!("http://127.0.0.2:{port}/health"))
                    .header("host", format!("{host}:{port}"))
                    .send()
                    .is_err(),
                "local mode accepted a connection through another address"
            );
            let child = processes.children.last_mut().unwrap();
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }
}
