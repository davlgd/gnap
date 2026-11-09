//! The `gnap-conformance` binary: its usage errors, which send nothing, and
//! a real exchange through the bounded transport with a loopback server.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_gnap-conformance"))
}

#[test]
fn usage_errors_exit_with_two_before_any_network() {
    for arguments in [
        vec![],
        vec!["discover"],
        vec!["unknown", "https://as.example/gnap"],
        vec!["discover", "https://as.example/gnap", "--unknown"],
        vec!["discover", "http://as.example/gnap"],
        vec!["discover", "https://as.example/gnap?query=1"],
        vec!["discover", "http://127.0.0.1:9/gnap"],
    ] {
        let output = cli().args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            output.stdout.is_empty(),
            "{arguments:?}: a usage error prints no report"
        );
    }
    // A refusal repeats none of its input: not a secret in the endpoint, nor
    // a terminal control character.
    for arguments in [
        vec!["discover", "https://user:SYNTHETIC_SECRET@as.example/gnap"],
        vec!["discover", "https://as.example/gnap?token=SYNTHETIC_SECRET"],
        vec!["discover", "https://as.example/gnap#SYNTHETIC_SECRET"],
        vec![
            "discover",
            "https://as.example/gnap",
            "--SYNTHETIC_SECRET\u{1b}[31m",
        ],
        vec!["SYNTHETIC_SECRET\u{1b}[31m", "https://as.example/gnap"],
    ] {
        let output = cli().args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        for stream in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(stream);
            assert!(
                !text.contains("SYNTHETIC_SECRET") && !text.contains('\u{1b}'),
                "{text}"
            );
        }
    }
    // An argument that isn't Unicode is refused without a panic or an echo.
    {
        use std::os::unix::ffi::OsStrExt as _;
        let mut raw = b"https://as.example/gnap?SYNTHETIC_SECRET=".to_vec();
        raw.push(0xff);
        let output = cli()
            .arg("discover")
            .arg(std::ffi::OsStr::from_bytes(&raw))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_SECRET"));
    }
    let help = cli().arg("--help").output().unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("discover"));
}

#[test]
fn discover_checks_a_loopback_server_through_the_bounded_transport() {
    let body = "{\"grant_request_endpoint\":\"ENDPOINT\"}";
    // The document has to announce the endpoint it was queried at.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!(
        "http://127.0.0.1:{}/gnap",
        listener.local_addr().unwrap().port()
    );
    let document = body.replace("ENDPOINT", &endpoint);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{document}",
        document.len()
    );
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
        String::from_utf8_lossy(&buffer[..read]).into_owned()
    });
    let output = cli()
        .args(["discover", &endpoint, "--json", "--allow-loopback-http"])
        .output()
        .unwrap();
    let request = server.join().unwrap();
    assert!(request.starts_with("OPTIONS /gnap HTTP/1.1"), "{request}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "gnap-conformance/1");
    assert_eq!(report["target"], endpoint);
    let endpoint_match = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "discovery-endpoint-match")
        .unwrap();
    assert_eq!(endpoint_match["outcome"], "passed", "{report}");
    // A loopback HTTP endpoint is nonconformant discovery, so the endpoint
    // check fails and the exit code says so.
    assert_eq!(output.status.code(), Some(1), "{report}");
}
