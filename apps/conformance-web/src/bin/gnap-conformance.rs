//! `gnap-conformance`: selected GNAP checks against a server, from a terminal.
//!
//! Each command sends only the requests it names, to the endpoint it is
//! given, through the workbench's bounded transport. The report goes to
//! standard output, as text or as JSON, and the exit code says whether the
//! selected checks passed (0), one failed (1), or none could be decided (2).

use gnap_conformance_web::cli;
use gnap_conformance_web::net::{self, Bounded, Exact, Limits};
use std::process::ExitCode;

const USAGE: &str = "\
Usage: gnap-conformance <command> <grant-endpoint> [--json] [--allow-loopback-http]

Commands:
  discover   send OPTIONS to the grant endpoint and check its discovery document (RFC 9635 §9)
  probe      send a malformed initial grant request and check the refusal (RFC 9635 §3.6)

Options:
  --json                 print the report as JSON (schema gnap-conformance/1)
  --allow-loopback-http  accept an http://localhost, 127.0.0.1 or [::1] endpoint
  -h, --help             print this help
  -V, --version          print the version

The endpoint is HTTPS on port 443 with a public DNS name, without credentials, query or
fragment. Exit codes: 0 when every selected check that applied passed, 1 when one failed,
2 for a usage error or when no check could be decided. Passing is not certification.";

/// A command's checks, which send through the bounded transport.
type Command = fn(&Bounded<Exact>, &str, u64) -> cli::Report;

fn main() -> ExitCode {
    // `args_os`: an argument that isn't Unicode is refused without being
    // shown, where `args` would panic and print it.
    let arguments: Option<Vec<String>> = std::env::args_os()
        .skip(1)
        .map(|argument| argument.into_string().ok())
        .collect();
    let Some(arguments) = arguments else {
        eprintln!("gnap-conformance: an argument isn't valid Unicode\n\n{USAGE}");
        return ExitCode::from(2);
    };
    match run(arguments) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("gnap-conformance: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run(arguments: Vec<String>) -> Result<u8, String> {
    let mut json = false;
    let mut local = false;
    let mut positional = Vec::new();
    for argument in arguments {
        match argument.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(0);
            }
            "-V" | "--version" => {
                println!("gnap-conformance {}", env!("CARGO_PKG_VERSION"));
                return Ok(0);
            }
            "--json" => json = true,
            "--allow-loopback-http" => local = true,
            // Refusals never repeat their input, which may hold a secret or
            // terminal control characters.
            flag if flag.starts_with('-') => return Err("unknown option".into()),
            _ => positional.push(argument),
        }
    }
    let [command, endpoint] = positional.as_slice() else {
        return Err("a command and a grant endpoint are required".into());
    };
    let (method, check): (&'static str, Command) = match command.as_str() {
        "discover" => ("OPTIONS", |t, e, s| cli::discover(t, e, s)),
        "probe" => ("POST", |t, e, s| cli::probe(t, e, s)),
        _ => return Err("unknown command".into()),
    };
    net::endpoint(endpoint, local)
        .map_err(|reason| format!("the endpoint is refused: {reason}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|_| "the network runtime is unavailable".to_owned())?;
    let transport = Bounded::with_limits(
        Exact {
            method,
            url: endpoint.clone(),
        },
        Limits::DIAGNOSTIC,
        local,
        runtime.handle().clone(),
    );
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let report = check(&transport, endpoint, started);
    if json {
        let text = serde_json::to_string_pretty(&report)
            .map_err(|_| "the report could not be serialized".to_owned())?;
        println!("{text}");
    } else {
        print!("{}", report.text());
    }
    Ok(report.exit_code())
}
