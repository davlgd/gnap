//! `gnap-conformance`: selected GNAP checks against a server, from a terminal.
//!
//! Each command sends only the requests it names, to the endpoint it is
//! given, through the workbench's bounded transport. The report goes to
//! standard output, as text or as JSON, and the exit code says whether the
//! selected checks passed (0), one failed (1), or none could be decided (2).

use gnap_conformance_web::net::{self, Admitted, Bounded, Exact, Limits, Phased};
use gnap_conformance_web::{cli, scenario};
use std::process::ExitCode;
use std::sync::Arc;

const USAGE: &str = "\
Usage: gnap-conformance <command> <grant-endpoint> [options]

Commands:
  discover   send OPTIONS to the grant endpoint and check its discovery document (RFC 9635 §9)
  probe      send a malformed initial grant request and check the refusal (RFC 9635 §3.6)
  lifecycle  run one grant with a generated key: request, interaction by polling, token
             rotation, optional key rotation, revocation, and optional resource access

Options:
  --json                 print the report as JSON (schema gnap-conformance/1)
  --allow-loopback-http  accept an http://localhost, 127.0.0.1 or [::1] endpoint
  -h, --help             print this help
  -V, --version          print the version

Lifecycle options:
  --proof <method>       httpsig, jws or jwsd (default httpsig)
  --alg <algorithm>      PS256, ES256 or EdDSA for httpsig; RS256, ES256 or EdDSA for JOSE
                         (default ES256)
  --access <right>       a requested access entry, a string or a JSON object; repeat up to 8
  --resource <url>       a resource to read with the token, before and after revocation
  --rotate-key           also change the token's key, when the AS announces it
  --wait <seconds>       how long to wait for the interaction (default 120, at most 600)

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
    let mut options = Lifecycle::default();
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| "an option needs a value".to_owned())
        };
        match argument.as_str() {
            "--proof" => options.proof = value()?,
            "--alg" => options.alg = value()?,
            "--access" => options.access.push(value()?),
            "--resource" => options.resource = Some(value()?),
            "--rotate-key" => options.rotate_key = true,
            "--wait" => {
                options.wait = value()?
                    .parse()
                    .map_err(|_| "the wait is a number of seconds".to_owned())?;
            }
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
    if command == "lifecycle" {
        return lifecycle(endpoint, &options, local, json);
    }
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
    // A resolution that outlived its deadline still holds a blocking thread:
    // leave it behind rather than wait for it.
    runtime.shutdown_background();
    if json {
        let text = serde_json::to_string_pretty(&report)
            .map_err(|_| "the report could not be serialized".to_owned())?;
        println!("{text}");
    } else {
        print!("{}", report.text());
    }
    Ok(report.exit_code())
}

/// The options of `lifecycle`, before validation.
struct Lifecycle {
    proof: String,
    alg: String,
    access: Vec<String>,
    resource: Option<String>,
    rotate_key: bool,
    wait: u64,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            proof: "httpsig".into(),
            alg: "ES256".into(),
            access: Vec::new(),
            resource: None,
            rotate_key: false,
            wait: 120,
        }
    }
}

/// The scenario's clock: the system's, with waits the operator can cut.
/// The system's clocks: the wall clock for the protocol's times, and a
/// monotonic origin for the scenario's deadlines.
struct SystemClock(
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::time::Instant,
);

impl scenario::Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }
    fn sleep_until(&self, at: u64) -> bool {
        let until = self.deadline(at, scenario::MAX_WAIT);
        while let Some(left) = until.checked_duration_since(std::time::Instant::now()) {
            if left.is_zero() || self.interrupted() {
                break;
            }
            std::thread::sleep(left.min(TICK));
        }
        !self.interrupted()
    }
    fn interrupted(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn elapsed(&self) -> u64 {
        self.1.elapsed().as_secs()
    }
    fn pause(&self, at: u64) {
        let until = self.deadline(at, scenario::CLEANUP_WAIT);
        while let Some(left) = until.checked_duration_since(std::time::Instant::now()) {
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(TICK));
        }
    }
}

/// How often a wait looks for an interrupt.
const TICK: std::time::Duration = std::time::Duration::from_millis(200);

impl SystemClock {
    /// The monotonic instant a wait for the wall-clock second `at` ends,
    /// at most `cap` seconds away: setting the wall clock back doesn't
    /// lengthen a wait.
    fn deadline(&self, at: u64, cap: u64) -> std::time::Instant {
        let seconds = at.saturating_sub(scenario::Clock::now(self)).min(cap);
        std::time::Instant::now() + std::time::Duration::from_secs(seconds)
    }
}

/// The admissions of the scenario's two transports, which share them.
struct Shared<'a> {
    admitted: &'a Admitted,
    transport: &'a Phased<Bounded<Arc<Admitted>>, Bounded<Arc<Admitted>>>,
}

impl scenario::Admission for Shared<'_> {
    fn admit(&self, method: &'static str, url: &str) -> bool {
        self.admitted.admit_same_origin(method, url)
    }
    fn clean_up(&self) {
        self.transport.clean_up();
    }
}

fn lifecycle(endpoint: &str, options: &Lifecycle, local: bool, json: bool) -> Result<u8, String> {
    let plan = scenario::Plan::new(
        endpoint,
        &options.proof,
        &options.alg,
        &options.access,
        options.resource.as_deref(),
        options.rotate_key,
        options.wait,
    )?;
    if let Some(resource) = &plan.resource {
        net::endpoint(resource, local)
            .map_err(|reason| format!("the resource is refused: {reason}"))?;
    }
    let admitted = Arc::new(
        Admitted::new(endpoint, local)
            .map_err(|reason| format!("the endpoint is refused: {reason}"))?,
    );
    admitted.allow("POST", endpoint);
    if plan.rotate_key {
        admitted.allow("OPTIONS", endpoint);
    }
    if let Some(resource) = &plan.resource {
        admitted.allow("GET", resource);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|_| "the network runtime is unavailable".to_owned())?;
    let interrupted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&interrupted);
    // The first interrupt stops the scenario and lets cleanup run; a second
    // one gives up on cleanup.
    runtime.spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            eprintln!("gnap-conformance: interrupted; cleaning up (interrupt again to quit)");
            if tokio::signal::ctrl_c().await.is_ok() {
                std::process::exit(2);
            }
        }
    });
    let transport = Phased::new(
        Bounded::with_limits(
            Arc::clone(&admitted),
            Limits::scenario(std::time::Duration::from_secs(plan.wait)),
            local,
            runtime.handle().clone(),
        ),
        Bounded::with_limits(
            Arc::clone(&admitted),
            Limits::CLEANUP,
            local,
            runtime.handle().clone(),
        ),
    );
    let admission = Shared {
        admitted: &admitted,
        transport: &transport,
    };
    let clock = SystemClock(interrupted, std::time::Instant::now());
    let notify = |message: &str| eprintln!("gnap-conformance: {message}");
    let report = scenario::lifecycle(&transport, &admission, &clock, &notify, &plan, local);
    // As for the other commands, a late resolution doesn't hold the process.
    runtime.shutdown_background();
    if json {
        let text = serde_json::to_string_pretty(&report)
            .map_err(|_| "the report could not be serialized".to_owned())?;
        println!("{text}");
    } else {
        print!("{}", report.text());
    }
    Ok(report.exit_code())
}

#[cfg(test)]
mod tests {
    use super::SystemClock;
    use std::time::{Duration, Instant};

    /// A wait ends on a monotonic instant, within its cap, whatever second
    /// the wall clock asks for.
    #[test]
    fn a_wait_is_capped_on_the_monotonic_clock() {
        let clock = SystemClock(std::sync::Arc::default(), Instant::now());
        let now = gnap_conformance_web::scenario::Clock::now(&clock);
        let before = Instant::now();
        let far = clock.deadline(now + 100_000, 5);
        assert!(far <= Instant::now() + Duration::from_secs(5));
        assert!(far >= before + Duration::from_secs(4));
        assert!(clock.deadline(now.saturating_sub(100), 5) <= Instant::now());
    }
}
