//! A complete GNAP grant, narrated.
//!
//! Runs a real client against a real authorization server and prints what
//! happens at each step. Nothing is mocked and nothing touches the network: the
//! transport hands each request straight to the server.
//!
//! ```console
//! cargo run -p gnap-as --example flow
//! ```
//!
//! Read it top to bottom to see what the protocol actually looks like: what a
//! client sends, what an AS decides, and where the RFC's rules bite.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, Finish, KeyResolver, MemoryStorage, Nonces, Policy,
};
use gnap_client::{HttpRequest, HttpResponse, HttpTransport, Session, Step};
use gnap_crypto::proof::Verifier;
use gnap_crypto::ps256::{Ps256Signer, Ps256Verifier};
use gnap_types::access::AccessItem;
use gnap_types::client::Client;
use gnap_types::interact::InteractCallback;
use gnap_types::message::GrantRequest;
use std::cell::Cell;

const GRANT_ENDPOINT: &str = "https://as.example/gnap";

const CONTINUE_ENDPOINT: &str = "https://as.example/continue";

/// The public half of the bundled test key.
const PUBLIC_KEY: &str = include_str!("../tests/fixtures/rfc9421-b12.spki.pem");

// ---------------------------------------------------------------------------
// What the deployment decides. The RFC leaves all of this out of scope (§4),
// which is why it lives behind traits rather than inside the crate.
// ---------------------------------------------------------------------------

/// Asks a resource owner first, then grants what was requested.
struct AskTheResourceOwner {
    approved: Cell<bool>,
}

impl Policy for AskTheResourceOwner {
    fn evaluate(&self, _request: &GrantRequest) -> Decision {
        if self.approved.get() {
            Decision::Approve {
                access: vec![AccessItem::Reference("dolphin-metadata".into())],
                subject: None,
            }
        } else {
            Decision::RequireInteraction
        }
    }

    fn evaluate_after_interaction(&self, request: &GrantRequest) -> Decision {
        // The RO said yes while interacting; §4 has the AS re-evaluate the
        // whole context, approval included.
        self.approved.set(true);
        self.evaluate(request)
    }
}

/// Trusts exactly one key. A real AS would look the client up (§2.3).
struct KnownKey(&'static str);

impl KeyResolver for KnownKey {
    fn resolve(&self, _client: &Client) -> Option<Box<dyn Verifier>> {
        Ps256Verifier::from_public_key_pem(self.0)
            .ok()
            .map(|v| Box::new(v) as Box<dyn Verifier>)
    }
}

/// Predictable values, so the output reads the same every run.
struct Counter(Cell<u32>);

impl Nonces for Counter {
    fn next(&self) -> String {
        let n = self.0.get() + 1;
        self.0.set(n);
        format!("value{n:04}")
    }
}

type Server = AuthorizationServer<AskTheResourceOwner, KnownKey, MemoryStorage, Counter>;

/// Hands every request straight to the server, and shows it.
struct Wire<'a> {
    server: &'a Server,
    now: Cell<u64>,
}

impl HttpTransport for Wire<'_> {
    type Error = String;

    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        println!("  --> {} {}", request.method, request.url);
        if let Some(a) = request.header_value("authorization") {
            println!("      Authorization: {a}");
        }
        let response = self.server.handle(&request, self.now.get());
        println!("  <-- {} {}", response.status, summarize(&response.body));
        Ok(response)
    }
}

/// Lists the top-level fields of a response body.
///
/// Top-level on purpose: a `continue` object carries its own `access_token`,
/// and a substring search would report a token where the RFC forbids one.
fn summarize(body: &[u8]) -> String {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(body) else {
        return "(no body)".into();
    };
    if map.is_empty() {
        return "(empty)".into();
    }
    map.keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn main() {
    // The RSA key pair from RFC 9421 Appendix B.1.2. A real client keeps its
    // private key somewhere the AS never sees (§11.5).
    let signer = Ps256Signer::from_pkcs1_pem(
        include_str!("../tests/fixtures/rfc9421-b12.pkcs1.pem"),
        "example-key",
    )
    .expect("the bundled test key should load");

    let server: Server = AuthorizationServer::new(
        AskTheResourceOwner {
            approved: Cell::new(false),
        },
        KnownKey(PUBLIC_KEY),
        MemoryStorage::new(),
        Counter(Cell::new(0)),
        Endpoints {
            grant: GRANT_ENDPOINT.into(),
            continuation: CONTINUE_ENDPOINT.into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    );
    let wire = Wire {
        server: &server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&wire, &signer, GRANT_ENDPOINT);

    // -----------------------------------------------------------------------
    println!("\n1. The client asks for access (§2)");
    println!("   It signs the request with its own key; there is no client secret.");

    let request: GrantRequest = serde_json::from_str(
        r#"{
          "client": "example-client",
          "access_token": {"access": ["dolphin-metadata"]},
          "interact": {
            "start": ["redirect"],
            "finish": {"method": "redirect",
                       "uri": "https://client.example/callback",
                       "nonce": "VJLO6A4CATR0KRO"}
          }
        }"#,
    )
    .expect("the example request should parse");

    let step = client
        .start(&request, 1_000)
        .expect("the AS should accept the request");
    let Step::Pending(pending) = &step else {
        panic!("expected the AS to ask for interaction, got {step:?}");
    };
    let interact = pending.interact.clone().expect("an interaction response");

    println!(
        "\n   The AS wants a resource owner to approve. State: {}",
        client.state()
    );
    println!(
        "   Send the user to: {}",
        interact.redirect.as_deref().unwrap_or("-")
    );

    let callback = the_resource_owner_answers(&server, &interact);
    match client.accept_callback(&callback, 1_005) {
        Ok(()) => println!("   Hash validated; the client will pass the reference on."),
        Err(e) => panic!("the callback should validate: {e}"),
    }

    // A forged callback goes nowhere: §4.2.1 forbids sending the reference on.
    let forged = InteractCallback {
        hash: "not-the-right-hash".into(),
        interact_ref: "stolen".into(),
    };
    match client.accept_callback(&forged, 1_005) {
        Ok(()) => panic!("a forged callback must not be accepted"),
        Err(e) => println!("   A forged one is refused: {e}"),
    }

    // -----------------------------------------------------------------------
    println!("\n3. The client continues, and gets its token (§5)");
    println!("   It must wait out the `wait` period first; calling early earns");
    println!("   a too_fast error from the AS.");

    wire.now.set(1_010);
    let step = client
        .continue_grant(1_010)
        .expect("the AS should now approve");
    let Step::Approved(approved) = &step else {
        panic!("expected approval, got {step:?}");
    };

    let tokens = approved.access_token.as_ref().expect("an access token");
    println!("\n   State: {}. Token issued, good for:", client.state());
    for right in tokens.tokens[0].access.iter().flatten() {
        println!("     - {right:?}");
    }

    manage_the_token(&wire, &mut client, &tokens.tokens[0]);

    println!("\nBefore revoking it, the client could have called a resource server with");
    println!("that token (§7.2). This in-memory example does not call a resource server.");
}

/// Step 4: what §6 lets the client do with the token it now holds.
fn manage_the_token(
    wire: &Wire<'_>,
    client: &mut Session<'_, Wire<'_>, Ps256Signer>,
    issued: &gnap_types::token::AccessToken,
) {
    println!("\n4. The client manages the token it was issued (§6)");

    let manage = issued
        .manage
        .as_ref()
        .expect("the AS offered a management API");
    println!("   Management URI: {}", manage.uri);

    wire.now.set(1_020);
    match client.rotate_token(None, 1_020) {
        Ok(rotated) => {
            println!("   Rotated: a new value, the same rights (§6.1-M05)");
            println!(
                "     - {}",
                rotated
                    .access
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), |a| format!("{:?}", a[0]))
            );
            println!(
                "   And a new management URI to carry on with (§6.1-M04): {}",
                rotated.manage.as_ref().map_or("-", |m| m.uri.as_str())
            );
        }
        Err(e) => panic!("the rotation should succeed: {e}"),
    }

    wire.now.set(1_030);
    match client.revoke_token(None, 1_030) {
        Ok(()) => println!("   Revoked: the AS answered 204, the token is gone (§6.2)"),
        Err(e) => panic!("the revocation should succeed: {e}"),
    }
}

/// Step 2: the RO answers somewhere the client cannot see, and the AS says how
/// to hand them back (§4.2).
fn the_resource_owner_answers(
    server: &Server,
    interact: &gnap_types::interact::InteractResponse,
) -> InteractCallback {
    println!("\n2. The resource owner approves, elsewhere (§4)");
    println!("   Once the RO has answered, the AS creates the interaction reference,");
    println!("   binds it to this grant, and hashes it with both nonces (§4.2.3).");

    // The interaction UI is the deployment's own; all it has to tell the AS is
    // which interaction finished, using the handle from the URI above.
    let handle = interact
        .redirect
        .as_deref()
        .and_then(|uri| uri.rsplit('/').next())
        .expect("the AS offered a redirect");

    let Finish::Redirect { uri } = server
        .complete_interaction(handle, 1_005)
        .expect("the interaction should complete")
    else {
        panic!("the client asked for the redirect finish method");
    };
    println!("   Send the user back to: {uri}");

    // What the client's callback endpoint reads off its own query string.
    InteractCallback::from_redirect(&uri).expect("the AS put both values in the query")
}
