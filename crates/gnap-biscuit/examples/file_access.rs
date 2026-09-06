//! An in-process AS → client attenuation → signed RS request → revocation flow.
//! All keys are ephemeral; no server, network request or persistent state exists.

use biscuit_auth::KeyPair;
use gnap_biscuit::{
    Error, FileAction, FileRight, Issuer, LiveDecision, RequestContext, VerifiedToken,
};
use gnap_client::{sign_request, HttpRequest};
use gnap_crypto::{Ps256Signer, SignedRequest};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let root = KeyPair::new();
    let roots = BTreeMap::from([(1, root.public())]);
    let grant_uri = "https://as.example/tx";
    let audience = "https://files.example";
    let resource = "https://files.example/notes/demo.txt";
    let client = Ps256Signer::generate(2048, "example-client")?;
    let issuer = Issuer::new(root, 1, grant_uri.into(), audience.into())?;
    let original = issuer.mint(
        &[FileRight::new(resource.into(), FileAction::Read)?],
        &client.public_jwk()?,
        now,
        now + 300,
    )?;

    // Local attenuation preserves proof of possession of the same RSA key.
    // It does not ask the AS for a new token with downstream rights.
    let parent = VerifiedToken::from_token(&original, &roots)?;
    let attenuated = parent.attenuate(Some(resource), Some(now + 120))?;
    let presented = VerifiedToken::from_token(&attenuated, &roots)?;
    let context = RequestContext {
        issuer: grant_uri,
        audience,
        max_clock_skew: 30,
    };
    let seen_nonces = RefCell::new(HashSet::new());
    let nonce_memory = |nonce: &str, _: u64| seen_nonces.borrow_mut().insert(nonce.to_owned());
    let revoked = RefCell::new(HashSet::<Vec<u8>>::new());
    // This reservation set belongs to the one configured client key above.
    // A multi-key deployment must partition by trusted key identity, not kid.
    let mut central_nonces = HashSet::new();
    let mut live = |ids: &[Vec<u8>], params: &gnap_crypto::ReceivedParams| {
        if ids.iter().any(|id| revoked.borrow().contains(id))
            || !central_nonces.insert(params.nonce.clone())
        {
            LiveDecision::Denied
        } else {
            LiveDecision::Allowed
        }
    };
    let mut clock = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|time| time.as_secs())
    };

    for (step, expected) in [
        ("first-request", Ok(())),
        ("after-revocation", Err(Error::Denied)),
    ] {
        let http = sign_request(
            HttpRequest::new("GET", resource),
            &client,
            Some(&attenuated),
            clock().ok_or(Error::Unavailable)?,
        )?;
        let request = SignedRequest {
            method: &http.method,
            target_uri: &http.url,
            headers: &http.headers,
            body: http.body.as_deref(),
        };
        let outcome = presented.authorize(&request, &context, &nonce_memory, &mut clock, &mut live);
        assert_eq!(outcome, expected);
        println!("{step}: {outcome:?}");
        revoked
            .borrow_mut()
            .insert(parent.revocation_identifiers()[0].clone());
    }
    Ok(())
}
