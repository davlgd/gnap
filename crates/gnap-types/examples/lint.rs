//! GNAP message linter.
//!
//! Reads a JSON document and reports a diagnostic citing the RFC section.
//! Needs neither network nor cryptography: everything checked here is about
//! the shape of the message.
//!
//! ```text
//! cargo run -p gnap-types --example lint -- request message.json
//! cat message.json | cargo run -p gnap-types --example lint -- response
//! ```

use gnap_types::key::Key;
use gnap_types::message::{GrantRequest, GrantResponse};
use std::io::Read;

/// What the linter found.
enum Report {
    /// The message is conformant; the list records what was checked.
    Ok(Vec<String>),
    /// The message is rejected, with the reason.
    Rejected(String),
}

fn lint_request(src: &str) -> Report {
    let req: GrantRequest = match serde_json::from_str(src) {
        Ok(r) => r,
        Err(e) => return Report::Rejected(e.to_string()),
    };
    let mut notes = Vec::new();

    match req.client.as_value() {
        None => notes.push("client sent by instance reference (§2.3.1)".into()),
        Some(obj) => {
            notes.push("client sent by value".into());
            match &obj.key {
                Key::ByReference(_) => notes.push("key sent by reference (§7.1.1)".into()),
                Key::ByValue(k) => {
                    if let Err(e) = k.validate() {
                        return Report::Rejected(e.to_string());
                    }
                    let m = k.proof.method();
                    notes.push(format!("valid key, proof `{m}`"));
                    if !m.is_registered() {
                        notes.push(format!(
                            "proofing method `{m}` is outside the IANA registry (Appendix D)"
                        ));
                    }
                }
            }
        }
    }

    if let Some(at) = &req.access_token {
        notes.push(format!(
            "{} token(s) requested, shape {:?} — the response must mirror it (§3.2.1, §3.2.2)",
            at.tokens.len(),
            at.cardinality
        ));
        for t in &at.tokens {
            for a in &t.access {
                if let Some(k) = a.kind() {
                    notes.push(format!("structured right of type `{k}`"));
                }
            }
            for f in &t.flags {
                if !f.is_registered() {
                    notes.push(format!("flag `{f}` is outside the IANA registry"));
                }
            }
        }
    }

    if let Some(i) = &req.interact {
        for m in &i.start {
            let mark = if m.method().is_registered() {
                ""
            } else {
                " (unregistered)"
            };
            notes.push(format!("start mode `{}`{mark}", m.method()));
        }
        if let Some(f) = &i.finish {
            notes.push(format!(
                "interaction finish `{}`, hash `{}`",
                f.method,
                f.effective_hash_method()
            ));
            if f.uri.is_none() {
                return Report::Rejected(
                    "interact.finish.uri: required for the `redirect` and `push` methods \
                     (RFC 9635 §2.5.2)"
                        .into(),
                );
            }
        }
    }

    for k in req.extra.keys() {
        notes.push(format!("extension field `{k}` preserved (Appendix D)"));
    }

    Report::Ok(notes)
}

fn lint_response(src: &str) -> Report {
    let res: GrantResponse = match serde_json::from_str(src) {
        Ok(r) => r,
        Err(e) => return Report::Rejected(e.to_string()),
    };
    let mut notes = Vec::new();

    if let Some(at) = &res.access_token {
        if let Err(e) = at.validate() {
            return Report::Rejected(e.to_string());
        }
        notes.push(format!(
            "{} token(s) issued, shape {:?}",
            at.tokens.len(),
            at.cardinality
        ));
        for t in &at.tokens {
            notes.push(format!(
                "token{}{}",
                if t.is_bearer() {
                    ", bearer"
                } else {
                    ", key-bound"
                },
                if t.is_durable() { ", durable" } else { "" }
            ));
        }
    }

    if let Some(c) = &res.r#continue {
        notes.push(format!(
            "continuation available, wait {} s (§3.1)",
            c.effective_wait()
        ));
    }

    if let Some(e) = &res.error {
        let mark = if e.code.is_registered() {
            ""
        } else {
            " (unregistered)"
        };
        notes.push(format!("error `{}`{mark}", e.code));
    }

    if res.access_token.is_some() && res.interact.is_some() {
        notes.push(
            "WARNING: tokens and interaction modes together — §3.2 requires the \
             _approved_ state, §3.3 requires _pending_; the two are exclusive"
                .into(),
        );
    }

    Report::Ok(notes)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let kind = args.first().map_or("request", String::as_str);

    let mut src = String::new();
    match args.get(1) {
        Some(path) => src = std::fs::read_to_string(path).expect("unreadable file"),
        None => {
            std::io::stdin()
                .read_to_string(&mut src)
                .expect("unreadable stdin");
        }
    }

    let report = match kind {
        "request" => lint_request(&src),
        "response" => lint_response(&src),
        other => {
            eprintln!("unknown type `{other}`; expected `request` or `response`");
            std::process::exit(2);
        }
    };

    match report {
        Report::Ok(notes) => {
            println!("CONFORMANT");
            for n in notes {
                println!("  · {n}");
            }
        }
        Report::Rejected(e) => {
            println!("REJECTED");
            println!("  {e}");
            std::process::exit(1);
        }
    }
}
