//! Runs the vector corpus from `vectors/deserialization.json`.
//!
//! Each vector names the requirements it attests.

use gnap_types::message::{GrantRequest, GrantResponse};
use serde_json::Value;

const CORPUS: &str = include_str!("fixtures/deserialization.json");

struct Vector {
    id: String,
    kind: String,
    expect: String,
    description: String,
    input: Value,
    expect_error_contains: Vec<String>,
}

fn load() -> Vec<Vector> {
    let doc: Value = serde_json::from_str(CORPUS).expect("unreadable corpus");
    doc["vectors"]
        .as_array()
        .expect("`vectors` must be an array")
        .iter()
        .map(|v| Vector {
            id: v["id"].as_str().unwrap().to_owned(),
            kind: v["type"].as_str().unwrap().to_owned(),
            expect: v["expect"].as_str().unwrap().to_owned(),
            description: v["description"].as_str().unwrap().to_owned(),
            input: v["input"].clone(),
            expect_error_contains: v["expect_error_contains"]
                .as_array()
                .map(|a| a.iter().map(|s| s.as_str().unwrap().to_owned()).collect())
                .unwrap_or_default(),
        })
        .collect()
}

/// Deserializes as the declared type and returns any error message.
fn run(v: &Vector) -> Result<(), String> {
    match v.kind.as_str() {
        "GrantRequest" => serde_json::from_value::<GrantRequest>(v.input.clone())
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "GrantResponse" => serde_json::from_value::<GrantResponse>(v.input.clone())
            .map(|_| ())
            .map_err(|e| e.to_string()),
        other => panic!("{}: type `{other}` is unknown to the harness", v.id),
    }
}

#[test]
fn deserialization_corpus() {
    let vectors = load();
    assert!(!vectors.is_empty(), "empty corpus");
    let mut accepted = 0;
    let mut rejected = 0;

    for v in &vectors {
        let outcome = run(v);
        match (v.expect.as_str(), &outcome) {
            ("accept", Ok(())) => {
                accepted += 1;
                println!("  {} accepted — {}", v.id, v.description);
            }
            ("accept", Err(e)) => panic!(
                "{} should have been accepted — {}\n  error: {e}",
                v.id, v.description
            ),
            ("reject", Ok(())) => panic!("{} should have been rejected — {}", v.id, v.description),
            ("reject", Err(e)) => {
                // Rejecting is not enough: the diagnostic has to be usable.
                for needle in &v.expect_error_contains {
                    assert!(
                        e.contains(needle.as_str()),
                        "{}: the message should contain `{needle}`\n  message: {e}",
                        v.id
                    );
                }
                rejected += 1;
                println!("  {} rejected — {}", v.id, v.description);
            }
            (other, _) => panic!("{}: unknown expectation `{other}`", v.id),
        }
    }

    println!(
        "\n  {accepted} accepted, {rejected} rejected, {} total",
        vectors.len()
    );
}

/// The corpus must stay consistent with the requirements base.
#[test]
fn cited_requirement_ids_are_well_formed() {
    let doc: Value = serde_json::from_str(CORPUS).unwrap();
    for v in doc["vectors"].as_array().unwrap() {
        for r in v["requirements"]
            .as_array()
            .expect("`requirements` is required")
        {
            let id = r.as_str().unwrap();
            assert!(
                id.starts_with("GNAP-9635-§") || id.starts_with("GNAP-9767-§"),
                "{}: malformed requirement id: {id}",
                v["id"]
            );
        }
    }
}
