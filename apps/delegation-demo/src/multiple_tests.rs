//! Two tokens under one consent, over real HTTP: separate rights, resource
//! servers and lifecycles, selected by label and never by position.
use super::*;
use gnap_as::{GrantRecord, TokenRecord};
use gnap_client::Step;
use gnap_types::token::{AccessToken, Cardinality};

fn lot_request(
    origin: &str,
    references: &resource_registration::References,
    expand: bool,
) -> GrantRequest {
    serde_json::from_value(json!({
        "client":"test-client",
        "access_token": multiple::lot(references, expand),
        "interact":{"start":["redirect"],"finish":{"method":"redirect","uri":format!("{origin}/callback"),"nonce":fresh_nonce().unwrap()}}
    }))
    .unwrap()
}
fn lot_changes(
    origin: &str,
    references: &resource_registration::References,
    expand: bool,
) -> ContinueRequest {
    let request = lot_request(origin, references, expand);
    ContinueRequest {
        access_token: request.access_token,
        interact: request.interact,
        ..Default::default()
    }
}
fn handle(step: &Step) -> &str {
    step.response()
        .interact
        .as_ref()
        .unwrap()
        .redirect
        .as_ref()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
}
fn consent(app: &App, step: &Step, choice: multiple::Choice) -> InteractCallback {
    let handle = handle(step);
    let snapshot = app
        .storage
        .lookup(GrantSelector::Interaction(handle))
        .unwrap()
        .unwrap();
    let finish = consent_finish_choice(
        &app.server,
        &app.storage,
        &app.decisions,
        "test-client",
        snapshot.id,
        handle,
        choice,
    )
    .unwrap();
    InteractCallback::from_redirect(&finish).unwrap()
}
fn wait(step: &Step) {
    std::thread::sleep(Duration::from_secs(
        step.response()
            .r#continue
            .as_ref()
            .map_or(0, gnap_types::message::Continue::effective_wait),
    ));
}
fn labelled<'a>(tokens: &'a [AccessToken], label: &str) -> &'a AccessToken {
    tokens
        .iter()
        .find(|token| token.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("no {label} token"))
}
fn signed(app: &App, path: &str, token: &TokenValue, signer: &Ps256Signer) -> HttpRequest {
    sign_request(
        HttpRequest::new("GET", format!("{}{path}", app.origin)),
        signer,
        Some(token),
        now(),
    )
    .unwrap()
}
fn right(name: &str) -> AccessItem {
    AccessItem::Reference(name.into())
}
/// Rights as a set: the AS canonicalises a registered set's order.
fn sorted(rights: &[AccessItem]) -> Vec<String> {
    let mut names: Vec<String> = rights
        .iter()
        .map(|right| match right {
            AccessItem::Reference(name) => name.clone(),
            other => format!("{other:?}"),
        })
        .collect();
    names.sort();
    names
}
fn stored(app: &App, value: &TokenValue) -> bool {
    app.storage
        .lookup(GrantSelector::AccessToken(value.as_str()))
        .unwrap()
        .is_some()
}

/// Completes consent and continuation for a pending step, honouring the wait.
fn approve(
    app: &App,
    session: &mut Session<'_, Network, Ps256Signer>,
    pending: &Step,
    choice: multiple::Choice,
) -> Step {
    let callback = consent(app, pending, choice);
    session.accept_callback(&callback, now()).unwrap();
    wait(pending);
    session.continue_grant(now()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_token_grant_over_http_keeps_labels_rights_and_lifecycles_apart() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut app = tests::test_app_at(&origin);
    app.resource_client = Arc::new(introspection::ResourceClient {
        origin: origin.clone(),
        signer: app.resource_client.signer.clone(),
        transport: Arc::new(introspection::Http {
            origin: origin.clone(),
        }),
        nonces: MemoryStorage::default(),
    });
    let router = application_router(app.clone(), CanonicalOrigin::parse(&origin).unwrap());
    let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    tokio::task::spawn_blocking(move || two_token_scenario(app, origin))
        .await
        .unwrap();
    serving.abort();
    let _ = serving.await;
}

fn two_token_scenario(app: App, origin: String) {
    let network = Network {
        origin: origin.clone(),
        client: reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
    };
    // The browser client's transport does not reach RS2 by design; a check
    // against the metadata RS goes through the RS-side HTTP adapter instead.
    let http = introspection::Http {
        origin: origin.clone(),
    };
    let references = app.bootstrap.get().unwrap().as_ref().unwrap();
    let status = |path: &str, token: &TokenValue| {
        network
            .send(signed(&app, path, token, &app.signer))
            .unwrap()
            .status
    };
    let status_at_rs2 = |token: &TokenValue| {
        http.send(signed(&app, derivation::RS2_PATH, token, &app.signer))
            .unwrap()
            .status
    };

    // One consent, two tokens: each carries its requested label and its own
    // rights (§3.2.2), and each works at its own RS only.
    let mut session = Session::new(&network, app.signer.as_ref(), format!("{origin}/gnap"))
        .supporting(&["redirect"]);
    let pending = session
        .start(&lot_request(&origin, references, true), now())
        .unwrap();
    let approved = approve(&app, &mut session, &pending, multiple::Choice::All);
    let issued = approved.response().access_token.as_ref().unwrap();
    assert_eq!(issued.cardinality, Cardinality::Multiple);
    assert_eq!(issued.tokens.len(), 2);
    let documents = labelled(&issued.tokens, multiple::DOCUMENTS).clone();
    let reports = labelled(&issued.tokens, multiple::REPORTS).clone();
    assert_eq!(
        sorted(documents.access.as_deref().unwrap_or_default()),
        sorted(&resource_registration::leaves(true)),
        "the documents token resolves the registered reference"
    );
    assert_eq!(reports.access, Some(vec![right(multiple::REPORTS_READ)]));
    assert_ne!(documents.value, reports.value);
    assert_ne!(
        documents.manage.as_ref().unwrap().uri,
        reports.manage.as_ref().unwrap().uri
    );
    assert_eq!(status("/resource/folder", &documents.value), 200);
    assert_eq!(status("/resource/archive", &documents.value), 200);
    assert_eq!(status(multiple::REPORTS_PATH, &reports.value), 200);
    assert_eq!(
        status("/resource/folder", &reports.value),
        401,
        "the reports token is not a documents credential"
    );
    assert_eq!(
        status(multiple::REPORTS_PATH, &documents.value),
        401,
        "the documents token is not a reports credential"
    );
    assert_eq!(
        status(derivation::RS1_PATH, &reports.value),
        401,
        "RS1 does not derive from a token that is not its own"
    );
    assert!(
        derivation::issue(&app.resource_client, &reports.value, now()).is_err(),
        "the AS refuses to derive from the reports token for RS1"
    );
    assert_eq!(
        status_at_rs2(&reports.value),
        401,
        "the reports token is not a metadata credential either"
    );
    assert_eq!(
        status(derivation::RS1_PATH, &documents.value),
        200,
        "the labelled documents token still derives a metadata child"
    );

    // Managing one token of the lot leaves the other, and its child, alone.
    let rotated = session
        .rotate_token(Some(multiple::REPORTS), now())
        .unwrap();
    assert_eq!(rotated.label.as_deref(), Some(multiple::REPORTS));
    assert_ne!(rotated.value, reports.value);
    assert_eq!(status(multiple::REPORTS_PATH, &reports.value), 401);
    assert_eq!(status(multiple::REPORTS_PATH, &rotated.value), 200);
    assert_eq!(status("/resource/folder", &documents.value), 200);
    let child = derivation::issue(&app.resource_client, &documents.value, now()).unwrap();
    assert!(stored(&app, &child.value));
    session
        .revoke_token(Some(multiple::REPORTS), now())
        .unwrap();
    assert_eq!(status(multiple::REPORTS_PATH, &rotated.value), 401);
    assert_eq!(status("/resource/folder", &documents.value), 200);
    assert!(
        stored(&app, &child.value),
        "revoking the reports token does not touch the documents token's child"
    );
    let held: Vec<_> = session
        .usable_tokens(now())
        .unwrap()
        .iter()
        .map(|token| token.label.clone())
        .collect();
    assert_eq!(held, vec![Some(multiple::DOCUMENTS.to_owned())]);
    session
        .revoke_token(Some(multiple::DOCUMENTS), now())
        .unwrap();
    assert!(
        !stored(&app, &child.value),
        "revoking the documents token cascades to its child"
    );
    assert_eq!(status("/resource/folder", &documents.value), 401);

    // A lot approved in part: only the reports token exists. Asking again for
    // both needs the resource owner; approval replaces the lot as a whole.
    let mut session = Session::new(&network, app.signer.as_ref(), format!("{origin}/gnap"))
        .supporting(&["redirect"]);
    let pending = session
        .start(&lot_request(&origin, references, true), now())
        .unwrap();
    let partial = approve(
        &app,
        &mut session,
        &pending,
        multiple::Choice::Only(vec![multiple::REPORTS.to_owned()]),
    );
    let issued = partial.response().access_token.as_ref().unwrap();
    assert_eq!(
        issued.cardinality,
        Cardinality::Multiple,
        "an array of one (§3.2.2)"
    );
    assert_eq!(issued.tokens.len(), 1);
    let only_reports = labelled(&issued.tokens, multiple::REPORTS).clone();
    assert_eq!(status(multiple::REPORTS_PATH, &only_reports.value), 200);
    assert!(
        session
            .rotate_token(Some(multiple::DOCUMENTS), now())
            .is_err(),
        "no documents token was issued"
    );
    wait(&partial);
    let asked_again = session
        .modify_grant(&lot_changes(&origin, references, true), now())
        .unwrap();
    assert!(
        matches!(asked_again, Step::Pending(_)),
        "a label with no live token needs consent again: {asked_again:?}"
    );
    assert_eq!(
        status(multiple::REPORTS_PATH, &only_reports.value),
        200,
        "the earlier token stays usable while consent is pending"
    );
    let both = approve(&app, &mut session, &asked_again, multiple::Choice::All);
    let issued = both.response().access_token.as_ref().unwrap();
    assert_eq!(issued.tokens.len(), 2);
    let documents = labelled(&issued.tokens, multiple::DOCUMENTS).clone();
    let reports = labelled(&issued.tokens, multiple::REPORTS).clone();
    assert_eq!(
        status(multiple::REPORTS_PATH, &only_reports.value),
        401,
        "re-approval replaced the whole lot"
    );
    assert_eq!(status(multiple::REPORTS_PATH, &reports.value), 200);
    assert_eq!(status("/resource/archive", &documents.value), 200);

    // Narrowing within what each label already holds needs no consent, and
    // dropping a label from the lot retires that token with the old lot.
    wait(&both);
    let narrowed = session
        .modify_grant(&lot_changes(&origin, references, false), now())
        .unwrap();
    assert!(matches!(narrowed, Step::Approved(_)), "{narrowed:?}");
    let issued = narrowed.response().access_token.as_ref().unwrap();
    assert_eq!(issued.cardinality, Cardinality::Multiple);
    assert_eq!(issued.tokens.len(), 1);
    let folder_only = labelled(&issued.tokens, multiple::DOCUMENTS).clone();
    assert_eq!(
        sorted(folder_only.access.as_deref().unwrap_or_default()),
        sorted(&resource_registration::leaves(false))
    );
    assert_eq!(status("/resource/folder", &folder_only.value), 200);
    assert_eq!(status("/resource/archive", &folder_only.value), 401);
    assert_eq!(status("/resource/archive", &documents.value), 401);
    assert_eq!(status(multiple::REPORTS_PATH, &reports.value), 401);

    // Revoking the grant retires everything it issued.
    wait(&narrowed);
    session.revoke_grant(now()).unwrap();
    assert_eq!(status("/resource/folder", &folder_only.value), 401);
    assert!(session.usable_tokens(now()).is_none());
}

/// The policy understands a lot slot by slot, and refuses what it does not.
#[test]
fn a_lot_is_resolved_label_by_label_and_nothing_else_is_accepted() {
    let app = tests::test_app();
    let references = app.bootstrap.get().unwrap().as_ref().unwrap();
    let resources = &app.rs_registration.resources;
    let request = |access_token: Value| -> GrantRequest {
        serde_json::from_value(json!({"client":"test-client","access_token":access_token})).unwrap()
    };
    let slots = multiple::requested_slots(&request(multiple::lot(references, true)), resources)
        .expect("the browser lot is understood");
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0].label.as_deref(), Some(multiple::DOCUMENTS));
    assert_eq!(
        sorted(&slots[0].rights),
        sorted(&resource_registration::leaves(true))
    );
    assert_eq!(slots[1].label.as_deref(), Some(multiple::REPORTS));
    assert_eq!(slots[1].rights, vec![right(multiple::REPORTS_READ)]);
    let single = request(json!({"access": [references.folder]}));
    assert_eq!(
        multiple::requested_slots(&single, resources),
        Some(vec![multiple::Slot {
            label: None,
            rights: resource_registration::leaves(false),
        }]),
        "the single flow resolves as before"
    );
    for refused in [
        json!([{"label":"documents","access":[references.folder]},{"label":"reports","access":[multiple::REPORTS_READ]},{"label":"calendar","access":["calendar:read"]}]),
        json!([{"label":"payroll","access":[multiple::REPORTS_READ]}]),
        json!([{"label":"reports","access":[FOLDER_READ]}]),
        json!([{"label":"reports","access":[multiple::REPORTS_READ, FOLDER_READ]}]),
        json!([{"label":"documents","access":[multiple::REPORTS_READ]}]),
        json!([{"label":"documents","access":[references.folder],"flags":["durable"]}]),
        json!({"access":[multiple::REPORTS_READ]}),
        json!({"label":"reports","access":[multiple::REPORTS_READ]}),
    ] {
        assert!(
            multiple::requested_slots(&request(refused.clone()), resources).is_none(),
            "{refused}"
        );
    }
    let rs1_as_client: GrantRequest = serde_json::from_value(
        json!({"client":introspection::RS_ID,"access_token":multiple::lot(references, true)}),
    )
    .unwrap();
    assert!(multiple::requested_slots(&rs1_as_client, resources).is_none());

    // The owner's choice selects slots; an empty selection is a refusal, and a
    // partial choice on a single request approves nothing.
    let approved = |decision: Decision| match decision {
        Decision::ApproveTokens { tokens, .. } => tokens
            .into_iter()
            .map(|token| (token.requested_label, token.access))
            .collect::<Vec<_>>(),
        other => panic!("expected a lot, got {other:?}"),
    };
    assert_eq!(
        approved(multiple::decision(
            Cardinality::Multiple,
            &slots,
            &multiple::Choice::All
        ))
        .len(),
        2
    );
    assert_eq!(
        approved(multiple::decision(
            Cardinality::Multiple,
            &slots,
            &multiple::Choice::Only(vec![multiple::REPORTS.into()])
        )),
        vec![(
            Some(multiple::REPORTS.to_owned()),
            vec![right(multiple::REPORTS_READ)]
        )]
    );
    assert!(matches!(
        multiple::decision(Cardinality::Multiple, &slots, &multiple::Choice::Denied),
        Decision::Deny(gnap_registry::ErrorCode::UserDenied)
    ));
    assert!(matches!(
        multiple::decision(
            Cardinality::Multiple,
            &slots,
            &multiple::Choice::Only(vec!["calendar".into()])
        ),
        Decision::Deny(gnap_registry::ErrorCode::UserDenied)
    ));
    let single_slot = multiple::requested_slots(&single, resources).unwrap();
    assert!(matches!(
        multiple::decision(Cardinality::Single, &single_slot, &multiple::Choice::All),
        Decision::Approve { .. }
    ));
    assert!(matches!(
        multiple::decision(
            Cardinality::Single,
            &single_slot,
            &multiple::Choice::Only(vec![multiple::REPORTS.into()])
        ),
        Decision::Deny(gnap_registry::ErrorCode::UserDenied)
    ));
}

/// A modification is measured against the live token of the same label,
/// never against the union of everything the grant holds.
#[test]
fn a_modification_is_compared_to_the_live_token_of_the_same_label() {
    let app = tests::test_app();
    let references = app.bootstrap.get().unwrap().as_ref().unwrap();
    let resources = &app.rs_registration.resources;
    let record = |label: Option<&str>, value: &str, rights: &[&str]| TokenRecord {
        derivation: None,
        identifier: None,
        issued_at: now(),
        token: serde_json::from_value(
            json!({"label":label,"value":value,"access":rights,"expires_in":1200}),
        )
        .unwrap(),
        client: serde_json::from_value(json!("test-client")).unwrap(),
        management_token: format!("manage-{value}"),
    };
    let snapshot = |tokens: Vec<(&str, TokenRecord)>| {
        let request: GrantRequest = serde_json::from_value(
            json!({"client":"test-client","access_token":multiple::lot(references, true)}),
        )
        .unwrap();
        let mut aggregate = GrantAggregate::new(GrantRecord {
            grant: Default::default(),
            request,
            continuation_token: None,
            as_nonce: None,
            user_code: None,
            interact_handle: None,
            interact_expires_at: None,
            interact_ref: None,
            interaction_completed: false,
        });
        for (handle, token) in tokens {
            aggregate.tokens.insert(handle.to_owned(), token);
        }
        app.storage.create(aggregate).unwrap()
    };
    let wants = |expand: bool| {
        let request: GrantRequest = serde_json::from_value(
            json!({"client":"test-client","access_token":multiple::lot(references, expand)}),
        )
        .unwrap();
        multiple::requested_slots(&request, resources).unwrap()
    };

    // Both labels live with their own rights: narrowing documents to the
    // folder is within the documents token, so no consent is needed.
    let both = snapshot(vec![
        (
            "d1",
            record(
                Some(multiple::DOCUMENTS),
                "DOCS",
                &[FOLDER_READ, ARCHIVE_READ],
            ),
        ),
        (
            "r1",
            record(Some(multiple::REPORTS), "REPS", &[multiple::REPORTS_READ]),
        ),
    ]);
    assert!(matches!(
        multiple::modification(Cardinality::Multiple, &wants(false), &both),
        Decision::ApproveTokens { .. }
    ));
    assert!(matches!(
        multiple::modification(Cardinality::Multiple, &wants(true), &both),
        Decision::ApproveTokens { .. }
    ));

    // The union of the grant covers every right, but no live token carries
    // the reports label: the lot has to go back to the resource owner.
    let union_only = snapshot(vec![(
        "d2",
        record(
            Some(multiple::DOCUMENTS),
            "MIXED",
            &[FOLDER_READ, ARCHIVE_READ, multiple::REPORTS_READ],
        ),
    )]);
    assert!(matches!(
        multiple::modification(Cardinality::Multiple, &wants(true), &union_only),
        Decision::RequireInteraction
    ));
    assert!(matches!(
        multiple::modification(Cardinality::Multiple, &wants(false), &union_only),
        Decision::ApproveTokens { .. }
    ));

    // A documents token that only holds the folder cannot silently grow.
    let folder_only = snapshot(vec![
        (
            "d3",
            record(Some(multiple::DOCUMENTS), "FOLD", &[FOLDER_READ]),
        ),
        (
            "r3",
            record(Some(multiple::REPORTS), "REPS2", &[multiple::REPORTS_READ]),
        ),
    ]);
    assert!(matches!(
        multiple::modification(Cardinality::Multiple, &wants(true), &folder_only),
        Decision::RequireInteraction
    ));
}

/// The browser flow keeps its mode explicit and names tokens by label: a
/// partial approval is refused on a single-token request, actions on a
/// missing `documents` token fail locally instead of using the other token,
/// and the retired-token check says which token it is about.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_flow_selects_tokens_by_label_over_http() {
    use tower::ServiceExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut app = tests::test_app_at(&origin);
    app.resource_client = Arc::new(introspection::ResourceClient {
        origin: origin.clone(),
        signer: app.resource_client.signer.clone(),
        transport: Arc::new(introspection::Http {
            origin: origin.clone(),
        }),
        nonces: MemoryStorage::default(),
    });
    let (sender, receiver) = mpsc::sync_channel(8);
    app.commands = sender;
    let (worker_origin, signer, server, storage, decisions) = (
        origin.clone(),
        app.signer.clone(),
        app.server.clone(),
        app.storage.clone(),
        app.decisions.clone(),
    );
    let references = app.bootstrap.get().unwrap().as_ref().unwrap().clone();
    let worker = std::thread::spawn(move || {
        client_worker(
            worker_origin,
            signer,
            server,
            storage,
            decisions,
            receiver,
            references,
        )
    });
    let router = application_router(app.clone(), CanonicalOrigin::parse(&origin).unwrap());
    let served = router.clone();
    let serving = tokio::spawn(async move {
        axum::serve(listener, served).await.unwrap();
    });

    let start = |action: &'static str| {
        let router = router.clone();
        let origin = origin.clone();
        async move {
            let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/{action}"))
                        .header("host", origin.strip_prefix("http://").unwrap())
                        .header("origin", &origin)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{action}");
            response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .strip_prefix("gnap_demo=")
                .unwrap()
                .to_owned()
        }
    };
    let labels = |view: &Value| -> Vec<String> {
        view["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|token| token["label"].as_str().unwrap_or("").to_owned())
            .collect()
    };
    async fn settle(app: &App, id: &str) -> Value {
        let pending = dispatch(app, id.to_owned(), "status".into()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(
            pending["continuation_wait_seconds"].as_u64().unwrap(),
        ))
        .await;
        dispatch(app, id.to_owned(), "continue".into())
            .await
            .unwrap()
    }
    async fn consent(app: &App, id: &str, action: &str) {
        let finish = dispatch(app, id.to_owned(), action.into()).await.unwrap();
        dispatch(
            app,
            id.to_owned(),
            format!("callback:{}", finish["redirect"].as_str().unwrap()),
        )
        .await
        .unwrap();
    }

    // A single-token request cannot be approved "in part".
    let single = start("start").await;
    let refused = dispatch(&app, single.clone(), "approve-reports".into())
        .await
        .unwrap_err();
    assert!(refused.contains("two-token"), "{refused}");
    let view = dispatch(&app, single.clone(), "status".into())
        .await
        .unwrap();
    assert_eq!(
        view["state"], "pending",
        "the refusal did not touch consent"
    );
    assert_eq!(view["mode"], "single");

    // A two-token request approved for the reports token only.
    let lot = start("start-multiple").await;
    let view = dispatch(&app, lot.clone(), "status".into()).await.unwrap();
    assert_eq!(view["mode"], "multiple");
    assert_eq!(view["requested_rights"].as_array().unwrap().len(), 3);
    assert_eq!(
        view["requested_tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|slot| slot["label"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>(),
        vec![multiple::DOCUMENTS, multiple::REPORTS]
    );
    consent(&app, &lot, "approve-reports").await;
    let view = settle(&app, &lot).await;
    assert_eq!(view["state"], "approved");
    assert_eq!(labels(&view), vec![multiple::REPORTS]);
    assert_eq!(view["rights"], json!([multiple::REPORTS_READ]));
    assert_eq!(
        view["retired_token_present"], false,
        "nothing was retired: the lot had no documents token before"
    );
    for documents_only in ["read", "read-archive", "read-metadata", "rotate", "revoke"] {
        let refused = dispatch(&app, lot.clone(), documents_only.into())
            .await
            .unwrap_err();
        assert!(
            refused.contains("No live documents token"),
            "{documents_only}: {refused}"
        );
    }
    let view = dispatch(&app, lot.clone(), "read-reports".into())
        .await
        .unwrap();
    assert_eq!(view["last_resource_status"], 200);
    assert_eq!(view["folder"]["reports"], "synthetic-quarterly-summary");
    let view = dispatch(&app, lot.clone(), "rotate-reports".into())
        .await
        .unwrap();
    assert_eq!(view["retired_token_label"], multiple::REPORTS);
    assert_eq!(labels(&view), vec![multiple::REPORTS]);
    let view = dispatch(&app, lot.clone(), "check-retired".into())
        .await
        .unwrap();
    assert_eq!(view["last_resource_status"], 401);
    assert!(view["events"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .as_str()
        .unwrap()
        .contains("retired reports token was rejected at /resource/reports"));
    let view = dispatch(&app, lot.clone(), "read-reports".into())
        .await
        .unwrap();
    assert_eq!(view["last_resource_status"], 200, "the rotated token works");

    // Narrowing to the documents token alone asks for a label with no live
    // token, so the owner is asked again. That request has no reports slot:
    // a partial approval is refused without touching the interaction, and
    // approving it replaces the lot, retiring the reports token.
    tokio::time::sleep(Duration::from_secs(
        view["continuation_wait_seconds"].as_u64().unwrap(),
    ))
    .await;
    let view = dispatch(&app, lot.clone(), "downscope".into())
        .await
        .unwrap();
    assert_eq!(view["state"], "pending");
    assert_eq!(view["requested_tokens"].as_array().unwrap().len(), 1);
    let refused = dispatch(&app, lot.clone(), "approve-reports".into())
        .await
        .unwrap_err();
    assert!(
        refused.contains("does not ask for a reports token"),
        "{refused}"
    );
    let view = dispatch(&app, lot.clone(), "status".into()).await.unwrap();
    assert_eq!(view["state"], "pending", "consent was not consumed");
    consent(&app, &lot, "approve").await;
    let view = settle(&app, &lot).await;
    assert_eq!(view["state"], "approved");
    assert_eq!(labels(&view), vec![multiple::DOCUMENTS]);
    assert_eq!(view["rights"], json!([FOLDER_READ]));
    assert_eq!(
        view["retired_token_present"], false,
        "the replaced lot had no documents token to retire"
    );
    let refused = dispatch(&app, lot.clone(), "read-reports".into())
        .await
        .unwrap_err();
    assert!(refused.contains("No live reports token"), "{refused}");

    // Asking for both again needs the owner; approval issues both tokens and
    // retires the previous documents token under its own label.
    tokio::time::sleep(Duration::from_secs(
        view["continuation_wait_seconds"].as_u64().unwrap(),
    ))
    .await;
    let view = dispatch(&app, lot.clone(), "expand".into()).await.unwrap();
    assert_eq!(view["state"], "pending");
    consent(&app, &lot, "approve").await;
    let view = settle(&app, &lot).await;
    assert_eq!(view["state"], "approved");
    assert_eq!(labels(&view), vec![multiple::DOCUMENTS, multiple::REPORTS]);
    assert_eq!(view["retired_token_label"], multiple::DOCUMENTS);
    let view = dispatch(&app, lot.clone(), "read".into()).await.unwrap();
    assert_eq!(view["last_resource_status"], 200);
    let view = dispatch(&app, lot.clone(), "read-metadata".into())
        .await
        .unwrap();
    assert_eq!(view["last_resource_status"], 200);
    assert_eq!(view["folder"]["derived_right"], derivation::METADATA_READ);

    // The regression from review: a reports rotation followed by a PATCH must
    // leave the retired-token check pointing at the documents RS, not at the
    // reports RS remembered from before.
    let view = dispatch(&app, lot.clone(), "rotate-reports".into())
        .await
        .unwrap();
    assert_eq!(view["retired_token_label"], multiple::REPORTS);
    tokio::time::sleep(Duration::from_secs(
        view["continuation_wait_seconds"].as_u64().unwrap(),
    ))
    .await;
    let view = dispatch(&app, lot.clone(), "downscope".into())
        .await
        .unwrap();
    assert_eq!(
        view["state"], "approved",
        "within the live documents rights"
    );
    assert_eq!(labels(&view), vec![multiple::DOCUMENTS]);
    assert_eq!(view["rights"], json!([FOLDER_READ]));
    assert_eq!(view["retired_token_label"], multiple::DOCUMENTS);
    let view = dispatch(&app, lot.clone(), "check-retired".into())
        .await
        .unwrap();
    assert_eq!(view["last_resource_status"], 401);
    assert!(
        view["events"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .as_str()
            .unwrap()
            .contains("retired documents token was rejected at /resource/folder"),
        "{}",
        view["events"]
    );
    let view = dispatch(&app, lot.clone(), "read-archive".into())
        .await
        .unwrap();
    assert_eq!(view["last_resource_status"], 401);
    let refused = dispatch(&app, lot.clone(), "revoke-reports".into())
        .await
        .unwrap_err();
    assert!(refused.contains("No live reports token"), "{refused}");
    let view = dispatch(&app, lot.clone(), "status".into()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(
        view["continuation_wait_seconds"].as_u64().unwrap(),
    ))
    .await;
    let view = dispatch(&app, lot.clone(), "revoke-grant".into())
        .await
        .unwrap();
    assert_eq!(view["state"], "grant_revoked");
    assert_eq!(view["token_present"], false);
    assert_eq!(view["retired_token_label"], multiple::DOCUMENTS);

    serving.abort();
    let _ = serving.await;
    // The router clones keep the command sender alive; the worker thread ends
    // with the process, as in the other HTTP fixtures.
    drop(worker);
}
