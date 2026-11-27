use super::*;
use irmind_app::engine_rpc::PassphraseVerifier;
use std::sync::atomic::{AtomicUsize, Ordering};

const MAGIC_V2: &[u8] = b"IRMIND-RPC-V2\0";
const PHRASE: &str = "synthetic scoped reauthentication only";

struct ApprovalIntel {
    store: Arc<LocalStore>,
    case: CaseId,
    calls: AtomicUsize,
}

#[async_trait]
impl irmind_app::ThreatIntelPort for ApprovalIntel {
    async fn execute(
        &self,
        call: &irmind_domain::AuthorizedCall,
        _: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(call.case_id(), &self.case);
        assert_eq!(call.arg("ioc"), Some("attacker.example"));
        assert!(
            self.store
                .entries(&self.case)?
                .iter()
                .any(|entry| entry.kind == AuditEventKind::ApprovalGranted)
        );
        Ok(b"synthetic response".to_vec())
    }
}

impl ApprovalIntel {
    fn new(store: &Arc<LocalStore>, case: &CaseId) -> Self {
        Self {
            store: store.clone(),
            case: case.clone(),
            calls: AtomicUsize::new(0),
        }
    }
}

fn open_pending(client: &mut Client, case: &CaseId) {
    client.open_with(case, MAGIC_V2, 2);
    client.call("subscribe", json!({"after":0,"case_id":case.as_str()}));
    let reply = client.call(
        "start_turn",
        json!({"case_id":case.as_str(),"text":"Investigate the synthetic evidence"}),
    );
    assert!(reply["result"]["operation"].is_string());
    loop {
        if client.read()["kind"] == "approval_state" {
            break;
        }
    }
}

fn prepare(client: &mut Client, case: &CaseId, decision: &str) -> Value {
    let end = std::time::Instant::now() + WAIT;
    loop {
        let reply = client.call(
            "approval_prepare",
            json!({"case_id":case.as_str(),"decision":decision,"request_id":null}),
        );
        if reply["error"]["code"] != 4 || std::time::Instant::now() >= end {
            assert!(reply["error"].is_null(), "{reply}");
            return reply["result"].clone();
        }
    }
}

fn submit(client: &mut Client, case: &CaseId, view: &Value, phrase: &str) -> Value {
    client.call(
        "approval_submit",
        json!({"case_id":case.as_str(), "presentation":view["presentation"],
            "view_sha256":view["view_sha256"], "method":"keystore_passphrase",
            "passphrase_hex":hex::encode(phrase)}),
    )
}

fn wait_state(client: &mut Client, case: &CaseId, view: &Value) -> Value {
    let end = std::time::Instant::now() + WAIT;
    loop {
        let reply = client.call(
            "approval_status",
            json!({"case_id":case.as_str(), "presentation":view["presentation"]}),
        );
        assert!(reply["error"].is_null(), "{reply}");
        let state = &reply["result"]["state"];
        if state != "authenticating" || std::time::Instant::now() >= end {
            return state.clone();
        }
    }
}

#[test]
fn engine_rpc_v2_requires_reauthentication_then_commits_once() {
    let (_root, store, engine, id) = engine_fixture();
    let port = ApprovalIntel::new(&store, &id);
    let model = ObedientModel {
        seen: Mutex::new(Vec::new()),
    };
    let engine = engine
        .with_threat_intel(&port)
        .with_case_lifecycle(store.clone());
    let (mut client, input, output) = connection();
    let attempts = AtomicUsize::new(0);
    let verify: &PassphraseVerifier<'_> = &|_, key| {
        assert_eq!(key.len(), 32);
        attempts.fetch_add(1, Ordering::SeqCst) == 1
    };
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            irmind_app::engine_rpc::serve_v2(
                &engine,
                id.clone(),
                Some(&model),
                &CancellationToken::new(),
                Some(verify),
                input,
                output,
            )
        });
        open_pending(&mut client, &id);
        let view = prepare(&mut client, &id, "approve");
        assert_eq!(view["view"]["action"], "ti_lookup_external");
        assert_eq!(view["view"]["case_id"], id.as_str());
        assert_eq!(view["view"]["effective_scope"], "local");
        assert_eq!(view["methods"], json!(["keystore_passphrase"]));
        assert_eq!(view["code"].as_str().expect("check code").len(), 16);
        assert_eq!(view, prepare(&mut client, &id, "approve"));
        assert_eq!(
            submit(&mut client, &id, &view, "wrong synthetic phrase")["result"]["state"],
            "authenticating"
        );
        assert_eq!(wait_state(&mut client, &id, &view), "reauth_failed");
        assert_eq!(port.calls.load(Ordering::SeqCst), 0);
        let next = prepare(&mut client, &id, "approve");
        assert_ne!(next["presentation"], view["presentation"]);
        assert_eq!(
            submit(&mut client, &id, &next, PHRASE)["result"]["state"],
            "authenticating"
        );
        assert_eq!(wait_state(&mut client, &id, &next), "approved");
        assert!(submit(&mut client, &id, &next, PHRASE)["error"]["code"].is_number());
        let end = std::time::Instant::now() + WAIT;
        loop {
            let reply = client.call("case_status", json!({"case_id":id.as_str()}));
            if reply["error"]["code"] != 4 || std::time::Instant::now() >= end {
                assert!(reply["error"].is_null(), "{reply}");
                break;
            }
        }
        drop(client);
        server.join().expect("RPC thread").expect("RPC result");
    });
    engine.verify(&id).expect("signed decision");
    let entries = store.entries(&id).expect("entries");
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::ApprovalGranted)
            .count(),
        1
    );
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    let audit = serde_json::to_string(&entries).expect("synthetic audit");
    assert!(!audit.contains(PHRASE));
    assert!(!audit.contains(&hex::encode(PHRASE)));
}

#[test]
fn engine_rpc_v2_discards_a_late_authentication_after_cancellation() {
    let (_root, store, engine, id) = engine_fixture();
    let port = ApprovalIntel::new(&store, &id);
    let model = ObedientModel {
        seen: Mutex::new(Vec::new()),
    };
    let engine = engine
        .with_threat_intel(&port)
        .with_case_lifecycle(store.clone());
    let (mut client, input, output) = connection();
    let (entered, reached) = channel();
    let (resume, waiting) = channel();
    let waiting = Mutex::new(waiting);
    let verify: &PassphraseVerifier<'_> = &|_, _| {
        entered.send(()).expect("verifier entered");
        waiting.lock().expect("receiver").recv_timeout(WAIT).is_ok()
    };
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            irmind_app::engine_rpc::serve_v2(
                &engine,
                id.clone(),
                Some(&model),
                &CancellationToken::new(),
                Some(verify),
                input,
                output,
            )
        });
        open_pending(&mut client, &id);
        let view = prepare(&mut client, &id, "deny");
        assert_eq!(
            submit(&mut client, &id, &view, PHRASE)["result"]["state"],
            "authenticating"
        );
        reached.recv_timeout(WAIT).expect("verifier blocked");
        assert_eq!(
            client.call(
                "approval_cancel",
                json!({"case_id":id.as_str(),"presentation":view["presentation"]})
            )["result"]["cancelled"],
            true
        );
        resume.send(()).expect("resume test verifier");
        assert_eq!(wait_state(&mut client, &id, &view), "cancelled");
        drop(client);
        server.join().expect("RPC thread").expect("RPC result");
    });
    engine.verify(&id).expect("case verification");
    assert!(!store.entries(&id).expect("entries").iter().any(|entry| {
        matches!(
            entry.kind,
            AuditEventKind::ApprovalGranted | AuditEventKind::ApprovalDenied
        )
    }));
    assert_eq!(port.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn engine_rpc_v2_rechecks_the_deadline_and_competing_decisions_under_lock() {
    for competing_tui in [false, true] {
        let clock = Arc::new(irmind_testkit::FixedClock::new(10));
        let (_root, store, engine, id) = engine_fixture_with_clock(clock.clone());
        let port = ApprovalIntel::new(&store, &id);
        let model = ObedientModel {
            seen: Mutex::new(Vec::new()),
        };
        let engine = engine
            .with_threat_intel(&port)
            .with_case_lifecycle(store.clone());
        let (mut client, input, output) = connection();
        let (entered, reached) = channel();
        let (resume, waiting) = channel();
        let waiting = Mutex::new(waiting);
        let verify: &PassphraseVerifier<'_> = &|_, _| {
            entered.send(()).expect("verifier entered");
            waiting.lock().expect("receiver").recv_timeout(WAIT).is_ok()
        };
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                irmind_app::engine_rpc::serve_v2(
                    &engine,
                    id.clone(),
                    Some(&model),
                    &CancellationToken::new(),
                    Some(verify),
                    input,
                    output,
                )
            });
            open_pending(&mut client, &id);
            let view = prepare(&mut client, &id, "approve");
            assert_eq!(view["view"]["expires_at"], 70);
            assert_eq!(
                submit(&mut client, &id, &view, PHRASE)["result"]["state"],
                "authenticating"
            );
            reached.recv_timeout(WAIT).expect("verifier in flight");
            let expected = if competing_tui {
                engine
                    .deny(
                        &id,
                        view["view"]["request_id"].as_str().expect("request"),
                        "Synthetic concurrent decision",
                    )
                    .expect("competing signed denial");
                "stale"
            } else {
                clock.set(70);
                "expired"
            };
            resume.send(()).expect("release verifier");
            assert_eq!(wait_state(&mut client, &id, &view), expected);
            drop(client);
            server.join().expect("RPC thread").expect("RPC result");
        });
        engine.verify(&id).expect("case verification");
        let entries = store.entries(&id).expect("authenticated entries");
        assert!(
            !entries
                .iter()
                .any(|entry| entry.kind == AuditEventKind::ApprovalGranted)
        );
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.kind == AuditEventKind::ApprovalDenied)
                .count(),
            usize::from(competing_tui)
        );
        assert_eq!(port.calls.load(Ordering::SeqCst), 0);
    }
}
