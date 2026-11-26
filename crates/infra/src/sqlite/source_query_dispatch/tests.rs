use super::*;
use irmind_app::{
    AuditLog as _, CaseMutation, Signer as _, source_queries::SourceQueryReservationV1,
};
use irmind_domain::{Case, CaseId, Severity};
use std::{path::Path, process::Command};

const CRASH_ROOT: &str = "IRMIND_TEST_QUERY_DISPATCH_CRASH_ROOT";
const CRASH_ORDER: &str = "IRMIND_TEST_QUERY_DISPATCH_CRASH_ORDER";

fn fixture() -> Vec<SignedEntry> {
    let mut chain: Vec<SignedEntry> = serde_json::from_slice(include_bytes!(
        "../../../../testkit/fixtures/contracts/signed-record-chain-case-v7.json"
    ))
    .unwrap();
    chain.truncate(6);
    let signer = crate::LocalSigner {
        actor: Actor::Analyst,
        key: ed25519_dalek::SigningKey::from_bytes(&[91; 32]),
    };
    let intent = &chain[5];
    let mut allowed = SignedEntry {
        case_id: intent.case_id.clone(),
        seq: intent.seq + 1,
        at: intent.at,
        actor: Actor::Analyst,
        origin: "policy".into(),
        kind: AuditEventKind::Allowed,
        payload: Tool::SourceQuery.as_str().into(),
        evidence: None,
        prev: intent.hash,
        hash: [0; 32],
        sig: Vec::new(),
        public_key: signer.public_key(),
    };
    allowed.hash = irmind_app::sha256(&allowed.canonical());
    allowed.sig = signer.sign(&allowed.hash).unwrap();
    chain.push(allowed);
    chain
}

fn create(store: &LocalStore, chain: &[SignedEntry]) {
    let created: serde_json::Value = serde_json::from_str(&chain[0].payload).unwrap();
    store
        .transact(
            &chain[0],
            CaseMutation::Create(Case {
                id: CaseId::parse(&chain[0].case_id).unwrap(),
                title: created["title"].as_str().unwrap().into(),
                scope: created["scope"].as_str().unwrap().into(),
                severity: Severity::Medium,
                sealed: false,
            }),
        )
        .unwrap();
    store.append_batch(&chain[1..4]).unwrap();
}

fn claim_fixture(tx: &Transaction<'_>, chain: &[SignedEntry]) -> Result<(), AppError> {
    let plan: serde_json::Value = serde_json::from_str(&chain[2].payload).unwrap();
    let source = serde_json::from_value(plan["source"].clone()).unwrap();
    let limits = serde_json::from_value(plan["limits"].clone()).unwrap();
    let reservation = SourceQueryReservationV1::decode(chain[4].payload.as_bytes())
        .unwrap()
        .content_id()
        .unwrap();
    claim(tx, &source, &limits, &reservation, &chain[5])
}

fn append_case_batch(tx: &Transaction<'_>, chain: &[SignedEntry]) {
    for entry in &chain[4..] {
        super::super::codec::append_entry_tx(tx, entry).unwrap();
    }
}

fn write_first_half(root: &Path, quota_first: bool, crash: bool) {
    let chain = fixture();
    let store = LocalStore::open(root).unwrap();
    let mut db = store.conn().unwrap();
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    if quota_first {
        claim_fixture(&tx, &chain).unwrap();
    } else {
        append_case_batch(&tx, &chain);
    }
    if crash {
        // An abrupt process exit leaves SQLite to recover an open WAL transaction.
        std::process::exit(83);
    }
    tx.commit().unwrap();
}

#[test]
fn crash_worker() {
    let Some(root) = std::env::var_os(CRASH_ROOT) else {
        return;
    };
    let quota_first = std::env::var(CRASH_ORDER).unwrap() == "quota";
    write_first_half(Path::new(&root), quota_first, true);
}

#[test]
fn process_exit_between_writes_rolls_back_both_orders() {
    for order in ["quota", "case"] {
        let root = tempfile::tempdir().unwrap();
        let chain = fixture();
        let case = CaseId::parse(&chain[0].case_id).unwrap();
        create(&LocalStore::open(root.path()).unwrap(), &chain);
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sqlite::source_query_dispatch::tests::crash_worker",
            ])
            .env(CRASH_ROOT, root.path())
            .env(CRASH_ORDER, order)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(83), "{output:?}");
        let reopened = LocalStore::open(root.path()).unwrap();
        assert!(reopened.query_dispatch_ready, "{order}");
        assert_eq!(reopened.entries(&case).unwrap().len(), 4, "{order}");
        let index_count: u64 = reopened
            .conn()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM source_query_dispatch", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(index_count, 0, "{order}");
    }
}

#[test]
fn startup_detects_either_committed_half_and_keeps_the_case_readable() {
    for quota_first in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let chain = fixture();
        let case = CaseId::parse(&chain[0].case_id).unwrap();
        create(&LocalStore::open(root.path()).unwrap(), &chain);
        write_first_half(root.path(), quota_first, false);
        let reopened = LocalStore::open(root.path()).unwrap();
        assert!(!reopened.query_dispatch_ready);
        assert_eq!(
            reopened.entries(&case).unwrap().len(),
            if quota_first { 4 } else { 7 }
        );
    }
}

#[test]
fn distinct_cases_share_a_provider_slot_and_rolling_window() {
    let root = tempfile::tempdir().unwrap();
    let store = LocalStore::open(root.path()).unwrap();
    let other_process = LocalStore::open(root.path()).unwrap();
    let chain = fixture();
    let plan: serde_json::Value = serde_json::from_str(&chain[2].payload).unwrap();
    let mut source_wire = plan["source"].clone();
    let source = serde_json::from_value(source_wire.clone()).unwrap();
    source_wire["id"] = serde_json::json!("alternate-source-label");
    let alias = serde_json::from_value(source_wire.clone()).unwrap();
    source_wire["owner"] = serde_json::json!("999988887777");
    let independent = serde_json::from_value(source_wire).unwrap();
    let mut limits: SourceQueryLimits = serde_json::from_value(plan["limits"].clone()).unwrap();
    limits.queries_per_minute = 1;
    limits.concurrency = 1;
    let first = &chain[5];
    let mut second = first.clone();
    second.case_id = "22222222-2222-4222-8222-222222222222".into();
    let mut db = store.conn().unwrap();
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    claim(&tx, &source, &limits, "synthetic-first", first).unwrap();
    tx.commit().unwrap();
    let mut db2 = other_process.conn().unwrap();
    let tx2 = db2
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(claim(&tx2, &alias, &limits, "synthetic-second", &second).is_err());
    claim(
        &tx2,
        &independent,
        &limits,
        "synthetic-independent",
        &second,
    )
    .unwrap();
    tx2.rollback().unwrap();

    // Simulate a settled slot for the accounting calculation. Real receipt
    // publication exercises the release path in the capture custody suite.
    db.execute(
        "UPDATE source_query_dispatch SET release_hash=zeroblob(32) WHERE reservation=?1",
        ["synthetic-first"],
    )
    .unwrap();
    let tx2 = db2
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    second.at = first.at + 59;
    assert!(claim(&tx2, &alias, &limits, "synthetic-second", &second).is_err());
    second.at += 1;
    claim(&tx2, &alias, &limits, "synthetic-second", &second).unwrap();
    tx2.rollback().unwrap();
}
