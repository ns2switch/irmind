#![forbid(unsafe_code)]
#![cfg(all(feature = "keystore-file", feature = "parser-json"))]
#![allow(clippy::unwrap_used)]
use irmind_app::{CryptoPorts, Engine, EnginePorts, SignerBackend, hex, sha256};
use irmind_domain::{Actor, ExecutionMode};
use irmind_infra::{LocalVerifier, SystemClock};
use irmind_mod_keystore_file::FileKeystore;
use irmind_security::MandatoryGuard;
use secrecy::SecretString;
use std::{path::Path, process::Command, sync::Arc};
#[path = "support/current_sources.rs"]
mod current_sources;
#[path = "support/demo_session.rs"]
mod demo_session;
#[path = "support/terminal_screen.rs"]
mod terminal_screen;
use demo_session::DemoSession;
const PHRASE: &str = "Synthetic recovery PTY passphrase";
const TITLE: &str = "Synthetic recovery PTY";
fn seed(root: &Path) {
    let backend = FileKeystore::open(root, &SecretString::from(PHRASE.to_owned()), true).unwrap();
    let signer = backend.create(Actor::Analyst).unwrap();
    let agent = backend
        .create(Actor::Agent(
            irmind_domain::AgentId::parse("skills-agent").unwrap(),
        ))
        .unwrap();
    let verifier = LocalVerifier::from_signer(signer.as_ref())
        .with_trusted_key(&agent.actor(), &agent.public_key())
        .unwrap();
    let store = Arc::new(current_sources::open(root));
    let skills = irmind_app::SkillServices::new(
        Arc::new(irmind_infra::FileSkillPackageStore::new(root)),
        Arc::new(irmind_infra::TomlSkillCompiler),
        agent,
        irmind_infra::bundled_skill_candidates()
            .unwrap()
            .into_iter()
            .map(|candidate| candidate.package().clone())
            .collect(),
    )
    .unwrap();
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(signer.clone(), Arc::new(verifier)),
            Arc::new(MandatoryGuard::new().unwrap()),
        )
        .with_subagents(irmind_app::subagents::SubagentPorts {
            branches: Arc::new(irmind_infra::ParquetStore::open(root).unwrap()),
            queries: store.task_evidence_queries(store.source_evidence_reader()),
            analyst: Arc::new(irmind_app::subagents::AnalystPlanMailbox::default()),
        }),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
    .with_skills(skills)
    .unwrap();
    let case = engine.create_case(TITLE, "local only").unwrap();
    let prepared = engine
        .prepare_subagent_plan(
            &case.id,
            "00000000-0000-0000-0000-000000000009".parse().unwrap(),
            vec![irmind_app::subagents::SubagentTaskProposal {
                type_id: "triage".into(),
                objective: "Inspect synthetic evidence only".into(),
                sources: vec![],
                remote_scope: None,
                skill: None,
                budget: irmind_app::subagents::SubagentResources {
                    tokens: 100_000,
                    calls: 2,
                    rounds: 1,
                    cloud_bytes: 0,
                },
            }],
            irmind_app::subagents::SubagentResources::default(),
            &irmind_app::CancellationToken::new(),
        )
        .unwrap();
    drop(prepared); // Durable preview survives without a running worker or execution lease.
    assert!(engine.seal(&case.id).is_err());
    let config = root.join("keystore.toml");
    std::fs::write(
        &config,
        format!(
            "[keystore]\nsigner = \"file\"\nsecrets = \"file\"\nanalyst_key_fingerprint = \"{}\"\n",
            hex(&sha256(&signer.public_key()))
        ),
    )
    .unwrap();
    irmind_fs::private_file(&config).unwrap();
}
fn command(root: &Path) -> Command {
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.args(["-c", "stty cols 100 rows 32; exec \"$0\" --home \"$1\""])
            .arg(env!("CARGO_BIN_EXE_irmind"))
            .arg(root);
        c
    };
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd.exe");
        c.args(["/d", "/c", "chcp", "65001", ">nul", "&&"])
            .arg(env!("CARGO_BIN_EXE_irmind"))
            .arg("--home")
            .arg(root)
            .args(["<CONIN$", ">CONOUT$", "2>&1"]);
        c
    };
    cmd.env("TERM", "xterm-256color").env("NO_COLOR", "1");
    cmd
}
#[test]
fn interrupted_plan_requires_explicit_recovery_and_is_then_sealable() {
    let root = tempfile::tempdir().unwrap();
    seed(root.path());
    let mut session = DemoSession::spawn_sized(&command(root.path()), 100, 32).unwrap();
    session.timeout = std::time::Duration::from_secs(45);
    session.expect("Unlock").unwrap();
    session.send(format!("{PHRASE}\r")).unwrap();
    session.expect("Fingerprint").unwrap();
    session.send("\r").unwrap();
    session.expect("Find cases or type").unwrap();
    session.send(format!("/open {TITLE}\r")).unwrap();
    session.expect("Ask about the case").unwrap();
    session.send("/subagents recover\r").unwrap();
    session.expect("Close interrupted subagent plans?").unwrap();
    session
        .expect("uncertain provider usage are retained")
        .unwrap();
    session.send("\x1b").unwrap();
    session
        .expect_screen("Close interrupted subagent plans?", false)
        .unwrap();
    session.send("/subagents recover\r").unwrap();
    session.expect("Close interrupted subagent plans?").unwrap();
    session.send("2\r").unwrap();
    session
        .expect("Closed 1 interrupted subagent plans")
        .unwrap();
    session.send("/subagents recover\r").unwrap();
    session.expect("Close interrupted subagent plans?").unwrap();
    session.send("2\r").unwrap();
    session
        .expect("Closed 0 interrupted subagent plans")
        .unwrap();
    session.send("/seal\r").unwrap();
    session.expect("Final hash:").unwrap();
    session.send("2\r").unwrap();
    session.expect("Case sealed").unwrap();
    session.send("/quit\r").unwrap();
    session.expect("Exit IRMind?").unwrap();
    session.send("\r").unwrap();
}
