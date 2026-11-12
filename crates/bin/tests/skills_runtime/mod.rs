mod authorization;
mod malicious;
mod sequence;
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, CancellationToken, CompletionRequest, CryptoPorts, Engine, EnginePorts, LlmPort,
    ModelEvent, ModelResponse, ModelStream, ModelToolCall, Signer, SkillServices,
};
use irmind_domain::{Actor, AgentId, ExecutionMode, ProposedCall, Tool};
use irmind_infra::{
    FileSkillPackageStore, LocalStore, LocalVerifier, SystemClock, TomlSkillCompiler,
};
use irmind_security::MandatoryGuard;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

struct FixedSigner(Actor, SigningKey, bool);
impl Signer for FixedSigner {
    fn actor(&self) -> Actor {
        self.0.clone()
    }
    fn public_key(&self) -> Vec<u8> {
        self.1.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AppError> {
        if self.2 {
            return Err(irmind_app::SkillServiceError::Storage.into());
        }
        Ok(self.1.sign(message).to_bytes().to_vec())
    }
}
pub(super) fn setup(root: &Path) -> (Arc<LocalStore>, Engine<'static>) {
    setup_with_agent_failure(root, false)
}
pub(super) fn setup_with_agent_failure(
    root: &Path,
    fail: bool,
) -> (Arc<LocalStore>, Engine<'static>) {
    let store = Arc::new(super::current_sources::open(&root.join("data")));
    let analyst = Arc::new(FixedSigner(
        Actor::Analyst,
        SigningKey::from_bytes(&[73; 32]),
        false,
    ));
    let agent = Arc::new(FixedSigner(
        Actor::Agent(AgentId::parse("scripted-skills").unwrap()),
        SigningKey::from_bytes(&[74; 32]),
        fail,
    ));
    let verifier = LocalVerifier::from_signer(analyst.as_ref())
        .with_trusted_key(&agent.actor(), &agent.public_key())
        .unwrap();
    let skills = SkillServices::new(
        Arc::new(FileSkillPackageStore::new(root)),
        Arc::new(TomlSkillCompiler),
        agent,
        irmind_infra::bundled_skill_candidates()
            .unwrap()
            .into_iter()
            .map(|s| s.package().clone())
            .collect(),
    )
    .unwrap();
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(analyst, Arc::new(verifier)),
            Arc::new(MandatoryGuard::new().unwrap()),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
    .with_skills(skills)
    .unwrap();
    (store, engine)
}
pub(super) struct Episode {
    pub(super) requests: Mutex<Vec<CompletionRequest>>,
    name: String,
    term: String,
    hash: String,
}
impl Episode {
    pub(super) fn new(name: &str, term: &str, hash: &str) -> Self {
        Self {
            requests: Mutex::default(),
            name: name.into(),
            term: term.into(),
            hash: hash.into(),
        }
    }
    fn conclusion(&self) -> (&'static str, &'static str) {
        match self.name.as_str() {
            "windows-triage" => (
                "Recorded PowerShell launch and scheduled task creation",
                "T1053.005",
            ),
            "linux-triage" => (
                "Failed SSH login followed by accepted public-key authentication",
                "T1078",
            ),
            "aws-credential-compromise" => (
                "Recorded IAM policy attachment and role assumption",
                "T1098",
            ),
            _ => unreachable!("scripted synthetic episode"),
        }
    }
    fn calls(&self, round: usize) -> Vec<ModelToolCall> {
        let mut calls = self
            .proposal(round)
            .map(|p| ModelToolCall::from_proposal(&format!("episode_{round}"), p).unwrap())
            .into_iter()
            .collect::<Vec<_>>();
        if round == 2 {
            calls.push(
                ModelToolCall::from_proposal(
                    "episode_technique",
                    ProposedCall {
                        tool: Tool::CaseAddFinding,
                        args: BTreeMap::from([
                            ("kind".into(), "technique".into()),
                            ("value".into(), self.conclusion().1.into()),
                            ("technique_id".into(), self.conclusion().1.into()),
                            ("evidence_hash".into(), self.hash.clone()),
                        ]),
                    },
                )
                .unwrap(),
            );
        }
        calls
    }
    fn proposal(&self, round: usize) -> Option<ProposedCall> {
        let (tool, args) = match round {
            0 => (Tool::SkillRead, vec![("name", self.name.clone())]),
            1 => (
                Tool::TextSearch,
                vec![("query", self.term.clone()), ("limit", "10".into())],
            ),
            2 => (
                Tool::CaseAddFinding,
                vec![
                    ("kind", "hypothesis".into()),
                    ("value", self.conclusion().0.into()),
                    ("evidence_hash", self.hash.clone()),
                    ("supporting_evidence", self.hash.clone()),
                ],
            ),
            _ => return None,
        };
        Some(ProposedCall {
            tool,
            args: args
                .into_iter()
                .map(|(k, v)| (k.into(), v))
                .collect::<BTreeMap<_, _>>(),
        })
    }
}
#[irmind_app::async_trait]
impl LlmPort for Episode {
    async fn complete(
        &self,
        request: CompletionRequest,
        _cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        let mut requests = self.requests.lock().unwrap();
        let round = requests.len();
        if round == 2 {
            let search = request
                .messages
                .iter()
                .rev()
                .find(|m| m.tool_call_id.as_deref() == Some("episode_1"))
                .unwrap();
            assert!(
                search.content.contains(&self.hash),
                "search must return real evidence: {}",
                search.content
            );
        }
        requests.push(request);
        let calls = self.calls(round);
        Ok(Box::pin(futures_util::stream::iter([Ok(
            ModelEvent::Completed {
                response: ModelResponse {
                    truncated: false,
                    text: if round >= 3 {
                        format!("Synthetic finding supported by {}", self.hash)
                    } else {
                        String::new()
                    },
                    raw: "scripted".into(),
                    calls,
                },
                usage: None,
            },
        )])))
    }
}
