use super::Scenario;
use crate::support::sequence::call;
use irmind_app::{
    AppError, CancellationToken, CompletionRequest, LlmPort, MessageRole, ModelEvent,
    ModelResponse, ModelStream, ModelToolCall,
};
use irmind_domain::{ProposedCall, Tool};
use std::sync::Mutex;

pub(super) struct Episode {
    pub(super) requests: Mutex<Vec<CompletionRequest>>,
    scenario: &'static Scenario,
    hashes: Vec<String>,
}
impl Episode {
    pub(super) fn final_text(&self) -> String {
        format!(
            "{} Evidence: {}",
            self.scenario.conclusion,
            self.hashes.join(", ")
        )
    }
    pub(super) fn new(scenario: &'static Scenario, hashes: Vec<String>) -> Self {
        Self {
            requests: Mutex::default(),
            scenario,
            hashes,
        }
    }
    fn calls(&self, round: usize) -> Vec<ProposedCall> {
        let s = self.scenario;
        let hash = self.hashes[s.selected_source].as_str();
        match round {
            0 => vec![call(Tool::SkillRead, &[("name", s.name)])],
            1 => vec![call(Tool::GraphSummary, &[])],
            2 => {
                let mut args = vec![("query", s.query), ("limit", "20")];
                args.extend_from_slice(s.filters);
                vec![call(Tool::TextSearch, &args)]
            }
            3 => vec![call(Tool::RawRecords, &[("hash", hash), ("index", "0")])],
            4 if s.name == "linux-persistence" => vec![call(
                Tool::TextSearch,
                &[("query", "crontab"), ("limit", "20")],
            )],
            4 => vec![call(
                Tool::EntityTimeline,
                &[("kind", "ip"), ("value", "203.0.113.77"), ("limit", "20")],
            )],
            5 => vec![
                call(
                    Tool::CaseAddFinding,
                    &[
                        ("kind", "hypothesis"),
                        ("value", s.conclusion),
                        ("evidence_hash", hash),
                        ("supporting_evidence", &self.hashes.join(",")),
                    ],
                ),
                call(
                    Tool::CaseAddFinding,
                    &[
                        ("kind", "technique"),
                        ("value", s.technique),
                        ("technique_id", s.technique),
                        ("evidence_hash", hash),
                    ],
                ),
            ],
            _ => vec![],
        }
    }
    fn validate_result(&self, request: &CompletionRequest, round: usize) {
        if (3..=5).contains(&round) {
            let previous = format!("catalog_{}_0", round - 1);
            let result = request
                .messages
                .iter()
                .find(|m| m.tool_call_id.as_deref() == Some(&previous))
                .unwrap();
            assert_eq!(result.role, MessageRole::Tool);
            assert!(result.content.contains("<UNTRUSTED_"), "{}", result.content);
            let expected = if round == 5 {
                &self.hashes[0]
            } else {
                &self.hashes[self.scenario.selected_source]
            };
            assert!(
                result.content.contains(expected),
                "{}: {}",
                self.scenario.name,
                result.content
            );
        }
    }
}
#[irmind_app::async_trait]
impl LlmPort for Episode {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let mut requests = self.requests.lock().unwrap();
        let round = requests.len();
        self.validate_result(&request, round);
        requests.push(request);
        let calls = self
            .calls(round)
            .into_iter()
            .enumerate()
            .map(|(i, c)| ModelToolCall::from_proposal(&format!("catalog_{round}_{i}"), c).unwrap())
            .collect();
        Ok(Box::pin(futures_util::stream::iter([Ok(
            ModelEvent::Completed {
                response: ModelResponse {
                    truncated: false,
                    text: if round >= 6 {
                        self.final_text()
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
