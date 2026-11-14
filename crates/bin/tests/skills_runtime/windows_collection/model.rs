use super::super::sequence::call;
use irmind_app::{
    AppError, CancellationToken, CompletionRequest, LlmPort, MessageRole, ModelEvent,
    ModelResponse, ModelStream, ModelToolCall,
};
use irmind_domain::{ProposedCall, Tool};
use std::{collections::BTreeMap, sync::Mutex};

pub(super) struct Collection {
    pub(super) requests: Mutex<Vec<CompletionRequest>>,
    hashes: BTreeMap<String, String>,
}
impl Collection {
    pub(super) fn new(hashes: BTreeMap<String, String>) -> Self {
        Self {
            requests: Mutex::default(),
            hashes,
        }
    }
    fn calls(&self, round: usize) -> Vec<ProposedCall> {
        match round {
            0 => vec![call(Tool::SkillRead, &[("name", "windows-triage")])],
            1 => vec![call(Tool::GraphSummary, &[])],
            2 => vec![call(
                Tool::TextSearch,
                &[("query", "demo-agent"), ("limit", "20")],
            )],
            3 => {
                let mut reads = self
                    .hashes
                    .values()
                    .map(|hash| {
                        call(
                            Tool::RawRecords,
                            &[("hash", hash), ("index", "0"), ("view", "original")],
                        )
                    })
                    .collect::<Vec<_>>();
                reads.push(call(
                    Tool::RawRecords,
                    &[
                        ("hash", &self.hashes["hayabusa.jsonl"]),
                        ("index", "1"),
                        ("view", "original"),
                    ],
                ));
                reads
            }
            4 => vec![call(
                Tool::EntityTimeline,
                &[
                    ("kind", "host"),
                    ("value", "synthetic-win-01"),
                    ("limit", "20"),
                ],
            )],
            5 => self.findings(),
            _ => vec![],
        }
    }
    fn findings(&self) -> Vec<ProposedCall> {
        let hash = &self.hashes["evtxecmd.csv"];
        vec![
            call(
                Tool::CaseAddFinding,
                &[
                    ("kind", "hypothesis"),
                    (
                        "value",
                        "Observed synthetic scheduled-task registration alongside exported execution and persistence artifacts; cache presence alone does not prove execution.",
                    ),
                    ("evidence_hash", hash),
                    (
                        "supporting_evidence",
                        &self.hashes.values().cloned().collect::<Vec<_>>().join(","),
                    ),
                ],
            ),
            call(
                Tool::CaseAddFinding,
                &[
                    ("kind", "technique"),
                    ("value", "T1053.005"),
                    ("technique_id", "T1053.005"),
                    ("evidence_hash", hash),
                ],
            ),
        ]
    }
    fn observe(&self, request: &CompletionRequest, round: usize) {
        if round != 4 {
            return;
        }
        let originals = request
            .messages
            .iter()
            .filter(|m| m.role == MessageRole::Tool && m.content.contains("view=original"))
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for field in [
            "TaskAction",
            "4698",
            "RunCount",
            "KeyPath",
            "ValueData",
            "LastModifiedTimeUTC",
            "Unknown",
            "BytesSent",
        ] {
            assert!(
                originals.contains(field),
                "Missing source fact: {field}: {originals}"
            );
        }
        for hash in self.hashes.values() {
            assert!(originals.contains(hash));
        }
    }
}

#[irmind_app::async_trait]
impl LlmPort for Collection {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let mut requests = self.requests.lock().unwrap();
        let round = requests.len();
        self.observe(&request, round);
        requests.push(request);
        let calls = self
            .calls(round)
            .into_iter()
            .enumerate()
            .map(|(index, call)| {
                ModelToolCall::from_proposal(&format!("collection_{round}_{index}"), call).unwrap()
            })
            .collect();
        let text = if round == 6 {
            format!(
                "The exported observations support a synthetic persistence hypothesis. Cache presence alone does not prove execution. No exfiltration conclusion is established. Evidence: {}",
                self.hashes.values().cloned().collect::<Vec<_>>().join(", ")
            )
        } else {
            String::new()
        };
        Ok(Box::pin(futures_util::stream::iter([Ok(
            ModelEvent::Completed {
                response: ModelResponse {
                    truncated: false,
                    text,
                    raw: "scripted".into(),
                    calls,
                },
                usage: None,
            },
        )])))
    }
}
