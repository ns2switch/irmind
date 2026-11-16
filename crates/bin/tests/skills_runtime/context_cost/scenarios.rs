use super::*;
use irmind_app::LargeCaseUseCases;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Script {
    scenario: &'static str,
    hash: String,
    regular: Mutex<usize>,
    turn: AtomicUsize,
}
#[irmind_app::async_trait]
impl LlmPort for Script {
    fn output_profile(&self) -> irmind_app::ModelOutputProfile {
        irmind_app::ModelOutputProfile::known(4096, false).unwrap()
    }
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let compacting = request.messages[0]
            .content
            .starts_with("Summarize prior conversation");
        let (text, calls) = if compacting {
            (
                format!(
                    "Synthetic summary: source {} remains cited; pending question: correlate the next record. No finding is confirmed.",
                    self.hash
                ),
                vec![],
            )
        } else {
            let mut number = self.regular.lock().unwrap();
            let index = *number;
            *number += 1;
            self.response(index)
        };
        let usage = capture(
            self.scenario,
            self.turn.load(Ordering::SeqCst),
            &request,
            text.len(),
        );
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                raw: text.clone(),
                text,
                calls,
                truncated: false,
            },
            usage,
        ))
    }
}
impl Script {
    fn response(&self, index: usize) -> (String, Vec<ModelToolCall>) {
        if self.scenario == "conversation_10_turns" {
            return (format!("Synthetic answer {}. {}", index+1,
                "The analyst can review local evidence and confirm a finding only after checking its cited source. ".repeat(16)), vec![]);
        }
        let proposal = if index == 0 {
            Some(ProposedCall {
                tool: Tool::SkillRead,
                args: BTreeMap::from([("name".into(), "aws-credential-compromise".into())]),
            })
        } else if index < 14 {
            Some(ProposedCall {
                tool: Tool::TextSearch,
                args: BTreeMap::from([
                    ("query".into(), "Synthetic context measurement".into()),
                    ("limit".into(), (index + 6).to_string()),
                ]),
            })
        } else {
            None
        };
        let calls = proposal
            .map(|p| ModelToolCall::from_proposal(&format!("cost_{index}"), p).unwrap())
            .into_iter()
            .collect();
        let mut text = format!(
            "Synthetic review of source {} at step {}. Findings remain unconfirmed.",
            self.hash,
            index + 1
        );
        if self.scenario.ends_with("long_notes") {
            text.push_str(
                &" These are preliminary synthetic notes, not a confirmed finding.".repeat(64),
            );
        }
        (text, calls)
    }
}

#[test]
#[ignore = "provider-free development context measurements, explicit trace destination required"]
fn record_context_cost_conversation_and_fifteen_round_skill_investigation() {
    assert!(std::env::var_os("IRMIND_CONTEXT_COST_TRACE").is_some());
    for scenario in [
        "conversation_10_turns",
        "skill_15_rounds",
        "skill_15_rounds_long_notes",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (store, engine) = setup(root.path());
        let case = engine
            .create_case("Synthetic context cost", "local evidence only")
            .unwrap();
        let records: Vec<_> = (0..20)
            .map(|i| {
                serde_json::json!({
                    "eventTime":"2026-10-23T12:00:00Z","eventName":"ConsoleLogin",
                    "eventID":format!("synthetic-cost-{i}"),"awsRegion":"eu-west-1",
                    "recipientAccountId":"123456789012","sourceIPAddress":"203.0.113.77",
                    "userIdentity":{"type":"IAMUser","principalId":"synthetic-alice"},
                    "details":"Synthetic context measurement only. ".repeat(100)
                })
            })
            .collect();
        std::fs::write(
            root.path().join("source.json"),
            serde_json::to_vec(&serde_json::json!({"Records":records})).unwrap(),
        )
        .unwrap();
        let parser = crate::current_sources::parser("parser-json");
        let large = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: parser.as_ref(),
        };
        let ingested = large
            .ingest_local_batch(
                &case.id,
                root.path(),
                &["source.json".into()],
                false,
                &CancellationToken::new(),
            )
            .unwrap();
        let model = Script {
            scenario,
            hash: ingested[0].1.as_str().to_owned(),
            regular: Mutex::new(0),
            turn: AtomicUsize::new(1),
        };
        let turns = if scenario == "conversation_10_turns" {
            10
        } else {
            1
        };
        for turn in 1..=turns {
            model.turn.store(turn, Ordering::SeqCst);
            engine
                .investigate(
                    &case.id,
                    &format!("Explain the synthetic case, turn {turn}; no external calls."),
                    &model,
                )
                .unwrap();
        }
        assert_eq!(
            *model.regular.lock().unwrap(),
            if turns == 10 { 10 } else { 15 }
        );
        engine.verify(&case.id).unwrap();
    }
}
