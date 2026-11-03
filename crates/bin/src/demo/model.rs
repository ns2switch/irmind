use super::EVENTS;
use futures_util::{StreamExt as _, stream};
use irmind_app::{
    AppError, CancellationToken, CompletionRequest, LlmPort, ModelEvent, ModelResponse,
    ModelStream, ModelToolCall, hex, sha256,
};
use irmind_domain::{ProposedCall, Tool};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

pub(super) struct ScriptedModel {
    round: AtomicUsize,
    source_hash: String,
    delay: Duration,
}

impl ScriptedModel {
    pub(super) fn new() -> Self {
        Self {
            round: AtomicUsize::new(0),
            source_hash: hex(&sha256(EVENTS)),
            delay: Duration::from_millis(80),
        }
    }
    pub(super) fn with_speed(speed: u8) -> Self {
        Self {
            delay: Duration::from_millis((80 / u64::from(speed.clamp(1, 50))).max(1)),
            ..Self::new()
        }
    }
    #[cfg(test)]
    pub(super) fn requests(&self) -> usize {
        self.round.load(Ordering::SeqCst)
    }
}

#[irmind_app::async_trait]
impl LlmPort for ScriptedModel {
    fn descriptor(&self) -> String {
        "scripted demo model · no network".into()
    }

    async fn complete(
        &self,
        _request: CompletionRequest,
        cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        let round = self.round.fetch_add(1, Ordering::SeqCst);
        let (text, proposals) = match round {
            0 => ("I will inspect the signed synthetic events first.", vec![ProposedCall { tool: Tool::TextSearch, args: BTreeMap::from([("query".into(), "203.0.113.77".into()), ("limit".into(), "3".into())]) }]),
            1 => ("The synthetic events suggest privilege escalation and cross-account access. I am proposing a finding and an external lookup; the latter requires your signed approval.", vec![
                ProposedCall { tool: Tool::CaseAddFinding, args: BTreeMap::from([
                    ("kind".into(), "hypothesis".into()),
                    ("value".into(), "evt-0004 → evt-0005 → evt-0006: arn:aws:iam::111122223333:user/alex attached AdministratorAccess, assumed arn:aws:iam::444455556666:role/CrossAccountAdmin, then created an access key. Possible T1078 and T1098.".into()),
                    ("evidence_hash".into(), self.source_hash.clone()),
                    ("supporting_evidence".into(), self.source_hash.clone()),
                ]) },
                ProposedCall { tool: Tool::ThreatIntelExternal, args: BTreeMap::from([("ioc".into(), "203.0.113.77".into())]) },
            ]),
            _ => ("The evidence points to an administrative policy attachment, a cross-account role assumption, and an access-key creation. A proposed finding is available for review. All data in this session is synthetic.", Vec::new()),
        };
        let calls = proposals
            .into_iter()
            .enumerate()
            .map(|(index, proposal)| {
                ModelToolCall::from_proposal(&format!("demo_{round}_{index}"), proposal)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let text = format!("{text} Source SHA-256: {}.", self.source_hash);
        let response = ModelResponse {
            text: text.clone(),
            calls,
            raw: "scripted-demo".into(),
            truncated: false,
        };
        let mut events = text
            .split_inclusive(char::is_whitespace)
            .map(|word| Ok(ModelEvent::TextDelta(word.into())))
            .collect::<Vec<_>>();
        events.push(Ok(ModelEvent::Completed {
            response,
            usage: None,
        }));
        let delay = self.delay;
        let cancel = cancel.clone();
        Ok(Box::pin(stream::iter(events).then(move |event| {
            let cancel = cancel.clone();
            async move {
                tokio::select! {
                    () = cancel.cancelled() => Err(AppError::Cancelled),
                    () = tokio::time::sleep(delay) => event,
                }
            }
        })))
    }
}
