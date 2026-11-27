use crate::{AppError, AuditEventKind, CancellationToken, CaseId, CaseLock, Engine, SignedEntry};
use serde_json::{Value, json};
use std::collections::VecDeque;

use super::wire::{self, Fault};

const MAX_PENDING_EVENTS: usize = 256;
const MAX_PENDING_BYTES: usize = 1024 * 1024;
// JSON escaping may expand controls to six bytes. Leave room for the envelope.
const ANSWER_PREVIEW_BYTES: usize = 8 * 1024;

pub(super) struct OpenCase {
    pub(super) cursor: u64,
    pub(super) subscription: Option<Subscription>,
    pub(super) needs_status: bool,
    pub(super) _lease: Box<dyn CaseLock>,
}

pub(super) fn admit(
    engine: &Engine<'_>,
    case_id: &CaseId,
    shutdown: &CancellationToken,
) -> Result<OpenCase, Fault> {
    let lease = engine
        .open_case_session(case_id)
        .map_err(Fault::from)?
        .ok_or(Fault::Scope)?;
    let case = engine
        .open_case_verified(case_id, shutdown)
        .map_err(Fault::from)?;
    if engine
        .case_scope_exceeds_policy(&case)
        .map_err(Fault::from)?
    {
        return Err(Fault::Scope);
    }
    Ok(OpenCase {
        cursor: 0,
        subscription: None,
        needs_status: false,
        _lease: lease,
    })
}

pub(super) fn status(
    engine: &Engine<'_>,
    case_id: &CaseId,
    shutdown: &CancellationToken,
) -> Result<(u64, Value), AppError> {
    let _lock = engine.repo.lock_case(case_id)?;
    engine.verify_unlocked_cancelable(case_id, shutdown)?;
    let case = engine.repo.get_case(case_id)?;
    if engine.case_scope_exceeds_policy(&case)? {
        return Err(AppError::InvalidCaseId);
    }
    let entries = engine.audit_log.entries(case_id)?;
    let cursor = entries.last().ok_or(AppError::InvalidChain(0))?.seq;
    let sources = entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        .count();
    let mut rejected = 0;
    for entry in entries.iter().filter(|entry| entry.origin == "system") {
        if crate::RejectedSource::from_audit(entry)?.is_some() {
            rejected += 1;
        }
    }
    let folder = crate::ingest_outcome::FileOutcomeReview::read(&entries)?;
    let blobs = engine.evidence_store.evidence_hashes(case_id)?.len();
    let indexed_summary = engine
        .graph
        .graph_summary(case_id)
        .ok()
        .map(|summary| {
            engine.guard.screen(&summary).map(|screened| {
                crate::ports::model::output::utf8_prefix(&screened.text, 4096).to_owned()
            })
        })
        .transpose()?;
    Ok((
        cursor,
        json!({
            "case_id": case_id.as_str(),
            "cursor": cursor,
            "sealed": case.sealed,
            "evidence": {
                "sources": sources,
                "local_evidence_blobs": blobs,
                "decoder_rejections": rejected,
                "folder_skipped": folder.skipped,
                "folder_failed": folder.failed,
                "integrity_matches": folder.matched,
                "integrity_mismatches": folder.mismatched,
                "indexed_summary": indexed_summary,
            }
        }),
    ))
}

pub(super) struct Subscription {
    after: u64,
    seen: Option<[u8; 32]>,
    pending: VecDeque<EventFrame>,
}

pub(super) struct EventFrame {
    pub(super) seq: u64,
    pub(super) bytes: Vec<u8>,
    pub(super) resync: bool,
}

impl Subscription {
    pub(super) const fn new(after: u64) -> Self {
        Self {
            after,
            seen: None,
            pending: VecDeque::new(),
        }
    }

    pub(super) fn next(
        &mut self,
        engine: &Engine<'_>,
        case_id: &CaseId,
        shutdown: &CancellationToken,
    ) -> Result<Option<EventFrame>, Fault> {
        if let Some(pending) = self.pending.pop_front() {
            return Ok(Some(pending));
        }
        let tip = engine
            .audit_log
            .last_entry(case_id)
            .map_err(Fault::from)?
            .ok_or(Fault::Scope)?;
        if self.seen == Some(tip.hash) {
            return Ok(None);
        }
        let entries = engine.audit_log.entries(case_id).map_err(Fault::from)?;
        let scanned = entries.last().ok_or(Fault::Scope)?;
        if scanned.seq < self.after
            || self
                .seen
                .is_some_and(|seen| !entries.iter().any(|entry| entry.hash == seen))
        {
            return Err(Fault::Resync);
        }
        self.verify_and_queue(engine, case_id, scanned.seq, &entries, shutdown)?;
        self.seen = Some(scanned.hash);
        self.after = scanned.seq;
        Ok(self.pending.pop_front())
    }

    fn verify_and_queue(
        &mut self,
        engine: &Engine<'_>,
        case: &CaseId,
        tip: u64,
        entries: &[SignedEntry],
        shutdown: &CancellationToken,
    ) -> Result<(), Fault> {
        let mut head = [0; 32];
        let mut bytes = 0;
        let mut resync = false;
        for (index, entry) in entries.iter().enumerate() {
            if shutdown.is_cancelled() {
                return Err(Fault::Cancelled);
            }
            head = engine
                .verify_chain_entry(case, index, head, entry)
                .map_err(Fault::from)?;
            if entry.seq <= self.after || resync {
                continue;
            }
            if let Some(event) = projection(engine, case, entry)? {
                bytes += event.len();
                if self.pending.len() == MAX_PENDING_EVENTS || bytes > MAX_PENDING_BYTES {
                    self.pending.clear();
                    resync = true;
                    continue;
                }
                self.pending.push_back(EventFrame {
                    seq: entry.seq,
                    bytes: event,
                    resync: false,
                });
            }
        }
        if resync {
            self.pending.push_back(EventFrame {
                seq: tip,
                bytes: event_frame(
                    case,
                    tip,
                    "case_status",
                    &json!({"state":"resync_required"}),
                )?,
                resync: true,
            });
        }
        Ok(())
    }
}

fn projection(
    engine: &Engine<'_>,
    case: &CaseId,
    entry: &SignedEntry,
) -> Result<Option<Vec<u8>>, Fault> {
    let (kind, payload) = match entry.kind {
        AuditEventKind::CaseCreated => ("case_status", json!({"state":"created"})),
        AuditEventKind::CaseSealed => ("case_status", json!({"state":"sealed"})),
        AuditEventKind::SourceManifestV2 => ("case_status", json!({"state":"evidence_added"})),
        AuditEventKind::Prompt => ("turn_state", json!({"state":"started"})),
        AuditEventKind::ModelRequest => ("turn_state", json!({"state":"model_requested"})),
        AuditEventKind::Cancelled => ("turn_state", json!({"state":"cancelled"})),
        AuditEventKind::ModelError => ("turn_state", json!({"state":"model_error"})),
        AuditEventKind::SubagentCheckpointV1 => {
            ("turn_state", json!({"state":"subagent_checkpoint"}))
        }
        AuditEventKind::Proposal => ("tool_projection", json!({"state":"proposed"})),
        AuditEventKind::ToolResult => ("tool_projection", json!({"state":"settled"})),
        AuditEventKind::NeedsApproval => ("approval_state", json!({"state":"review_in_tui"})),
        AuditEventKind::ApprovalGranted => ("approval_state", json!({"state":"granted_in_irmind"})),
        AuditEventKind::ApprovalDenied => ("approval_state", json!({"state":"denied_in_irmind"})),
        AuditEventKind::FinalAnswer => {
            let guarded =
                crate::ports::model::output::screen_output(engine.guard.as_ref(), &entry.payload)
                    .map_err(Fault::from)?;
            let preview = crate::ports::model::output::utf8_prefix(&guarded, ANSWER_PREVIEW_BYTES);
            (
                "turn_state",
                json!({"state":"answer", "text":preview, "clipped":preview.len() < guarded.len()}),
            )
        }
        _ => return Ok(None),
    };
    event_frame(case, entry.seq, kind, &payload).map(Some)
}

fn event_frame(
    case: &CaseId,
    seq: u64,
    kind: &'static str,
    payload: &Value,
) -> Result<Vec<u8>, Fault> {
    wire::frame(json!({"case_id":case.as_str(), "seq":seq, "kind":kind, "payload":payload}))
        .map_err(|_| Fault::Invalid)
}
