use crate::case::conversation::{Card, CardKind};
use crate::case::state::CaseState;
use crate::case::{Engine, Result};
use irmind_app::{AuditEventKind, SignedEntry};

pub(super) fn audit_card(
    entry: &SignedEntry,
    state: &CaseState,
    engine: &Engine<'_>,
) -> Result<Option<Card>> {
    let card = match entry.kind {
        AuditEventKind::Prompt => Some(Card::new(
            CardKind::Analyst,
            "Analyst",
            engine.guard.screen(&entry.payload)?.text,
            false,
        )),
        AuditEventKind::Proposal => Some(Card::new(
            CardKind::Proposal,
            "Tool proposal",
            engine.guard.screen(&entry.payload)?.text,
            false,
        )),
        AuditEventKind::ModelReply => Some(Card::new(
            CardKind::Model,
            "IRMind",
            engine.guard.screen(&entry.payload)?.text,
            true,
        )),
        AuditEventKind::NeedsApproval => return approval_card(entry, state, engine),
        AuditEventKind::ApprovalGranted | AuditEventKind::ApprovalDenied => Some(Card::new(
            CardKind::Notice,
            entry.kind.as_str(),
            engine.guard.screen(&entry.payload)?.text,
            false,
        )),
        AuditEventKind::ToolDispatch => Some(Card::new(
            CardKind::Proposal,
            "Tool running",
            engine.guard.screen(&entry.payload)?.text,
            false,
        )),
        AuditEventKind::ToolResult => Some(Card::new(
            CardKind::ToolResult,
            "Tool result",
            format!(
                "{}\nEvidence: {}",
                engine.guard.screen(&entry.payload)?.text,
                entry.evidence.as_deref().unwrap_or("none")
            ),
            false,
        )),
        AuditEventKind::EvidenceIngested => Some(Card::new(
            CardKind::Evidence,
            "Evidence ingested",
            format!(
                "{}\nHash: {}",
                engine.guard.screen(&entry.payload)?.text,
                entry.evidence.as_deref().unwrap_or("none")
            ),
            false,
        )),
        AuditEventKind::FindingProposed
        | AuditEventKind::FindingConfirmed
        | AuditEventKind::FindingDismissed => Some(Card::new(
            CardKind::Finding,
            entry.kind.as_str(),
            engine.guard.screen(&entry.payload)?.text,
            false,
        )),
        AuditEventKind::InjectionDetected => Some(Card::new(
            CardKind::Notice,
            "Injection detected",
            engine.guard.screen(&entry.payload)?.text,
            false,
        )),
        _ => None,
    };
    Ok(card)
}

fn approval_card(
    entry: &SignedEntry,
    state: &CaseState,
    engine: &Engine<'_>,
) -> Result<Option<Card>> {
    let id = serde_json::from_str::<serde_json::Value>(&entry.payload)
        .ok()
        .and_then(|value| {
            value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    Ok(
        if let Some((id, request)) = id.and_then(|id| {
            state
                .approvals
                .iter()
                .find(|request| request.id == id)
                .map(|request| (id, request))
        }) {
            let source = state.approval_sources.get(&id).map_or_else(
                || "No tainted source fragment".into(),
                |source| {
                    format!(
                        "TAINTED {:?} · evidence {}\n{}",
                        source.provenance.source_kind(),
                        irmind_app::hex(source.provenance.evidence_hash()),
                        source.excerpt
                    )
                },
            );
            let detail = format!(
                "Tool: {}\nArguments: {:?}\nReason: analyst approval required\n{}\n[a approve · d deny · e edit]",
                request.tool.as_str(),
                request.args,
                source
            );
            Some(Card::new(
                CardKind::Approval(id),
                "Approval required",
                engine.guard.screen(&detail)?.text,
                false,
            ))
        } else {
            Some(Card::new(
                CardKind::Notice,
                "Approval requested",
                engine.guard.screen(&entry.payload)?.text,
                false,
            ))
        },
    )
}
