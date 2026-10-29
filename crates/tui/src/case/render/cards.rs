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
        AuditEventKind::Proposal | AuditEventKind::ToolDispatch => Some(Card::new(
            CardKind::Proposal,
            engine.guard.screen(&friendly_call(&entry.payload))?.text,
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
        AuditEventKind::ToolResult => Some(Card::new(
            CardKind::ToolResult,
            "Tool result",
            format!(
                "{}\nEvidence: {}",
                engine.guard.screen(&entry.payload)?.text,
                entry
                    .evidence
                    .as_deref()
                    .map_or_else(|| "none".into(), short_hash)
            ),
            false,
        )),
        AuditEventKind::EvidenceIngested => Some(Card::new(
            CardKind::Notice,
            "Evidence ingested",
            format!(
                "Evidence ingested · {} · {}",
                engine.guard.screen(&entry.payload)?.text,
                entry
                    .evidence
                    .as_deref()
                    .map_or_else(|| "none".into(), short_hash)
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
                        "UNTRUSTED {} · {:?} · evidence {} · {}\n{}",
                        source.source_label,
                        source.provenance.source_kind(),
                        short_hash(&irmind_app::hex(source.provenance.evidence_hash())),
                        source.provenance.record_index().map_or_else(
                            || "record unavailable".into(),
                            |record| format!("record {record}")
                        ),
                        highlight_match(&source.excerpt, &request.args)
                    )
                },
            );
            let tool = friendly_tool(request.tool.as_str());
            let target = request
                .args
                .values()
                .next()
                .map_or("the selected value", String::as_str);
            let question = if request.tool.as_str().contains("external") {
                format!(
                    "Allow IRMind to send {target} to {tool}? This value will leave this computer."
                )
            } else {
                format!("Allow IRMind to run {tool} for {target}?")
            };
            let detail = format!(
                "{question}\nTool: {}\nExact arguments: {}\nReason: analyst approval required\n{}",
                request.tool.as_str(),
                serde_json::to_string(&request.args)?,
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

fn short_hash(hash: &str) -> String {
    if hash.len() <= 20 {
        return hash.to_owned();
    }
    format!("{}…{}", &hash[..8], &hash[hash.len() - 7..])
}

fn friendly_tool(value: &str) -> String {
    let name = value.split_whitespace().next().unwrap_or(value);
    match name {
        "ti_lookup_external" => "VirusTotal lookup".into(),
        "siem_search" => "Splunk search".into(),
        "siem_get_alert" => "SIEM alert".into(),
        "cloud_audit_events" => "Cloud audit events".into(),
        "edr_process_tree" => "EDR process tree".into(),
        other => other.replace('_', " "),
    }
}

fn friendly_call(payload: &str) -> String {
    let (tool, arguments) = payload.split_once(' ').unwrap_or((payload, ""));
    let name = friendly_tool(tool);
    let Ok(value) = serde_json::from_str::<serde_json::Value>(arguments) else {
        return name;
    };
    let Some(object) = value.as_object() else {
        return name;
    };
    let primary = ["ioc", "host", "query", "id", "source"]
        .iter()
        .find_map(|key| object.get(*key).and_then(serde_json::Value::as_str));
    primary.map_or(name.clone(), |value| {
        let value = value.chars().take(60).collect::<String>();
        format!("{name}({value})")
    })
}

fn highlight_match(excerpt: &str, args: &std::collections::BTreeMap<String, String>) -> String {
    let Some(value) = args
        .values()
        .find(|value| value.len() >= 4 && excerpt.contains(value.as_str()))
    else {
        return excerpt.to_owned();
    };
    excerpt.replacen(value, &format!("⟦{value}⟧"), 1)
}

#[cfg(test)]
mod tests {
    use super::friendly_call;

    #[test]
    fn proposal_title_names_the_tool_and_primary_argument() {
        assert_eq!(
            friendly_call("ti_lookup_external {\"ioc\":\"example.com\"}"),
            "VirusTotal lookup(example.com)"
        );
    }
}
