use super::CaseRuntime;
use crate::status_bar::StatusData;
use irmind_app::{
    AuditEventKind, StatusSegment, budget_status,
    subagents::{
        ReservationAction, SubagentPlanV1, SubagentRecord, SubagentReservationV1, SubagentResultV1,
        decode_subagent_record,
    },
};
use std::collections::{BTreeMap, BTreeSet};

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn footer_data(&self, view: &crate::case::CaseFrame<'_>) -> StatusData {
        let mut data = crate::status_bar::frame_data(view);
        data.extend(self.status_data.clone());
        data.insert(
            StatusSegment::Clock,
            chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now())
                .format("%H:%M:%S UTC")
                .to_string(),
        );
        data
    }

    pub(super) fn refresh_status_data(&mut self) -> super::Result<()> {
        let mut data = StatusData::default();
        data.insert(StatusSegment::Severity, self.state.case.severity.as_str());
        data.insert(
            StatusSegment::Seal,
            if self.state.case.sealed {
                "sealed"
            } else {
                "open"
            },
        );
        data.insert(
            StatusSegment::Version,
            format!("IRMind {}", env!("CARGO_PKG_VERSION")),
        );
        if let Some(directory) = &self.data_directory {
            data.insert(StatusSegment::DataDirectory, directory.to_string_lossy());
        }
        if let Ok(keystore) = self.io_ops.keystore_status() {
            data.insert(
                StatusSegment::Keystore,
                format!("{}/{}", keystore.signer_backend, keystore.secrets_backend),
            );
        }
        let status = budget_status(&self.state.entries, &self.engine.policy)?;
        data.insert(
            StatusSegment::ToolCalls,
            format!("{} calls", status.usage.tool_calls),
        );
        data.insert(
            StatusSegment::CloudBytes,
            format!("{} B cloud", status.usage.cloud_bytes),
        );
        if let Some(limits) = status.effective {
            data.insert(
                StatusSegment::TokenBudget,
                format!("of {} tok", limits.model_tokens),
            );
            data.insert(
                StatusSegment::CallBudget,
                format!("of {} calls", limits.tool_calls),
            );
            data.insert(
                StatusSegment::CloudBudget,
                format!("cloud limit {} B", limits.cloud_bytes),
            );
            if limits.model_tokens != 0 {
                let percent =
                    u128::from(status.usage.model_tokens) * 100 / u128::from(limits.model_tokens);
                data.insert(StatusSegment::TokenPercent, format!("{percent}% tokens"));
            }
        }
        let sources = self
            .state
            .entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.kind,
                    AuditEventKind::SourceManifestV2 | AuditEventKind::EvidenceIngested
                )
            })
            .filter_map(|entry| entry.evidence.as_deref())
            .collect::<BTreeSet<_>>();
        data.insert(StatusSegment::Sources, format!("{} sources", sources.len()));
        data.insert(
            StatusSegment::Subagents,
            format!("{} active children", active_children(&self.state.entries)?),
        );
        self.status_data = data;
        Ok(())
    }
}
fn active_children(entries: &[irmind_app::SignedEntry]) -> super::Result<usize> {
    let mut plans = BTreeMap::new();
    let mut active = BTreeSet::new();
    for entry in entries {
        match entry.kind {
            AuditEventKind::SubagentPlanV1 => {
                let plan: SubagentPlanV1 = decode_subagent_record(entry)
                    .map_err(|_| anyhow::anyhow!("invalid subagent status record"))?;
                let identity = plan
                    .identity()
                    .map_err(|_| anyhow::anyhow!("invalid subagent plan for status display"))?;
                plans.insert(
                    identity,
                    plan.tasks.iter().map(|t| t.task_id).collect::<Vec<_>>(),
                );
            }
            AuditEventKind::SubagentReservationV1 => {
                let value: SubagentReservationV1 = decode_subagent_record(entry)
                    .map_err(|_| anyhow::anyhow!("invalid subagent status record"))?;
                if value.action == ReservationAction::StartPlan
                    && let Some(tasks) = plans.get(&value.plan_sha256)
                {
                    active.extend(tasks.iter().copied());
                }
                if value.action == ReservationAction::ReleasePlan
                    && let Some(tasks) = plans.get(&value.plan_sha256)
                {
                    active.retain(|id| !tasks.contains(id));
                }
            }
            AuditEventKind::SubagentResultV1 => {
                let result: SubagentResultV1 = decode_subagent_record(entry)
                    .map_err(|_| anyhow::anyhow!("invalid subagent status record"))?;
                active.remove(&result.task_id);
            }
            _ => {}
        }
    }
    Ok(active.len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn entry<T: SubagentRecord>(value: &T) -> irmind_app::SignedEntry {
        serde_json::from_value(serde_json::json!({
            "seq": 1, "case_id": "11111111-1111-4111-8111-111111111111", "at": 0,
            "actor": "analyst", "origin": "synthetic", "kind": T::KIND.as_str(),
            "payload": value.audit_payload().unwrap(), "evidence": null,
            "prev": vec![0u8; 32], "hash": vec![0u8; 32], "sig": [], "public_key": []
        }))
        .unwrap()
    }
    #[test]
    fn active_children_decode_real_audit_payloads_and_remove_finished_tasks() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/development/subagent-format-vectors");
        let plan: SubagentPlanV1 =
            serde_json::from_slice(&std::fs::read(root.join("plan.json")).unwrap()).unwrap();
        let reservation: SubagentReservationV1 =
            serde_json::from_slice(&std::fs::read(root.join("reservation.json")).unwrap()).unwrap();
        let result: SubagentResultV1 =
            serde_json::from_slice(&std::fs::read(root.join("result.json")).unwrap()).unwrap();
        let mut entries = vec![entry(&plan), entry(&reservation)];
        assert_eq!(active_children(&entries).unwrap(), 1);
        entries.push(entry(&result));
        assert_eq!(active_children(&entries).unwrap(), 0);
        entries[0].payload = serde_json::to_string(&plan).unwrap();
        assert!(active_children(&entries).is_err());
    }
}
