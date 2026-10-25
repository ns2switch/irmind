use anyhow::{Context, Result};
use irmind_app::{CancellationToken, CancelledOperation};
use std::collections::BTreeMap;

pub(super) type ActiveTask<'scope> = (
    CancellationToken,
    std::thread::ScopedJoinHandle<'scope, Result<String, irmind_app::AppError>>,
    &'static str,
);

pub(super) fn parse_approval_args(value: &str) -> Result<BTreeMap<String, String>> {
    serde_json::from_str(value).context("approval arguments must be a JSON object of strings")
}

pub(super) fn cancelled_operation(label: &str) -> CancelledOperation {
    match label {
        "Ingest" => CancelledOperation::Ingest,
        "Verify" => CancelledOperation::Verify,
        "Rebuild graph" => CancelledOperation::GraphRebuild,
        "Approval" => CancelledOperation::Approval,
        "Export" => CancelledOperation::Export,
        "Seal" | "Prepare seal" => CancelledOperation::Seal,
        "Save evidence" => CancelledOperation::EvidenceSave,
        _ => CancelledOperation::Investigation,
    }
}
