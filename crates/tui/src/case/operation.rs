use irmind_app::CancelledOperation;

pub(super) fn cancelled_operation(label: &str) -> CancelledOperation {
    match label {
        "Ingest" => CancelledOperation::Ingest,
        "Verify" => CancelledOperation::Verify,
        "Rebuild graph" => CancelledOperation::GraphRebuild,
        "Approval" => CancelledOperation::Approval,
        "Export" => CancelledOperation::Export,
        "Seal" => CancelledOperation::Seal,
        "Save evidence" => CancelledOperation::EvidenceSave,
        _ => CancelledOperation::Investigation,
    }
}
