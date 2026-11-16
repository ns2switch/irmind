use super::{
    Actor, AppError, AuditLog, CancellationToken, CaseDeletedV1, CaseDeletionInventory, CaseId,
    CaseLifecycleError, EvidenceStore, GLOBAL_OPERATION_SCOPE, LocalStore, Repository,
    SignedOperation, case_bytes, files, hex, params, sha256, storage, verify_signature,
};
pub(super) fn measure(
    store: &LocalStore,
    id: &CaseId,
    cancel: &CancellationToken,
) -> Result<CaseDeletionInventory, AppError> {
    let case = store.get_case(id)?;
    let entries = store.entries(id)?;
    let first = entries.first().ok_or(CaseLifecycleError::InvalidReceipt)?;
    let last = entries.last().ok_or(CaseLifecycleError::InvalidReceipt)?;
    files::directory(&store.evidence_dir)?;
    let mut shared = 0u64;
    for hash in store.evidence_hashes(id)? {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let meta = files::regular_metadata(&store.evidence_dir.join(&hash))?;
        shared = shared
            .checked_add(meta.len())
            .ok_or(CaseLifecycleError::ScanLimit)?;
    }
    let conn = store.conn()?;
    let audit:u64=conn.query_row("SELECT COALESCE(SUM(length(CAST(payload AS BLOB))+length(CAST(actor AS BLOB))+length(CAST(origin AS BLOB))+length(CAST(kind AS BLOB))+COALESCE(length(evidence),0)+length(prev)+length(hash)+length(sig)+length(public_key)+24),0) FROM audit WHERE case_id=?1",[id.as_str()],|r|r.get(0)).map_err(storage)?;
    let operations:u64=conn.query_row("SELECT COALESCE(SUM(length(CAST(operation AS BLOB))+length(CAST(actor AS BLOB))+length(prev)+length(hash)+length(sig)+length(public_key)+16),0) FROM operational_audit WHERE case_id=?1",[id.as_str()],|r|r.get(0)).map_err(storage)?;
    let refs: u64 = conn
        .query_row(
            "SELECT COALESCE(SUM(length(hash)),0) FROM evidence WHERE case_id=?1",
            [id.as_str()],
            |r| r.get(0),
        )
        .map_err(storage)?;
    let metadata = audit
        .checked_add(operations)
        .and_then(|n| n.checked_add(refs))
        .and_then(|n| {
            n.checked_add(
                (case.title.len()
                    + case.scope.len()
                    + case.id.as_str().len()
                    + case.severity.as_str().len()
                    + 2) as u64,
            )
        })
        .ok_or(CaseLifecycleError::ScanLimit)?;
    Ok(CaseDeletionInventory {
        case_id: id.clone(),
        title: case.title,
        created_at: first.at,
        last_chain_hash: hex(&last.hash),
        entry_count: entries.len() as u64,
        source_count: entries
            .iter()
            .filter(|e| e.kind == irmind_domain::AuditEventKind::SourceManifestV2)
            .count() as u64,
        owned_file_bytes: case_bytes(store, id, cancel)?,
        shared_blob_bytes: shared,
        logical_metadata_bytes: metadata,
    })
}
pub(super) fn check_tail(
    store: &LocalStore,
    id: &CaseId,
    receipt: &CaseDeletedV1,
) -> Result<(), AppError> {
    let entries = store.entries(id)?;
    let mut previous = [0u8; 32];
    if entries.len() as u64 != receipt.entry_count {
        return Err(CaseLifecycleError::InvalidReceipt.into());
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.case_id != id.as_str()
            || entry.seq != index as u64 + 1
            || entry.prev != previous
            || sha256(&entry.canonical()) != entry.hash
        {
            return Err(CaseLifecycleError::InvalidReceipt.into());
        }
        previous = entry.hash;
    }
    if hex(&previous) != receipt.last_chain_hash {
        return Err(CaseLifecycleError::InvalidReceipt.into());
    }
    Ok(())
}
pub(super) fn commit_intent(
    store: &LocalStore,
    operation: &SignedOperation,
    receipt: &CaseDeletedV1,
) -> Result<(), AppError> {
    if operation.case_id != GLOBAL_OPERATION_SCOPE
        || operation.actor != Actor::Analyst
        || sha256(&operation.canonical()) != operation.hash
    {
        return Err(CaseLifecycleError::InvalidReceipt.into());
    }
    let id = receipt.inventory()?.case_id;
    let first = store
        .entries(&id)?
        .into_iter()
        .next()
        .ok_or(CaseLifecycleError::InvalidReceipt)?;
    if operation.public_key != first.public_key {
        return Err(CaseLifecycleError::InvalidReceipt.into());
    }
    verify_signature(&operation.public_key, &operation.hash, &operation.sig)?;
    let mut conn = store.conn()?;
    let tx = conn.transaction().map_err(storage)?;
    super::super::codec::append_global_operation_tx(&tx, operation)?;
    tx.execute(
        "INSERT INTO case_deletion(case_id,operation_seq,operation) VALUES (?1,?2,?3)",
        params![id.as_str(), operation.seq, operation.operation],
    )
    .map_err(storage)?;
    tx.commit().map_err(storage)
}
