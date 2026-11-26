//! Storage ownership, session leases and a durable deletion intent.
use super::{
    Actor, AppError, AuditLog, CancellationToken, CaseId, CaseLock, Connection, EvidenceStore,
    GLOBAL_OPERATION_SCOPE, HeldCaseFile, LocalStore, OpenOptions, Path, Repository,
    SignedOperation, fs, hex, params, private_dir, private_file, sha256, storage, verify_signature,
};
use fs4::fs_std::FileExt;
use irmind_app::{
    CaseDeletedV1, CaseDeletionInventory, CaseLifecycleError, CaseLifecycleStore, DeletionProgress,
    PreparedCaseDeletion, VerifiedCaseDeletion,
};
mod files;
mod inventory;
mod schema;
use files::{case_bytes, cleanup_case_files};
pub(super) use schema::install;

pub(super) struct OperationLease {
    pub(super) _session: fs::File,
    pub(super) _operation: fs::File,
}
impl CaseLock for OperationLease {}
struct HeldLease {
    _files: Vec<fs::File>,
}
impl CaseLock for HeldLease {}
struct Prepared<'a> {
    store: &'a LocalStore,
    inventory: CaseDeletionInventory,
    _leases: Vec<Box<dyn CaseLock>>,
    cancel: CancellationToken,
}
impl LocalStore {
    pub(crate) fn lease_file(
        &self,
        name: &str,
        shared: bool,
        wait: bool,
    ) -> Result<fs::File, AppError> {
        let path = self.lock_dir.join(name);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(storage)?;
        private_file(&path).map_err(storage)?;
        let acquired = if wait {
            if shared {
                FileExt::lock_shared(&file).map_err(storage)?;
            } else {
                FileExt::lock_exclusive(&file).map_err(storage)?;
            }
            true
        } else if shared {
            FileExt::try_lock_shared(&file).map_err(storage)?
        } else {
            FileExt::try_lock_exclusive(&file).map_err(storage)?
        };
        if !acquired {
            return Err(CaseLifecycleError::Busy.into());
        }
        Ok(file)
    }
    pub(crate) fn session_file(&self, id: &CaseId, shared: bool) -> Result<fs::File, AppError> {
        self.lease_file(&format!("{}.session", id.as_str()), shared, false)
    }
    pub(crate) fn evidence_maintenance(&self) -> Result<fs::File, AppError> {
        self.lease_file("evidence-maintenance.lock", true, true)
    }
    fn deletion_leases(&self, id: &CaseId) -> Result<Vec<Box<dyn CaseLock>>, AppError> {
        let files = vec![
            self.session_file(id, false)?,
            self.lease_file(id.as_str(), false, false)?,
            self.lease_file("evidence-maintenance.lock", false, false)?,
            self.lease_file("global-operations.lock", false, false)?,
        ];
        Ok(vec![Box::new(HeldLease { _files: files })])
    }
    pub(crate) fn reject_deleted(&self, id: &CaseId) -> Result<(), AppError> {
        let exists: bool = self
            .conn()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM case_deletion WHERE case_id=?1)",
                [id.as_str()],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if exists {
            return Err(CaseLifecycleError::Deleted.into());
        }
        Ok(())
    }
    fn require_unsealed_deletion(&self, id: &CaseId) -> Result<(), AppError> {
        let blocked:bool=self.conn()?.query_row("SELECT sealed!=0 OR seal_pending!=0 OR EXISTS(SELECT 1 FROM seal_intent WHERE case_id=?1) FROM cases WHERE id=?1",[id.as_str()],|r|r.get(0)).map_err(storage)?;
        if blocked
            || fs::symlink_metadata(self.seal_dir.join(format!("{}.json", id.as_str()))).is_ok()
        {
            return Err(AppError::Sealed);
        }
        Ok(())
    }
    fn finish_deletion(
        &self,
        receipt: &CaseDeletedV1,
        analyst_key: &[u8],
        cancel: &CancellationToken,
    ) -> Result<DeletionProgress, AppError> {
        let id = receipt.inventory()?.case_id;
        let exists: bool = self
            .conn()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
                [id.as_str()],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if exists {
            if self.check_stored_case_format(&id)? != analyst_key {
                return Err(CaseLifecycleError::InvalidReceipt.into());
            }
            self.require_unsealed_deletion(&id)?;
            inventory::check_tail(self, &id, receipt)?;
        }
        cleanup_case_files(self, &id, cancel)?;
        if exists {
            self.clean_shared_blobs(&id, cancel)?;
        }
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(storage)?;
        for table in ["evidence", "operational_audit", "audit", "cases"] {
            let column = if table == "cases" { "id" } else { "case_id" };
            tx.execute(
                &format!("DELETE FROM {table} WHERE {column}=?1"),
                [id.as_str()],
            )
            .map_err(storage)?;
        }
        tx.execute(
            "UPDATE case_deletion SET complete=1 WHERE case_id=?1",
            [id.as_str()],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        drop(conn);
        self.graph_catalog.lock().map_err(storage)?.remove(&id);
        Ok(DeletionProgress {
            case_id: id,
            complete: true,
            message: "Case data deleted. The signed tombstone remains; this is not secure erasure."
                .into(),
        })
    }
    fn clean_shared_blobs(&self, id: &CaseId, cancel: &CancellationToken) -> Result<(), AppError> {
        for hash in self.evidence_hashes(id)? {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let other: bool = self
                .conn()?
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM evidence WHERE hash=?1 AND case_id!=?2)",
                    params![hash, id.as_str()],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            if !other {
                files::unlink_blob(&self.evidence_dir, &hash)?;
            }
        }
        Ok(())
    }
}
impl CaseLifecycleStore for LocalStore {
    fn open_session(&self, id: &CaseId) -> Result<Box<dyn CaseLock>, AppError> {
        let file = self.session_file(id, true)?;
        self.get_case(id)?;
        Ok(Box::new(HeldCaseFile { _file: file }))
    }
    fn prepare_deletion(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn PreparedCaseDeletion + '_>, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let leases = self.deletion_leases(id)?;
        self.get_case(id)?;
        self.check_stored_case_format(id)?;
        self.require_unsealed_deletion(id)?;
        let inventory = inventory::measure(self, id, cancel)?;
        Ok(Box::new(Prepared {
            store: self,
            inventory,
            _leases: leases,
            cancel: cancel.clone(),
        }))
    }
    fn resume_deletion(
        &self,
        deletion: &VerifiedCaseDeletion,
        cancel: &CancellationToken,
    ) -> Result<DeletionProgress, AppError> {
        let receipt = deletion.receipt();
        let id = receipt.inventory()?.case_id;
        let _leases = self.deletion_leases(&id)?;
        let operation = deletion.operation();
        let stored = self
            .conn()?
            .query_row(
                "SELECT operation_seq,operation FROM case_deletion WHERE case_id=?1",
                [id.as_str()],
                |r| Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?)),
            )
            .map_err(storage)?;
        if stored.0 != operation.seq
            || stored.1 != operation.operation
            || CaseDeletedV1::decode(operation)?.as_ref() != Some(receipt)
        {
            return Err(CaseLifecycleError::InvalidReceipt.into());
        }
        let actual = self
            .global_operations()?
            .into_iter()
            .find(|e| e.seq == operation.seq)
            .ok_or(CaseLifecycleError::InvalidReceipt)?;
        if actual.hash != operation.hash
            || actual.sig != operation.sig
            || actual.operation != operation.operation
        {
            return Err(CaseLifecycleError::InvalidReceipt.into());
        }
        self.finish_deletion(receipt, &operation.public_key, cancel)
    }
}
impl PreparedCaseDeletion for Prepared<'_> {
    fn inventory(&self) -> &CaseDeletionInventory {
        &self.inventory
    }
    fn commit(self: Box<Self>, operation: &SignedOperation) -> Result<DeletionProgress, AppError> {
        if self.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let receipt =
            CaseDeletedV1::decode(operation)?.ok_or(CaseLifecycleError::InvalidReceipt)?;
        if receipt.inventory()? != self.inventory
            || inventory::measure(self.store, &self.inventory.case_id, &self.cancel)?
                != self.inventory
        {
            return Err(CaseLifecycleError::InvalidReceipt.into());
        }
        self.store
            .require_unsealed_deletion(&self.inventory.case_id)?;
        inventory::commit_intent(self.store, operation, &receipt)?;
        Ok(self
            .store
            .finish_deletion(&receipt, &operation.public_key, &self.cancel)
            .unwrap_or_else(|error| DeletionProgress {
                case_id: self.inventory.case_id.clone(),
                complete: false,
                message: format!("Signed deletion pending: {error}. Retry from /cases deleted."),
            }))
    }
}
