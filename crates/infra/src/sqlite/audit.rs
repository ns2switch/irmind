use super::codec::{append_entry_tx, map_entry, map_operation};
use super::*;

impl AuditLog for LocalStore {
    fn last_entry(&self, id: &CaseId) -> Result<Option<SignedEntry>, AppError> {
        self.conn()?.query_row("SELECT case_id,seq,at,actor,origin,kind,payload,evidence,prev,hash,sig,public_key FROM audit WHERE case_id=?1 ORDER BY seq DESC LIMIT 1", [id.as_str()], map_entry)
            .optional().map_err(storage)
    }

    fn transact(&self, entry: &SignedEntry, mutation: CaseMutation) -> Result<(), AppError> {
        if self
            .seal_dir
            .join(format!("{}.json", entry.case_id))
            .exists()
        {
            return Err(AppError::Sealed);
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(storage)?;
        if let CaseMutation::Create(case) = &mutation {
            if case.id.as_str() != entry.case_id
                || case.sealed
                || entry.kind != irmind_domain::AuditEventKind::CaseCreated
                || entry.actor != Actor::Analyst
            {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                    irmind_app::AdapterPolicyError::InvalidCaseCreationTransaction,
                )));
            }
            tx.execute(
                "INSERT INTO cases (id,title,scope,severity) VALUES (?1,?2,?3,?4)",
                params![
                    case.id.as_str(),
                    case.title,
                    case.scope,
                    case.severity.as_str()
                ],
            )
            .map_err(storage)?;
        }
        append_entry_tx(&tx, entry)?;
        match mutation {
            CaseMutation::None | CaseMutation::Create(_) => {}
            CaseMutation::Scope { id, new_scope } => {
                if entry.case_id != id.as_str()
                    || entry.kind != irmind_domain::AuditEventKind::CaseScopeChanged
                    || entry.actor != Actor::Analyst
                {
                    return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                        irmind_app::AdapterPolicyError::InvalidCaseScopeTransaction,
                    )));
                }
                let changed = tx
                    .execute(
                        "UPDATE cases SET scope=?1 WHERE id=?2 AND sealed=0",
                        params![new_scope, id.as_str()],
                    )
                    .map_err(storage)?;
                if changed != 1 {
                    return Err(AppError::Sealed);
                }
            }
            CaseMutation::Seal(id) => {
                if entry.case_id != id.as_str()
                    || entry.kind != irmind_domain::AuditEventKind::CaseSealed
                    || entry.actor != Actor::Analyst
                {
                    return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                        irmind_app::AdapterPolicyError::InvalidCaseSealTransaction,
                    )));
                }
                let changed = tx
                    .execute(
                        "UPDATE cases SET sealed=1, seal_pending=1 WHERE id=?1 AND sealed=0",
                        [id.as_str()],
                    )
                    .map_err(storage)?;
                if changed != 1 {
                    return Err(AppError::Sealed);
                }
            }
        }
        tx.commit().map_err(storage)
    }

    fn append_batch(&self, entries: &[SignedEntry]) -> Result<(), AppError> {
        let first = entries
            .first()
            .ok_or_else(|| storage_reason("empty audit batch"))?;
        CaseId::parse(&first.case_id).map_err(|_| storage_reason("invalid audit batch case"))?;
        if entries.iter().any(|entry| entry.case_id != first.case_id) {
            return Err(storage_reason("audit batch spans multiple cases"));
        }
        if self
            .seal_dir
            .join(format!("{}.json", first.case_id))
            .exists()
        {
            return Err(AppError::Sealed);
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(storage)?;
        for entry in entries {
            append_entry_tx(&tx, entry)?;
        }
        tx.commit().map_err(storage)
    }

    fn entries(&self, id: &CaseId) -> Result<Vec<SignedEntry>, AppError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT case_id,seq,at,actor,origin,kind,payload,evidence,prev,hash,sig,public_key FROM audit WHERE case_id=?1 ORDER BY seq").map_err(storage)?;
        stmt.query_map([id.as_str()], map_entry)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)
    }

    fn last_operation(&self, id: &CaseId) -> Result<Option<SignedOperation>, AppError> {
        self.conn()?.query_row("SELECT case_id,seq,at,actor,operation,prev,hash,sig,public_key FROM operational_audit WHERE case_id=?1 ORDER BY seq DESC LIMIT 1", [id.as_str()], map_operation)
            .optional().map_err(storage)
    }

    fn append_operation(&self, entry: &SignedOperation) -> Result<(), AppError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(storage)?;
        let last: Option<(u64, Vec<u8>)> = tx
            .query_row(
                "SELECT seq,hash FROM operational_audit WHERE case_id=?1 ORDER BY seq DESC LIMIT 1",
                [&entry.case_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        let (next, prev) = last.map_or((1, vec![0u8; 32]), |(seq, hash)| (seq + 1, hash));
        if entry.seq != next
            || entry.prev.as_slice() != prev
            || sha256(&entry.canonical()) != entry.hash
        {
            return Err(storage_reason(
                "operational audit sequence or hash mismatch",
            ));
        }
        verify_signature(&entry.public_key, &entry.hash, &entry.sig)?;
        tx.execute("INSERT INTO operational_audit (case_id,seq,at,actor,operation,prev,hash,sig,public_key) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![entry.case_id, entry.seq, entry.at, entry.actor.as_storage(), entry.operation,
                entry.prev.as_slice(), entry.hash.as_slice(), entry.sig, entry.public_key]).map_err(storage)?;
        tx.commit().map_err(storage)
    }

    fn operations(&self, id: &CaseId) -> Result<Vec<SignedOperation>, AppError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT case_id,seq,at,actor,operation,prev,hash,sig,public_key FROM operational_audit WHERE case_id=?1 ORDER BY seq").map_err(storage)?;
        stmt.query_map([id.as_str()], map_operation)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)
    }

    fn lock_global_operations(&self) -> Result<Box<dyn CaseLock>, AppError> {
        let path = self.lock_dir.join("global-operations.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(storage)?;
        private_file(&path).map_err(storage)?;
        file.lock_exclusive().map_err(storage)?;
        Ok(Box::new(HeldCaseFile { _file: file }))
    }

    fn global_operations(&self) -> Result<Vec<SignedOperation>, AppError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT ?1 AS case_id,seq,at,actor,operation,prev,hash,sig,public_key FROM global_operational_audit ORDER BY seq").map_err(storage)?;
        stmt.query_map([GLOBAL_OPERATION_SCOPE], map_operation)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)
    }

    fn append_global_operation(&self, entry: &SignedOperation) -> Result<(), AppError> {
        if entry.case_id != GLOBAL_OPERATION_SCOPE || entry.actor != Actor::Analyst {
            return Err(storage_reason("invalid global operational actor or scope"));
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(storage)?;
        let last: Option<(u64, Vec<u8>)> = tx
            .query_row(
                "SELECT seq,hash FROM global_operational_audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        let (next, prev) = last.map_or((1, vec![0u8; 32]), |(seq, hash)| (seq + 1, hash));
        if entry.seq != next
            || entry.prev.as_slice() != prev
            || sha256(&entry.canonical()) != entry.hash
        {
            return Err(storage_reason(
                "global operational audit sequence or hash mismatch",
            ));
        }
        verify_signature(&entry.public_key, &entry.hash, &entry.sig)?;
        tx.execute("INSERT INTO global_operational_audit (seq,at,actor,operation,prev,hash,sig,public_key) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![entry.seq, entry.at, entry.actor.as_storage(), entry.operation,
                entry.prev.as_slice(), entry.hash.as_slice(), entry.sig, entry.public_key]).map_err(storage)?;
        tx.commit().map_err(storage)
    }
}

impl LocalStore {
    pub(crate) fn for_each_audit_entry(
        &self,
        id: &CaseId,
        mut visitor: impl FnMut(SignedEntry) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        let conn = self.conn()?;
        let mut statement = conn.prepare("SELECT case_id,seq,at,actor,origin,kind,payload,evidence,prev,hash,sig,public_key FROM audit WHERE case_id=?1 ORDER BY seq").map_err(storage)?;
        let mut count = 0usize;
        for row in statement
            .query_map([id.as_str()], map_entry)
            .map_err(storage)?
        {
            visitor(row.map_err(storage)?)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| storage_reason("too many audit entries"))?;
        }
        Ok(count)
    }
}
