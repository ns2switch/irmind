//! Installation-wide dispatch admission stored in the same WAL as the case audit.
use super::{
    AppError, Connection, LocalStore, OptionalExtension as _, SignedEntry, Transaction, params,
    storage, storage_reason, verify_signature,
};
use irmind_app::source_queries::{
    ResolvedQuerySourceV1, SourceQueryDispatch, SourceQueryError, SourceQueryLimits,
    SourceQueryRecoveryV1, SourceQuerySettlementV1,
};
use irmind_domain::{Actor, AuditEventKind, Tool};

pub(super) fn install(db: &Connection) -> Result<(), AppError> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS source_query_dispatch (
            reservation TEXT PRIMARY KEY NOT NULL,
            case_id TEXT NOT NULL,
            intent_seq INTEGER NOT NULL,
            intent_hash BLOB NOT NULL CHECK(length(intent_hash)=32),
            module TEXT NOT NULL,
            owner TEXT NOT NULL,
            location TEXT NOT NULL,
            started_at INTEGER NOT NULL,
            release_hash BLOB CHECK(release_hash IS NULL OR length(release_hash)=32),
            UNIQUE(case_id,intent_seq)
        );
        CREATE INDEX IF NOT EXISTS source_query_dispatch_frequency
            ON source_query_dispatch(module,owner,location,started_at);
        CREATE INDEX IF NOT EXISTS source_query_dispatch_active
            ON source_query_dispatch(module,owner,location) WHERE release_hash IS NULL;
        CREATE INDEX IF NOT EXISTS source_query_dispatch_audit
            ON audit(case_id,hash) WHERE kind IN ('SourceQuerySettlementV1','SourceQueryRecoveryV1');
        CREATE INDEX IF NOT EXISTS source_query_dispatch_allowed
            ON audit(kind,payload) WHERE kind='Allowed' AND payload='source_query';",
    )
    .map_err(storage)
}

/// Both halves commit together. Disagreement can only come from a database
/// outside this protocol. Preserve its receipts and make dispatch unavailable.
pub(super) fn consistent(db: &Connection) -> Result<bool, AppError> {
    db.query_row(
        "SELECT NOT EXISTS(
            SELECT 1 FROM source_query_dispatch d
            LEFT JOIN audit i ON i.case_id=d.case_id AND i.seq=d.intent_seq
                               AND i.hash=d.intent_hash AND i.kind=?1
            LEFT JOIN audit a ON a.case_id=d.case_id AND a.seq=d.intent_seq+1
                               AND a.prev=d.intent_hash AND a.kind=?2 AND a.payload=?3
            WHERE NOT EXISTS (SELECT 1 FROM case_deletion t WHERE t.case_id=d.case_id AND t.complete=1)
              AND (i.seq IS NULL OR a.seq IS NULL OR
                   (d.release_hash IS NOT NULL AND NOT EXISTS(
                      SELECT 1 FROM audit r WHERE r.case_id=d.case_id AND r.hash=d.release_hash
                                       AND r.kind IN (?4,?5))))
        ) AND NOT EXISTS(
            SELECT 1 FROM audit a
            WHERE a.kind=?2 AND a.payload=?3 AND NOT EXISTS (
                SELECT 1 FROM source_query_dispatch d
                WHERE d.case_id=a.case_id AND d.intent_seq=a.seq-1 AND d.intent_hash=a.prev)
        )",
        params![
            AuditEventKind::SourceQueryExecutionV1.as_str(),
            AuditEventKind::Allowed.as_str(),
            Tool::SourceQuery.as_str(),
            AuditEventKind::SourceQuerySettlementV1.as_str(),
            AuditEventKind::SourceQueryRecoveryV1.as_str(),
        ],
        |row| row.get(0),
    )
    .map_err(storage)
}

impl LocalStore {
    pub(super) fn append_coordinated_query(
        &self,
        dispatch: &SourceQueryDispatch<'_>,
    ) -> Result<(), AppError> {
        if !self.query_dispatch_ready {
            return Err(storage_reason(
                "source-query quota and audit inventory disagree",
            ));
        }
        let [reservation, intent, allowed] = dispatch.entries else {
            return Err(SourceQueryError::Invalid.into());
        };
        if reservation.kind != AuditEventKind::SourceQueryReservationV1
            || intent.kind != AuditEventKind::SourceQueryExecutionV1
            || allowed.kind != AuditEventKind::Allowed
            || allowed.payload != Tool::SourceQuery.as_str()
            || reservation.case_id != intent.case_id
            || intent.case_id != allowed.case_id
        {
            return Err(SourceQueryError::Invalid.into());
        }
        if self
            .seal_dir
            .join(format!("{}.json", intent.case_id))
            .exists()
        {
            return Err(AppError::Sealed);
        }
        let mut db = self.conn()?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(storage)?;
        claim(
            &tx,
            dispatch.source,
            dispatch.limits,
            dispatch.reservation,
            intent,
        )?;
        for entry in dispatch.entries {
            super::codec::append_entry_tx(&tx, entry)?;
        }
        tx.commit().map_err(storage)
    }
}

fn claim(
    tx: &Transaction<'_>,
    source: &ResolvedQuerySourceV1,
    limits: &SourceQueryLimits,
    reservation: &str,
    intent: &SignedEntry,
) -> Result<(), AppError> {
    let key = params![
        source.module(),
        source.owner(),
        source.location(),
        intent.at.saturating_sub(59)
    ];
    let (recent, last): (u64, Option<u64>) = tx
        .query_row(
            "SELECT COUNT(*),MAX(started_at) FROM source_query_dispatch
             WHERE module=?1 AND owner=?2 AND location=?3 AND started_at>=?4",
            key,
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(storage)?;
    let active: u64 = tx
        .query_row(
            "SELECT COUNT(*) FROM source_query_dispatch
             WHERE module=?1 AND owner=?2 AND location=?3 AND release_hash IS NULL",
            params![source.module(), source.owner(), source.location()],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if recent >= limits.queries_per_minute
        || active >= limits.concurrency
        || last.is_some_and(|last| last > intent.at)
    {
        return Err(SourceQueryError::DispatchQuota.into());
    }
    tx.execute(
        "INSERT INTO source_query_dispatch
         (reservation,case_id,intent_seq,intent_hash,module,owner,location,started_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            reservation,
            intent.case_id,
            intent.seq,
            intent.hash.as_slice(),
            source.module(),
            source.owner(),
            source.location(),
            intent.at,
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Called by every audit append after inserting the signed receipt. The
/// application has already replayed and authenticated its terminal transition.
pub(super) fn record_slot_release(
    tx: &Transaction<'_>,
    entry: &SignedEntry,
) -> Result<(), AppError> {
    let (reservation, analytics_only) = match entry.kind {
        AuditEventKind::SourceQuerySettlementV1 => (
            SourceQuerySettlementV1::decode(entry.payload.as_bytes())?
                .reservation()
                .to_owned(),
            false,
        ),
        AuditEventKind::SourceQueryRecoveryV1 => (
            SourceQueryRecoveryV1::decode(entry.payload.as_bytes())?
                .reservation()
                .to_owned(),
            true,
        ),
        _ => return Ok(()),
    };
    let stored: Option<(String, Vec<u8>, String)> = tx
        .query_row(
            "SELECT d.module,a.public_key,a.actor FROM source_query_dispatch d
             JOIN audit a ON a.case_id=d.case_id AND a.seq=CASE WHEN ?3 THEN 1 ELSE d.intent_seq-1 END
             WHERE d.reservation=?1 AND d.case_id=?2 AND d.release_hash IS NULL",
            params![reservation, entry.case_id, analytics_only],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(storage)?;
    let Some((module, key, actor)) = stored else {
        return Ok(());
    };
    if (analytics_only && (module != "query-azure-log-analytics" || entry.actor != Actor::Analyst))
        || (!analytics_only && !matches!(entry.actor, Actor::Agent(_)))
        || entry.actor.as_storage() != actor
        || entry.public_key != key
    {
        return Err(AppError::InvalidChain(entry.seq));
    }
    verify_signature(&entry.public_key, &entry.hash, &entry.sig)?;
    tx.execute(
        "UPDATE source_query_dispatch SET release_hash=?1
         WHERE reservation=?2 AND case_id=?3 AND release_hash IS NULL",
        params![entry.hash.as_slice(), reservation, entry.case_id],
    )
    .map_err(storage)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
