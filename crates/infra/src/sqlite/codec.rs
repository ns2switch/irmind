use super::{
    Actor, AppError, OptionalExtension, SignedEntry, SignedOperation, Transaction, params, sha256,
    storage, storage_reason,
};

fn decode_fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], rusqlite::Error> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

pub(super) fn map_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<SignedEntry> {
    let actor: String = row.get(3)?;
    Ok(SignedEntry {
        case_id: row.get(0)?,
        seq: row.get(1)?,
        at: row.get(2)?,
        actor: Actor::parse_storage(&actor).map_err(|_| rusqlite::Error::InvalidQuery)?,
        origin: row.get(4)?,
        kind: irmind_domain::AuditEventKind::parse(&row.get::<_, String>(5)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        payload: row.get(6)?,
        evidence: row.get(7)?,
        prev: decode_fixed(row.get(8)?)?,
        hash: decode_fixed(row.get(9)?)?,
        sig: row.get(10)?,
        public_key: row.get(11)?,
    })
}

pub(super) fn map_operation(row: &rusqlite::Row<'_>) -> rusqlite::Result<SignedOperation> {
    let actor: String = row.get(3)?;
    Ok(SignedOperation {
        case_id: row.get(0)?,
        seq: row.get(1)?,
        at: row.get(2)?,
        actor: Actor::parse_storage(&actor).map_err(|_| rusqlite::Error::InvalidQuery)?,
        operation: row.get(4)?,
        prev: decode_fixed(row.get(5)?)?,
        hash: decode_fixed(row.get(6)?)?,
        sig: row.get(7)?,
        public_key: row.get(8)?,
    })
}

pub(super) fn append_entry_tx(tx: &Transaction<'_>, entry: &SignedEntry) -> Result<(), AppError> {
    let sealed: i64 = tx
        .query_row(
            "SELECT sealed FROM cases WHERE id=?1",
            [&entry.case_id],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if sealed != 0 {
        return Err(AppError::Sealed);
    }
    let last: Option<(u64, Vec<u8>, String)> = tx
        .query_row(
            "SELECT seq,hash,kind FROM audit WHERE case_id=?1 ORDER BY seq DESC LIMIT 1",
            [&entry.case_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(storage)?;
    if last.as_ref().is_some_and(|(_, _, kind)| {
        irmind_domain::AuditEventKind::parse(kind)
            .is_ok_and(|kind| kind == irmind_domain::AuditEventKind::CaseSealed)
    }) {
        return Err(AppError::Sealed);
    }
    let (next, prev) = last.map_or((1, vec![0u8; 32]), |(seq, hash, _)| (seq + 1, hash));
    if entry.seq != next
        || entry.prev.as_slice() != prev
        || sha256(&entry.canonical()) != entry.hash
    {
        return Err(storage_reason("audit append sequence or hash mismatch"));
    }
    tx.execute(
        "INSERT INTO audit (case_id,seq,at,actor,origin,kind,payload,evidence,prev,hash,sig,public_key) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            entry.case_id,
            entry.seq,
            entry.at,
            entry.actor.as_storage(),
            entry.origin,
            entry.kind.as_str(),
            entry.payload,
            entry.evidence,
            entry.prev.as_slice(),
            entry.hash.as_slice(),
            entry.sig,
            entry.public_key
        ],
    )
    .map_err(storage)?;
    Ok(())
}
