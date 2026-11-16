use super::{AppError, Connection, storage};
pub(in crate::sqlite) fn install(db: &Connection) -> Result<(), AppError> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS case_deletion (case_id TEXT PRIMARY KEY, operation_seq INTEGER NOT NULL UNIQUE, operation TEXT NOT NULL, complete INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(operation_seq) REFERENCES global_operational_audit(seq));").map_err(storage)?;
    for (trigger, table, column) in [
        ("audit_no_delete", "audit", "case_id"),
        (
            "operational_audit_no_delete",
            "operational_audit",
            "case_id",
        ),
    ] {
        db.execute_batch(&format!("DROP TRIGGER IF EXISTS {trigger}; CREATE TRIGGER {trigger} BEFORE DELETE ON {table}
            WHEN NOT EXISTS(SELECT 1 FROM case_deletion d JOIN global_operational_audit g ON g.seq=d.operation_seq JOIN cases c ON c.id=d.case_id
                WHERE d.case_id=OLD.{column} AND g.operation=d.operation AND g.actor='analyst' AND c.sealed=0 AND c.seal_pending=0)
            BEGIN SELECT RAISE(ABORT,'case journal is append only without a signed deletion intent'); END;")).map_err(storage)?;
    }
    db.execute_batch("CREATE TRIGGER IF NOT EXISTS deletion_no_delete BEFORE DELETE ON case_deletion BEGIN SELECT RAISE(ABORT,'deletion intents cannot be removed'); END;
        CREATE TRIGGER IF NOT EXISTS deletion_identity_no_update BEFORE UPDATE OF case_id,operation_seq,operation ON case_deletion BEGIN SELECT RAISE(ABORT,'deletion identity cannot change'); END;
        CREATE TRIGGER IF NOT EXISTS audit_deletion_no_insert BEFORE INSERT ON audit WHEN EXISTS(SELECT 1 FROM case_deletion WHERE case_id=NEW.case_id) BEGIN SELECT RAISE(ABORT,'case has signed deletion intent'); END;
        CREATE TRIGGER IF NOT EXISTS operation_deletion_no_insert BEFORE INSERT ON operational_audit WHEN EXISTS(SELECT 1 FROM case_deletion WHERE case_id=NEW.case_id) BEGIN SELECT RAISE(ABORT,'case has signed deletion intent'); END;
        CREATE TRIGGER IF NOT EXISTS evidence_deletion_no_insert BEFORE INSERT ON evidence WHEN EXISTS(SELECT 1 FROM case_deletion WHERE case_id=NEW.case_id) BEGIN SELECT RAISE(ABORT,'case has signed deletion intent'); END;
        CREATE TRIGGER IF NOT EXISTS case_deletion_no_recreate BEFORE INSERT ON cases WHEN EXISTS(SELECT 1 FROM case_deletion WHERE case_id=NEW.id) BEGIN SELECT RAISE(ABORT,'deleted case cannot be recreated'); END;").map_err(storage)?;
    Ok(())
}
