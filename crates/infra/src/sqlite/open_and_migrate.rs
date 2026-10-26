use super::*;

impl LocalStore {
    pub fn open(root: &Path) -> Result<Self, AppError> {
        let (evidence_dir, seal_dir, lock_dir, graph_dir) = Self::prepare_directories(root)?;
        let db = Self::open_database(root)?;
        let store = Self {
            db: Mutex::new(db),
            graph: GraphStore::new(&graph_dir)?,
            evidence_dir,
            seal_dir,
            lock_dir,
        };
        store.migrate_legacy_graphs()?;
        store.reconcile_pending_seals()?;
        Ok(store)
    }

    fn prepare_directories(root: &Path) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf), AppError> {
        fs::create_dir_all(root).map_err(storage)?;
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt as _;
            let absolute = fs::canonicalize(root).map_err(storage)?;
            if absolute.as_os_str().encode_wide().count() > 160 {
                return Err(storage(
                    "data directory is too deep for portable Windows paths; use --home with a shorter path",
                ));
            }
        }
        let evidence_dir = root.join("evidence");
        let seal_dir = root.join("seals");
        let lock_dir = root.join("locks");
        let graph_dir = root.join("graph");
        fs::create_dir_all(&evidence_dir).map_err(storage)?;
        fs::create_dir_all(&seal_dir).map_err(storage)?;
        fs::create_dir_all(&lock_dir).map_err(storage)?;
        for path in [root, &evidence_dir, &seal_dir, &lock_dir] {
            private_dir(path).map_err(storage)?;
        }
        Ok((evidence_dir, seal_dir, lock_dir, graph_dir))
    }

    fn open_database(root: &Path) -> Result<Connection, AppError> {
        let db_path = root.join("irmind.db");
        let mut db_file = OpenOptions::new();
        db_file.write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            db_file.mode(0o600);
        }
        let _ = db_file.open(&db_path).map_err(storage)?;
        private_file(&db_path).map_err(storage)?;
        let db = Connection::open(db_path).map_err(storage)?;
        db.busy_timeout(std::time::Duration::from_secs(30))
            .map_err(storage)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, title TEXT NOT NULL, scope TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium', sealed INTEGER NOT NULL DEFAULT 0, seal_pending INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS audit (case_id TEXT NOT NULL, seq INTEGER NOT NULL, at INTEGER NOT NULL, actor TEXT NOT NULL, origin TEXT NOT NULL,
                kind TEXT NOT NULL, payload TEXT NOT NULL, evidence TEXT, prev BLOB NOT NULL, hash BLOB NOT NULL,
                sig BLOB NOT NULL, public_key BLOB NOT NULL, PRIMARY KEY(case_id,seq), FOREIGN KEY(case_id) REFERENCES cases(id));
            CREATE TABLE IF NOT EXISTS evidence (case_id TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(case_id,hash),
                FOREIGN KEY(case_id) REFERENCES cases(id));
            CREATE TABLE IF NOT EXISTS seal_intent (case_id TEXT PRIMARY KEY, data TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id));
            CREATE TABLE IF NOT EXISTS operational_audit (case_id TEXT NOT NULL, seq INTEGER NOT NULL, at INTEGER NOT NULL,
                actor TEXT NOT NULL, operation TEXT NOT NULL, prev BLOB NOT NULL, hash BLOB NOT NULL,
                sig BLOB NOT NULL, public_key BLOB NOT NULL, PRIMARY KEY(case_id,seq), FOREIGN KEY(case_id) REFERENCES cases(id));
            CREATE TABLE IF NOT EXISTS global_operational_audit (seq INTEGER PRIMARY KEY, at INTEGER NOT NULL,
                actor TEXT NOT NULL, operation TEXT NOT NULL, prev BLOB NOT NULL, hash BLOB NOT NULL,
                sig BLOB NOT NULL, public_key BLOB NOT NULL);
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append only'); END;
            CREATE TRIGGER IF NOT EXISTS seal_intent_no_update BEFORE UPDATE ON seal_intent BEGIN SELECT RAISE(ABORT,'seal intent is append only'); END;
            CREATE TRIGGER IF NOT EXISTS seal_intent_no_delete BEFORE DELETE ON seal_intent BEGIN SELECT RAISE(ABORT,'seal intent is append only'); END;
            CREATE TRIGGER IF NOT EXISTS operational_audit_no_update BEFORE UPDATE ON operational_audit BEGIN SELECT RAISE(ABORT,'operational audit is append only'); END;
            CREATE TRIGGER IF NOT EXISTS operational_audit_no_delete BEFORE DELETE ON operational_audit BEGIN SELECT RAISE(ABORT,'operational audit is append only'); END;
            CREATE TRIGGER IF NOT EXISTS global_operational_audit_no_update BEFORE UPDATE ON global_operational_audit BEGIN SELECT RAISE(ABORT,'global operational audit is append only'); END;
            CREATE TRIGGER IF NOT EXISTS global_operational_audit_no_delete BEFORE DELETE ON global_operational_audit BEGIN SELECT RAISE(ABORT,'global operational audit is append only'); END;
        ").map_err(storage)?;
        Self::migrate_case_columns(&db)?;
        Ok(db)
    }

    fn migrate_case_columns(db: &Connection) -> Result<(), AppError> {
        let has_severity = {
            let mut statement = db.prepare("PRAGMA table_info(cases)").map_err(storage)?;
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?
                .contains(&"severity".to_owned())
        };
        if !has_severity {
            db.execute_batch(
                "ALTER TABLE cases ADD COLUMN severity TEXT NOT NULL DEFAULT 'medium'",
            )
            .map_err(storage)?;
        }
        let has_seal_pending = {
            let mut statement = db.prepare("PRAGMA table_info(cases)").map_err(storage)?;
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?
                .contains(&"seal_pending".to_owned())
        };
        if !has_seal_pending {
            db.execute_batch(
                "ALTER TABLE cases ADD COLUMN seal_pending INTEGER NOT NULL DEFAULT 0",
            )
            .map_err(storage)?;
        }
        Ok(())
    }

    pub(crate) fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, AppError> {
        self.db.lock().map_err(storage)
    }

    pub(crate) fn migrate_legacy_graphs(&self) -> Result<(), AppError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let migration_lock = options
            .open(self.lock_dir.join("graph-migration.lock"))
            .map_err(storage)?;
        private_file(&self.lock_dir.join("graph-migration.lock")).map_err(storage)?;
        migration_lock.lock_exclusive().map_err(storage)?;
        let ids = {
            let conn = self.conn()?;
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='graph_index'",
                    [],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if exists == 0 {
                return Ok(());
            }
            let mut statement = conn
                .prepare("SELECT DISTINCT case_id FROM graph_index ORDER BY case_id")
                .map_err(storage)?;
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?
        };
        for raw_id in ids {
            let id = CaseId::parse(&raw_id)
                .map_err(|_| storage_reason("invalid legacy graph case id"))?;
            let _case_lock = self.lock_case(&id)?;
            self.migrate_legacy_case(&id)?;
        }
        self.conn()?
            .execute_batch(
                "DROP TABLE IF EXISTS graph_observations;
                 DROP TABLE IF EXISTS graph_nodes;
                 DROP TABLE IF EXISTS graph_events;
                 DROP TABLE IF EXISTS graph_index;",
            )
            .map_err(storage)
    }

    fn migrate_legacy_case(&self, id: &CaseId) -> Result<(), AppError> {
        let legacy = {
            let conn = self.conn()?;
            let mut statement = conn
                .prepare("SELECT hash,records FROM graph_index WHERE case_id=?1 ORDER BY hash")
                .map_err(storage)?;
            statement
                .query_map([id.as_str()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?
        };
        for (hash, expected) in legacy {
            self.get_evidence(id, &hash)?;
            let records = self.read_legacy_records(id, &hash)?;
            if i64::try_from(records.len()).map_err(storage)? != expected {
                return Err(storage_reason("legacy graph record count mismatch"));
            }
            let hash_bytes: [u8; 32] = hex::decode(&hash)
                .map_err(storage)?
                .try_into()
                .map_err(|_| storage_reason("invalid legacy evidence hash"))?;
            let tainted = records
                .into_iter()
                .map(|record| {
                    let index = record.index as u64;
                    Tainted::from_external(
                        record,
                        Provenance::new(hash_bytes, Some(index), SourceKind::Graph),
                    )
                })
                .collect::<Vec<_>>();
            self.graph
                .index_records(id, &hash, &tainted, &irmind_app::CancellationToken::new())?;
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction().map_err(storage)?;
        for table in [
            "graph_observations",
            "graph_nodes",
            "graph_events",
            "graph_index",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE case_id=?1"),
                [id.as_str()],
            )
            .map_err(storage)?;
        }
        tx.commit().map_err(storage)
    }

    fn read_legacy_records(&self, id: &CaseId, hash: &str) -> Result<Vec<GraphRecord>, AppError> {
        let conn = self.conn()?;
        let mut statement = conn
                    .prepare(
                        "SELECT e.record_index,e.at,e.event,o.kind,o.value
                         FROM graph_events e LEFT JOIN graph_observations o
                           ON o.case_id=e.case_id AND o.hash=e.hash AND o.record_index=e.record_index
                         WHERE e.case_id=?1 AND e.hash=?2
                         ORDER BY e.record_index,o.kind,o.value",
                    )
                    .map_err(storage)?;
        let rows = statement
            .query_map(params![id.as_str(), hash], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(storage)?;
        let mut records: Vec<GraphRecord> = Vec::new();
        for row in rows {
            let (index, at, event, kind, value) = row.map_err(storage)?;
            let index = usize::try_from(index)
                .map_err(|_| storage_reason("invalid legacy graph record index"))?;
            if records.last().is_none_or(|last| last.index != index) {
                records.push(GraphRecord {
                    index,
                    at,
                    event,
                    text: String::new(),
                    entities: Vec::new(),
                    relations: Vec::new(),
                });
            }
            if let (Some(kind), Some(value)) = (kind, value)
                && let Some(last) = records.last_mut()
            {
                last.entities.push((kind, value));
            }
        }
        Ok(records)
    }

    pub(crate) fn check_entity_query(
        &self,
        id: &CaseId,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<(), AppError> {
        self.get_case(id)?;
        if !valid_entity(kind, value) || !(1..=20).contains(&limit) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::InvalidGraphQueryArguments,
            )));
        }
        Ok(())
    }
}
