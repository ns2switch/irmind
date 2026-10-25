use crate::*;

impl LocalStore {
    pub fn open(root: &Path) -> Result<Self, AppError> {
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
            private_fs::private_dir(path).map_err(storage)?;
        }
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
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append only'); END;
            CREATE TRIGGER IF NOT EXISTS seal_intent_no_update BEFORE UPDATE ON seal_intent BEGIN SELECT RAISE(ABORT,'seal intent is append only'); END;
            CREATE TRIGGER IF NOT EXISTS seal_intent_no_delete BEFORE DELETE ON seal_intent BEGIN SELECT RAISE(ABORT,'seal intent is append only'); END;
        ").map_err(storage)?;
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
            let records = {
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
                records
            };
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

    pub(crate) fn check_entity_query(
        &self,
        id: &CaseId,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<(), AppError> {
        self.get_case(id)?;
        if !valid_entity(kind, value) || !(1..=20).contains(&limit) {
            return Err(AppError::Policy("invalid graph query arguments".into()));
        }
        Ok(())
    }
}
fn decode_fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], rusqlite::Error> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

pub(crate) fn map_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<SignedEntry> {
    let actor: String = row.get(3)?;
    Ok(SignedEntry {
        case_id: row.get(0)?,
        seq: row.get(1)?,
        at: row.get(2)?,
        actor: Actor::parse_storage(&actor).map_err(|_| rusqlite::Error::InvalidQuery)?,
        origin: row.get(4)?,
        kind: row.get(5)?,
        payload: row.get(6)?,
        evidence: row.get(7)?,
        prev: decode_fixed(row.get(8)?)?,
        hash: decode_fixed(row.get(9)?)?,
        sig: row.get(10)?,
        public_key: row.get(11)?,
    })
}

fn append_entry_tx(tx: &Transaction<'_>, entry: &SignedEntry) -> Result<(), AppError> {
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
    if last
        .as_ref()
        .is_some_and(|(_, _, kind)| kind == "CaseSealed")
    {
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
            entry.kind,
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

impl Repository for LocalStore {
    fn lock_case(&self, id: &CaseId) -> Result<Box<dyn CaseLock>, AppError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(self.lock_dir.join(id.as_str()))
            .map_err(storage)?;
        private_file(&self.lock_dir.join(id.as_str())).map_err(storage)?;
        file.lock_exclusive().map_err(storage)?;
        Ok(Box::new(HeldCaseFile { _file: file }))
    }

    fn get_case(&self, id: &CaseId) -> Result<Case, AppError> {
        self.conn()?
            .query_row(
                "SELECT title,scope,severity,sealed FROM cases WHERE id=?1",
                [id.as_str()],
                |row| {
                    Ok(Case {
                        id: id.clone(),
                        title: row.get(0)?,
                        scope: row.get(1)?,
                        severity: Severity::parse(&row.get::<_, String>(2)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        sealed: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .map_err(storage)
    }

    fn list_cases(&self) -> Result<Vec<Case>, AppError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT id,title,scope,severity,sealed FROM cases ORDER BY rowid DESC")
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                let id: String = row.get(0)?;
                Ok((
                    id,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(storage)?;
        let mut result = Vec::new();
        for row in rows {
            let (id, title, scope, severity, sealed) = row.map_err(storage)?;
            result.push(Case {
                id: CaseId::parse(&id)
                    .map_err(|_| storage_reason("invalid case id in database"))?,
                title,
                scope,
                severity: Severity::parse(&severity)
                    .map_err(|_| storage_reason("invalid case severity in database"))?,
                sealed: sealed != 0,
            });
        }
        Ok(result)
    }

    fn write_seal_file(&self, id: &CaseId, seal: &CaseSeal) -> Result<(), AppError> {
        self.validate_seal(id, seal)?;
        let data = serde_json::to_string(seal).map_err(storage)?;
        let inserted = self
            .conn()?
            .execute(
                "INSERT OR IGNORE INTO seal_intent(case_id,data) VALUES (?1,?2)",
                params![id.as_str(), data],
            )
            .map_err(storage)?;
        if inserted != 1 {
            return Err(storage_reason("seal intent already exists"));
        }
        self.write_seal_bytes_atomic(id, seal)
    }

    fn case_seal(&self, id: &CaseId) -> Result<Option<CaseSeal>, AppError> {
        let pending: i64 = self
            .conn()?
            .query_row(
                "SELECT seal_pending FROM cases WHERE id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if pending != 0 {
            return Err(AppError::InvalidChain(0));
        }
        self.read_seal_file(id)
    }
}
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
                || entry.kind != "CaseCreated"
                || entry.actor != Actor::Analyst
            {
                return Err(AppError::Policy("invalid case creation transaction".into()));
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
                    || entry.kind != "CaseScopeChanged"
                    || entry.actor != Actor::Analyst
                {
                    return Err(AppError::Policy("invalid case scope transaction".into()));
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
                    || entry.kind != "CaseSealed"
                    || entry.actor != Actor::Analyst
                {
                    return Err(AppError::Policy("invalid case seal transaction".into()));
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

    fn entries(&self, id: &CaseId) -> Result<Vec<SignedEntry>, AppError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT case_id,seq,at,actor,origin,kind,payload,evidence,prev,hash,sig,public_key FROM audit WHERE case_id=?1 ORDER BY seq").map_err(storage)?;
        stmt.query_map([id.as_str()], map_entry)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)
    }
}
