use super::{
    AppError, CaseId, Connection, LocalStore, Mutex, OpenOptions, ParquetStore, Path, PathBuf, fs,
    private_dir, private_file, storage,
};

impl LocalStore {
    pub fn open(root: &Path) -> Result<Self, AppError> {
        let (evidence_dir, seal_dir, lock_dir) = Self::prepare_directories(root)?;
        let db = Self::open_database(root)?;
        let store = Self {
            db: Mutex::new(db),
            parquet: ParquetStore::open(root)?,
            graph_catalog: Mutex::new(std::collections::HashMap::new()),
            evidence_dir,
            seal_dir,
            lock_dir,
        };
        Self::discard_old_graph_indexes(root)?;
        store.reconcile_pending_seals()?;
        Ok(store)
    }

    fn prepare_directories(root: &Path) -> Result<(PathBuf, PathBuf, PathBuf), AppError> {
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
        fs::create_dir_all(&evidence_dir).map_err(storage)?;
        fs::create_dir_all(&seal_dir).map_err(storage)?;
        fs::create_dir_all(&lock_dir).map_err(storage)?;
        for path in [root, &evidence_dir, &seal_dir, &lock_dir] {
            private_dir(path).map_err(storage)?;
        }
        Ok((evidence_dir, seal_dir, lock_dir))
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

    fn discard_old_graph_indexes(root: &Path) -> Result<(), AppError> {
        let old_dir = root.join("graph");
        if !old_dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&old_dir).map_err(storage)? {
            let entry = entry.map_err(storage)?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".duckdb") else {
                continue;
            };
            if CaseId::parse(stem).is_err() || !entry.file_type().map_err(storage)?.is_file() {
                continue;
            }
            fs::remove_file(path).map_err(storage)?;
        }
        Ok(())
    }
}
