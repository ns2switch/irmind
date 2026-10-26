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
