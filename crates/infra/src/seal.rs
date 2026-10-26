use crate::*;

pub(crate) const MAX_EXPORT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
pub(crate) struct ExportBundle {
    version: u32,
    case_id: String,
    title: String,
    #[serde(default = "default_export_severity")]
    severity: String,
    scope: String,
    audit: Vec<SignedEntry>,
    seal: CaseSeal,
    evidence: std::collections::BTreeMap<String, String>,
}

fn default_export_severity() -> String {
    "medium".into()
}

impl LocalStore {
    pub(crate) fn reconcile_pending_seals(&self) -> Result<(), AppError> {
        let ids = {
            let conn = self.conn()?;
            let mut stmt = conn
                .prepare("SELECT id FROM cases WHERE seal_pending=1 ORDER BY id")
                .map_err(storage)?;
            stmt.query_map([], |row| row.get::<_, String>(0))
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?
        };
        for raw in ids {
            let Ok(id) = CaseId::parse(&raw) else {
                continue;
            };
            let Ok(_case_lock) = self.lock_case(&id) else {
                continue;
            };
            // A failed recovery leaves seal_pending set; verify reports the case as inconsistent.
            let _ = self.recover_pending_seal(&id);
        }
        Ok(())
    }

    fn recover_pending_seal(&self, id: &CaseId) -> Result<(), AppError> {
        let case = self.get_case(id)?;
        let entries = self.entries(id)?;
        verify_case_metadata(&case.title, case.severity, &case.scope, &entries)?;
        let mut previous = [0u8; 32];
        for (index, entry) in entries.iter().enumerate() {
            if entry.case_id != id.as_str()
                || entry.seq != index as u64 + 1
                || entry.prev != previous
                || sha256(&entry.canonical()) != entry.hash
            {
                return Err(AppError::InvalidChain(entry.seq));
            }
            verify_signature(&entry.public_key, &entry.hash, &entry.sig)?;
            previous = entry.hash;
        }
        let last = entries.last().ok_or(AppError::InvalidChain(0))?;
        if !case.sealed || last.kind != "CaseSealed" || last.actor != Actor::Analyst {
            return Err(AppError::InvalidChain(last.seq));
        }
        let hashes = self.evidence_hashes(id)?;
        if last.payload != hashes.join(",") {
            return Err(AppError::InvalidChain(last.seq));
        }
        for hash in &hashes {
            let bytes = self.get_evidence(id, hash)?;
            if hex(&sha256(&bytes)) != *hash {
                return Err(AppError::EvidenceMismatch(hash.clone()));
            }
        }
        for entry in &entries {
            if let Some(hash) = &entry.evidence
                && !hashes.contains(hash)
            {
                return Err(AppError::EvidenceMismatch(hash.clone()));
            }
        }
        let intent: String = self
            .conn()?
            .query_row(
                "SELECT data FROM seal_intent WHERE case_id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or(AppError::InvalidChain(last.seq))?;
        let expected: CaseSeal = serde_json::from_str(&intent).map_err(storage)?;
        self.validate_seal(id, &expected)?;
        if let Some(seal) = self.read_seal_file(id)? {
            if seal != expected {
                return Err(AppError::InvalidChain(last.seq));
            }
            irmind_fs::sync_directory(&self.seal_dir).map_err(storage)?;
            self.finish_seal(id)?;
        } else {
            self.write_seal_bytes_atomic(id, &expected)?;
        }
        let prefix = format!(".{}.", id.as_str());
        for item in fs::read_dir(&self.seal_dir).map_err(storage)? {
            let item = item.map_err(storage)?;
            let name = item.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) && name.ends_with(".tmp") {
                fs::remove_file(item.path()).map_err(storage)?;
            }
        }
        Ok(())
    }

    fn finish_seal(&self, id: &CaseId) -> Result<(), AppError> {
        self.conn()?
            .execute(
                "UPDATE cases SET seal_pending=0 WHERE id=?1 AND sealed=1 AND seal_pending=1",
                [id.as_str()],
            )
            .map_err(storage)?;
        Ok(())
    }

    pub(crate) fn validate_seal(&self, id: &CaseId, seal: &CaseSeal) -> Result<(), AppError> {
        if !self.get_case(id)?.sealed {
            return Err(AppError::Policy("case state is not sealed".into()));
        }
        let entry = self.last_entry(id)?.ok_or(AppError::InvalidChain(0))?;
        if entry.kind != "CaseSealed"
            || entry.actor != Actor::Analyst
            || seal.seq != entry.seq
            || seal.hash != entry.hash
            || seal.public_key != entry.public_key
            || seal.analyst_key_fingerprint != hex(&sha256(&entry.public_key))
            || entry.payload != self.evidence_hashes(id)?.join(",")
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        verify_signature(
            &seal.public_key,
            &seal_challenge(id, seal.seq, &seal.hash, &entry.payload),
            &seal.sig,
        )
        .map_err(|_| AppError::InvalidChain(entry.seq))
    }

    pub(crate) fn write_seal_bytes_atomic(
        &self,
        id: &CaseId,
        seal: &CaseSeal,
    ) -> Result<(), AppError> {
        let path = self.seal_dir.join(format!("{}.json", id.as_str()));
        if path.exists() {
            return Err(storage_reason("case seal already exists"));
        }
        let value = json!({"case_id": id.as_str(), "seq": seal.seq, "hash": hex(&seal.hash), "signature": hex(&seal.sig), "public_key": hex(&seal.public_key), "analyst_key_fingerprint": seal.analyst_key_fingerprint});
        let bytes = serde_json::to_vec_pretty(&value).map_err(storage)?;
        let temporary =
            self.seal_dir
                .join(format!(".{}.{}.tmp", id.as_str(), rand::random::<u64>()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options.open(&temporary).map_err(storage)?;
            private_file(&temporary).map_err(storage)?;
            file.write_all(&bytes).map_err(storage)?;
            file.sync_all().map_err(storage)?;
            drop(file);
            irmind_fs::durable_rename(&temporary, &path).map_err(storage)?;
            irmind_fs::sync_directory(&self.seal_dir).map_err(storage)?;
            self.finish_seal(id)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn export_case_cancelable(
        &self,
        id: &CaseId,
        path: &Path,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let case = self.get_case(id)?;
        if !case.sealed {
            return Err(storage_reason("seal the case before export"));
        }
        let seal = self
            .case_seal(id)?
            .ok_or_else(|| storage_reason("missing case seal"))?;
        let mut evidence = std::collections::BTreeMap::new();
        let mut encoded_bytes = 0usize;
        for hash in self.evidence_hashes(id)? {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let encoded = BASE64.encode(self.get_evidence(id, &hash)?);
            encoded_bytes = encoded_bytes
                .checked_add(encoded.len())
                .ok_or_else(|| storage_reason("export size overflow"))?;
            if encoded_bytes > MAX_EXPORT_BYTES {
                return Err(storage_reason("export exceeds 128 MiB"));
            }
            evidence.insert(hash, encoded);
        }
        let bundle = ExportBundle {
            version: 3,
            case_id: id.as_str().into(),
            title: case.title,
            severity: case.severity.as_str().into(),
            scope: case.scope,
            audit: self.entries(id)?,
            seal,
            evidence,
        };
        let bytes = serde_json::to_vec(&bundle).map_err(storage)?;
        if bytes.len() > MAX_EXPORT_BYTES {
            return Err(storage_reason("export exceeds 128 MiB"));
        }
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut created = false;
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options.open(path).map_err(storage)?;
            created = true;
            private_file(path).map_err(storage)?;
            for chunk in bytes.chunks(1024 * 1024) {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                file.write_all(chunk).map_err(storage)?;
            }
            file.sync_all().map_err(storage)?;
            Ok(bundle.seal.analyst_key_fingerprint)
        })();
        if result.is_err() && created {
            let _ = fs::remove_file(path);
        }
        result
    }
}

impl CaseExporter for LocalStore {
    fn export_case(
        &self,
        id: &CaseId,
        path: &Path,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.export_case_cancelable(id, path, cancel)
    }
}
pub fn verify_export(path: &Path) -> Result<(String, usize), AppError> {
    verify_export_expected(path, None)
}

pub struct LocalExportVerifier;

impl ExportVerifier for LocalExportVerifier {
    fn verify_export(
        &self,
        path: &Path,
        expected_key: Option<&str>,
    ) -> Result<(String, usize), AppError> {
        verify_export_expected(path, expected_key)
    }
}

pub fn verify_export_expected(
    path: &Path,
    expected_key: Option<&str>,
) -> Result<(String, usize), AppError> {
    let file = fs::File::open(path).map_err(storage)?;
    if file.metadata().map_err(storage)?.len() > MAX_EXPORT_BYTES as u64 {
        return Err(storage_reason("export exceeds 128 MiB"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_EXPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    if bytes.len() > MAX_EXPORT_BYTES {
        return Err(storage_reason("export exceeds 128 MiB"));
    }
    let bundle: ExportBundle = serde_json::from_slice(&bytes).map_err(storage)?;
    if bundle.version != 3 {
        return Err(storage_reason("unsupported export version"));
    }
    let id =
        CaseId::parse(&bundle.case_id).map_err(|_| storage_reason("invalid case id in export"))?;
    let mut prev = [0u8; 32];
    let mut verifier = LocalVerifier {
        trusted: std::collections::BTreeMap::new(),
    };
    for (index, entry) in bundle.audit.iter().enumerate() {
        if entry.case_id != id.as_str()
            || entry.seq != index as u64 + 1
            || entry.prev != prev
            || sha256(&entry.canonical()) != entry.hash
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        verifier
            .verify(&entry.public_key, &entry.hash, &entry.sig)
            .map_err(|_| AppError::InvalidChain(entry.seq))?;
        verifier = verifier
            .with_trusted_key(&entry.actor, &entry.public_key)
            .map_err(|_| AppError::InvalidChain(entry.seq))?;
        prev = entry.hash;
    }
    let severity = Severity::parse(&bundle.severity).map_err(|_| AppError::InvalidChain(1))?;
    verify_case_metadata(&bundle.title, severity, &bundle.scope, &bundle.audit)?;
    let last = bundle.audit.last().ok_or(AppError::InvalidChain(0))?;
    if last.kind != "CaseSealed"
        || last.actor != Actor::Analyst
        || last.seq != bundle.seal.seq
        || last.hash != bundle.seal.hash
        || last.public_key != bundle.seal.public_key
    {
        return Err(AppError::InvalidChain(last.seq));
    }
    let manifest = bundle
        .evidence
        .keys()
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    if last.payload != manifest {
        return Err(AppError::InvalidChain(last.seq));
    }
    verifier
        .verify(
            &bundle.seal.public_key,
            &seal_challenge(&id, bundle.seal.seq, &bundle.seal.hash, &manifest),
            &bundle.seal.sig,
        )
        .map_err(|_| AppError::InvalidChain(last.seq))?;
    for (hash, encoded) in &bundle.evidence {
        if encoded.len() > 66_666_672 {
            return Err(storage_reason("encoded evidence exceeds 50 MB"));
        }
        let content = BASE64.decode(encoded).map_err(storage)?;
        if content.len() > 50_000_000 {
            return Err(storage_reason("evidence exceeds 50 MB"));
        }
        if hex(&sha256(&content)) != *hash {
            return Err(AppError::EvidenceMismatch(hash.clone()));
        }
    }
    for entry in &bundle.audit {
        if let Some(hash) = &entry.evidence
            && !bundle.evidence.contains_key(hash)
        {
            return Err(AppError::EvidenceMismatch(hash.clone()));
        }
    }
    let fingerprint = hex(&sha256(&bundle.seal.public_key));
    if bundle.seal.analyst_key_fingerprint != fingerprint {
        return Err(AppError::Signature(
            "analyst key fingerprint mismatch".into(),
        ));
    }
    if expected_key.is_some_and(|key| !key.eq_ignore_ascii_case(&fingerprint)) {
        return Err(AppError::Signature(
            "export key does not match expected fingerprint".into(),
        ));
    }
    Ok((fingerprint, bundle.audit.len()))
}

impl LocalStore {
    pub(crate) fn read_seal_file(&self, id: &CaseId) -> Result<Option<CaseSeal>, AppError> {
        let path = self.seal_dir.join(format!("{}.json", id.as_str()));
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(storage(e)),
        };
        let value: Value = serde_json::from_slice(&bytes).map_err(storage)?;
        if value.get("case_id").and_then(Value::as_str) != Some(id.as_str()) {
            return Err(storage_reason("seal case id mismatch"));
        }
        let field = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| storage_reason("missing seal field"))
        };
        let hash = hex::decode(field("hash")?)
            .map_err(storage)?
            .try_into()
            .map_err(|_| storage_reason("invalid seal hash"))?;
        Ok(Some(CaseSeal {
            seq: value
                .get("seq")
                .and_then(Value::as_u64)
                .ok_or_else(|| storage_reason("missing seal sequence"))?,
            hash,
            sig: hex::decode(field("signature")?).map_err(storage)?,
            public_key: hex::decode(field("public_key")?).map_err(storage)?,
            analyst_key_fingerprint: value
                .get("analyst_key_fingerprint")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        }))
    }
}
