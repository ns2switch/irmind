use super::*;

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
    let bundle = read_export_bundle(path)?;
    let id =
        CaseId::parse(&bundle.case_id).map_err(|_| storage_reason("invalid case id in export"))?;
    let verifier = verify_export_chain(&bundle, &id)?;
    verify_export_seal(&bundle, &id, &verifier)?;
    verify_export_evidence(&bundle)?;
    let fingerprint = hex(&sha256(&bundle.seal.public_key));
    if bundle.seal.analyst_key_fingerprint != fingerprint {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::AdapterSignature(
                irmind_app::AdapterSignatureError::AnalystKeyFingerprintMismatch,
            ),
        ));
    }
    if expected_key.is_some_and(|key| !key.eq_ignore_ascii_case(&fingerprint)) {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::AdapterSignature(
                irmind_app::AdapterSignatureError::ExportKeyDoesNotMatchExpectedFingerprint,
            ),
        ));
    }
    Ok((fingerprint, bundle.audit.len()))
}

fn read_export_bundle(path: &Path) -> Result<ExportBundle, AppError> {
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
    Ok(bundle)
}

fn verify_export_chain(bundle: &ExportBundle, id: &CaseId) -> Result<LocalVerifier, AppError> {
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
    Ok(verifier)
}

fn verify_export_seal(
    bundle: &ExportBundle,
    id: &CaseId,
    verifier: &LocalVerifier,
) -> Result<(), AppError> {
    let severity = Severity::parse(&bundle.severity).map_err(|_| AppError::InvalidChain(1))?;
    verify_case_metadata(&bundle.title, severity, &bundle.scope, &bundle.audit)?;
    let last = bundle.audit.last().ok_or(AppError::InvalidChain(0))?;
    if last.kind != irmind_domain::AuditEventKind::CaseSealed
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
            &seal_challenge(id, bundle.seal.seq, &bundle.seal.hash, &manifest),
            &bundle.seal.sig,
        )
        .map_err(|_| AppError::InvalidChain(last.seq))?;
    Ok(())
}

fn verify_export_evidence(bundle: &ExportBundle) -> Result<(), AppError> {
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
    Ok(())
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
