use super::{AppError, CaseId, CaseSeal, LocalStore, fs, storage, storage_reason};
use serde_json::Value;

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
