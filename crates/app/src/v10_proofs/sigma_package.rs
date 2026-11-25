use super::{CaseCheckpointV1, Digest, INVALID, Result, Wire, put_optional_hash, put_text};

const INSTALLATION: &[u8] = b"irmind-sigma-package-installation-v1\0";
const CASE_ADMISSION: &[u8] = b"irmind-sigma-case-run-admission-v1\0";
pub const SIGMA_EVALUATOR_V3_CASE_ADMISSION: &str = "irmind-sigma-evaluator-v3-case-admission-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SigmaPackageOriginV1 {
    Local,
    CatalogAsset(Digest),
    SigmaHqArchive(Digest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigmaPackageInstallationV1 {
    pub name: String,
    pub version: String,
    pub active: bool,
    pub previous_installation: Option<Digest>,
    pub metadata: Digest,
    pub manifest: Digest,
    pub asset: Digest,
    pub license: String,
    pub origin: SigmaPackageOriginV1,
}

impl SigmaPackageInstallationV1 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = INSTALLATION.to_vec();
        put_text(&mut out, &self.name, 64)?;
        put_text(&mut out, &self.version, 64)?;
        out.push(u8::from(self.active));
        put_optional_hash(&mut out, self.previous_installation);
        out.extend(self.metadata);
        out.extend(self.manifest);
        out.extend(self.asset);
        put_text(&mut out, &self.license, 4096)?;
        let (kind, proof) = match self.origin {
            SigmaPackageOriginV1::Local => (0, None),
            SigmaPackageOriginV1::CatalogAsset(proof) => (1, Some(proof)),
            SigmaPackageOriginV1::SigmaHqArchive(proof) => (2, Some(proof)),
        };
        out.push(kind);
        put_optional_hash(&mut out, proof);
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire(body.strip_prefix(INSTALLATION).ok_or(INVALID)?);
        let name = wire.text(64)?;
        let version = wire.text(64)?;
        let active = match wire.byte()? {
            0 => false,
            1 => true,
            _ => return Err(INVALID),
        };
        let previous_installation = wire.optional_hash()?;
        let metadata = wire.fixed()?;
        let manifest = wire.fixed()?;
        let asset = wire.fixed()?;
        let license = wire.text(4096)?;
        let origin = match (wire.byte()?, wire.optional_hash()?) {
            (0, None) => SigmaPackageOriginV1::Local,
            (1, Some(proof)) => SigmaPackageOriginV1::CatalogAsset(proof),
            (2, Some(proof)) => SigmaPackageOriginV1::SigmaHqArchive(proof),
            _ => return Err(INVALID),
        };
        wire.finish()?;
        let receipt = Self {
            name,
            version,
            active,
            previous_installation,
            metadata,
            manifest,
            asset,
            license,
            origin,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<()> {
        if (!self.active && self.previous_installation.is_none())
            || !valid_sigma_package_identity(&self.name, &self.version)
            || self.license.chars().any(char::is_control)
        {
            return Err(INVALID);
        }
        Ok(())
    }
}

pub fn valid_sigma_package_identity(name: &str, version: &str) -> bool {
    let name = name.as_bytes();
    if name.len() > 64
        || !name.first().is_some_and(u8::is_ascii_lowercase)
        || name.ends_with(b"-")
        || !name
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        || version.len() > 64
    {
        return false;
    }
    crate::catalog::valid_sigma_package_version(version)
}

#[derive(Clone, Eq, PartialEq)]
pub struct SigmaCaseRunAdmissionV1 {
    pub checkpoint: CaseCheckpointV1,
    pub installation: Option<Digest>,
    pub pack_admission: Digest,
    pub manifest: Digest,
    pub artifact_inventory: Digest,
    pub selected_sources: Digest,
    pub start_us: i64,
    pub end_us: i64,
    pub field_table: Digest,
    pub compiled_rules: Digest,
    pub evaluator: String,
    pub reserved_work: u64,
}

impl SigmaCaseRunAdmissionV1 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = CASE_ADMISSION.to_vec();
        self.checkpoint.write(&mut out)?;
        put_optional_hash(&mut out, self.installation);
        out.extend(self.pack_admission);
        out.extend(self.manifest);
        out.extend(self.artifact_inventory);
        out.extend(self.selected_sources);
        out.extend(self.start_us.to_be_bytes());
        out.extend(self.end_us.to_be_bytes());
        out.extend(self.field_table);
        out.extend(self.compiled_rules);
        put_text(&mut out, &self.evaluator, 128)?;
        out.extend(self.reserved_work.to_be_bytes());
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire(body.strip_prefix(CASE_ADMISSION).ok_or(INVALID)?);
        let receipt = Self {
            checkpoint: CaseCheckpointV1::read(&mut wire)?,
            installation: wire.optional_hash()?,
            pack_admission: wire.fixed()?,
            manifest: wire.fixed()?,
            artifact_inventory: wire.fixed()?,
            selected_sources: wire.fixed()?,
            start_us: i64::from_be_bytes(wire.fixed()?),
            end_us: i64::from_be_bytes(wire.fixed()?),
            field_table: wire.fixed()?,
            compiled_rules: wire.fixed()?,
            evaluator: wire.text(128)?,
            reserved_work: wire.u64()?,
        };
        wire.finish()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<()> {
        if self.start_us >= self.end_us
            || self.evaluator != SIGMA_EVALUATOR_V3_CASE_ADMISSION
            || self.reserved_work == 0
        {
            return Err(INVALID);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn approved_package_receipts_round_trip() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/development/sigma-package-vectors/wire.json"
        ))
        .unwrap();
        let bytes = |name: &str| hex::decode(vectors[name]["bytes_hex"].as_str().unwrap()).unwrap();
        for key in [
            "catalog_installation",
            "local_installation",
            "local_deactivation",
        ] {
            let body = bytes(key);
            let receipt = SigmaPackageInstallationV1::decode(&body).unwrap();
            assert_eq!(receipt.encode().unwrap(), body);
        }
        let body = bytes("case_admission");
        let mut receipt = SigmaCaseRunAdmissionV1::decode(&body).unwrap();
        assert_eq!(receipt.encode().unwrap(), body);
        receipt.evaluator = super::super::SIGMA_EVALUATOR_V3.to_owned();
        assert!(receipt.encode().is_err());
        let mut trailing = body;
        trailing.push(0);
        assert!(SigmaCaseRunAdmissionV1::decode(&trailing).is_err());
    }
}
