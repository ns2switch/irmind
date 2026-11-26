use super::{CaseCheckpointV1, Digest, INVALID, Result, Wire, put_optional_hash, put_text};

const INSTALLATION: &[u8] = b"irmind-sigma-package-installation-v1\0";
const CASE_ADMISSION: &[u8] = b"irmind-sigma-case-run-admission-v1\0";
pub const SIGMA_EVALUATOR_V3_CASE_ADMISSION: &str = "irmind-sigma-evaluator-v3-case-admission-v1";
pub const SIGMA_EVALUATOR_V4_CASE_ADMISSION: &str = "irmind-sigma-evaluator-v4-case-admission-v1";

pub fn requires_sigma_case_admission(evaluator: &str) -> bool {
    matches!(
        evaluator,
        SIGMA_EVALUATOR_V3_CASE_ADMISSION | SIGMA_EVALUATOR_V4_CASE_ADMISSION
    )
}

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

    /// Check a transition against the preceding authenticated operation for this
    /// name. Replay must include deactivated installations.
    pub fn validate_successor(&self, previous: Option<(&Self, Digest)>) -> Result<()> {
        self.validate()?;
        let Some((old, hash)) = previous else {
            return if self.previous_installation.is_none() && self.active {
                Ok(())
            } else {
                Err(INVALID)
            };
        };
        if self.previous_installation != Some(hash)
            || self.name != old.name
            || std::mem::discriminant(&self.origin) != std::mem::discriminant(&old.origin)
            || crate::catalog::older_or_unknown(&self.version, &old.version)
        {
            return Err(INVALID);
        }
        if self.version == old.version
            && (self.metadata != old.metadata
                || self.manifest != old.manifest
                || self.asset != old.asset
                || self.license != old.license)
        {
            return Err(INVALID);
        }
        if !self.active && (!old.active || self.version != old.version || self.origin != old.origin)
        {
            return Err(INVALID);
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if (!self.active && self.previous_installation.is_none())
            || !valid_sigma_package_identity(&self.name, &self.version)
            || !valid_sigma_license_expression(&self.license)
        {
            return Err(INVALID);
        }
        Ok(())
    }
}

/// Validate bounded SPDX expression syntax. Catalog review checks the
/// declarations and distribution rights against the actual rule sources.
pub fn valid_sigma_license_expression(expression: &str) -> bool {
    enum Expected {
        License,
        Operator { may_add_exception: bool },
        Exception,
    }
    fn identifier(token: &str) -> bool {
        !matches!(
            token,
            "AND" | "OR" | "WITH" | "NONE" | "NOASSERTION" | "DRL-1.1"
        ) && token
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    }

    fn license_identifier(token: &str) -> bool {
        if let Some(rest) = token.strip_prefix("DocumentRef-") {
            return rest
                .split_once(":LicenseRef-")
                .is_some_and(|(document, license)| identifier(document) && identifier(license));
        }
        identifier(token)
    }

    if expression == "DRL-1.1" {
        return true;
    }
    if !(1..=4096).contains(&expression.len()) || !expression.is_ascii() {
        return false;
    }

    let mut rest = expression;
    let mut depth = 0;
    let mut expected = Expected::License;
    while !rest.is_empty() {
        rest = rest.trim_start_matches(' ');
        let Some(first) = rest.as_bytes().first() else {
            break;
        };
        let length = if matches!(first, b'(' | b')') {
            1
        } else {
            rest.find([' ', '(', ')']).unwrap_or(rest.len())
        };
        let (token, tail) = rest.split_at(length);
        rest = tail;
        expected = match (expected, token) {
            (Expected::License, "(") if depth < 16 => {
                depth += 1;
                Expected::License
            }
            (Expected::License, token)
                if license_identifier(token.strip_suffix('+').unwrap_or(token)) =>
            {
                Expected::Operator {
                    may_add_exception: !token.ends_with('+'),
                }
            }
            (Expected::Operator { .. }, "AND" | "OR") => Expected::License,
            (
                Expected::Operator {
                    may_add_exception: true,
                },
                "WITH",
            ) => Expected::Exception,
            (Expected::Exception, token) if identifier(token) => Expected::Operator {
                may_add_exception: false,
            },
            (Expected::Operator { .. }, ")") if depth > 0 => {
                depth -= 1;
                Expected::Operator {
                    may_add_exception: false,
                }
            }
            _ => return false,
        };
    }
    depth == 0 && matches!(expected, Expected::Operator { .. })
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

    /// Decode the record whose outer signature and case chain were authenticated.
    pub fn from_case_entry(
        entry: &crate::SignedEntry,
    ) -> std::result::Result<Self, crate::AppError> {
        use crate::{Actor, AppError, AuditEventKind};
        let invalid = || AppError::InvalidChain(entry.seq);
        if entry.kind != AuditEventKind::SigmaCaseRunAdmissionV1
            || entry.actor != Actor::Analyst
            || entry.origin != "analyst"
            || entry.evidence.is_some()
        {
            return Err(invalid());
        }
        let body = super::decode_payload(&entry.payload, CASE_ADMISSION).map_err(|_| invalid())?;
        let receipt = Self::decode(&body).map_err(|_| invalid())?;
        if receipt.checkpoint.case_id.as_str() != entry.case_id
            || receipt.checkpoint.sequence.checked_add(1) != Some(entry.seq)
            || receipt.checkpoint.entry_hash != entry.prev
        {
            return Err(invalid());
        }
        Ok(receipt)
    }

    /// The signed run follows its admission and matches the exact approved
    /// selection, field table, evaluator and reservation.
    pub fn verify_following_run(
        admission: &crate::SignedEntry,
        run: &super::SigmaRunV1,
        pack_manifest: Digest,
    ) -> std::result::Result<Self, crate::AppError> {
        let claim = Self::from_case_entry(admission)?;
        if run.checkpoint.case_id != claim.checkpoint.case_id
            || run.checkpoint.sequence != admission.seq
            || run.checkpoint.entry_hash != admission.hash
            || run.pack_admission != claim.pack_admission
            || pack_manifest != claim.manifest
            || run.artifact_inventory != claim.artifact_inventory
            || run.selected_sources != claim.selected_sources
            || run.start_utc_micros != claim.start_us
            || run.end_utc_micros != claim.end_us
            || run.field_table != claim.field_table
            || run.compiled_rules != claim.compiled_rules
            || run.evaluator != claim.evaluator
            || run.reserved_units != claim.reserved_work
        {
            return Err(crate::AppError::InvalidChain(admission.seq));
        }
        Ok(claim)
    }

    fn validate(&self) -> Result<()> {
        if self.start_us >= self.end_us
            || !requires_sigma_case_admission(&self.evaluator)
            || self.reserved_work == 0
        {
            return Err(INVALID);
        }
        Ok(())
    }
}

/// Authenticate the exact kind-6 object against the operation hash in a
/// signed case admission and the Analyst identity verified for that case.
pub fn verify_sigma_installation_proof(
    body: &[u8],
    expected_operation: Digest,
    verifier: &dyn crate::Verifier,
) -> std::result::Result<SigmaPackageInstallationV1, crate::AppError> {
    use crate::{Actor, AppError, GLOBAL_OPERATION_SCOPE, SignedOperation};
    let decode_error = || AppError::InvalidChain(0);
    if body.len() > 32 * 1024 {
        return Err(decode_error());
    }
    let entry: SignedOperation = serde_json::from_slice(body).map_err(|_| decode_error())?;
    let invalid = || AppError::InvalidChain(entry.seq);
    if serde_json::to_vec(&entry).map_err(|_| invalid())? != body
        || entry.case_id != GLOBAL_OPERATION_SCOPE
        || entry.actor != Actor::Analyst
        || entry.seq == 0
        || entry.sig.len() != 64
        || entry.public_key.len() != 32
        || entry.hash != expected_operation
        || crate::sha256(&entry.canonical()) != entry.hash
        || verifier.trusted_public_key(&Actor::Analyst)? != entry.public_key
    {
        return Err(invalid());
    }
    verifier
        .verify(&entry.public_key, &entry.hash, &entry.sig)
        .map_err(|_| invalid())?;
    let receipt = decode_sigma_installation_operation(&entry)?;
    if !receipt.active {
        return Err(invalid());
    }
    Ok(receipt)
}

pub fn decode_sigma_installation_operation(
    entry: &crate::SignedOperation,
) -> std::result::Result<SigmaPackageInstallationV1, crate::AppError> {
    let invalid = || crate::AppError::InvalidChain(entry.seq);
    if entry.operation.len() > 16 * 1024 {
        return Err(invalid());
    }
    let raw = hex::decode(&entry.operation).map_err(|_| invalid())?;
    if crate::hex(&raw) != entry.operation {
        return Err(invalid());
    }
    SigmaPackageInstallationV1::decode(&raw).map_err(|_| invalid())
}

/// Reject orphaned and misversioned case admissions after chain verification.
pub fn verify_sigma_case_admission_pairs(
    entries: &[crate::SignedEntry],
) -> std::result::Result<(), crate::AppError> {
    use crate::{AppError, AuditEventKind};
    for (index, entry) in entries.iter().enumerate() {
        if entry.kind == AuditEventKind::SigmaCaseRunAdmissionV1 {
            let admission = SigmaCaseRunAdmissionV1::from_case_entry(entry)?;
            let following = entries
                .get(index + 1)
                .ok_or(AppError::InvalidChain(entry.seq))?;
            let run = super::sigma_execution(following)?;
            SigmaCaseRunAdmissionV1::verify_following_run(entry, &run, admission.manifest)?;
        } else if entry.kind == AuditEventKind::SigmaRunV1 {
            let run = super::sigma_execution(entry)?;
            if requires_sigma_case_admission(&run.evaluator)
                && index
                    .checked_sub(1)
                    .and_then(|before| entries.get(before))
                    .is_none_or(|before| before.kind != AuditEventKind::SigmaCaseRunAdmissionV1)
            {
                return Err(AppError::InvalidChain(entry.seq));
            }
        }
    }
    Ok(())
}

impl crate::Engine<'_> {
    /// Read the latest operation after authenticating the complete global chain.
    pub fn local_sigma_package_operation(
        &self,
        name: &str,
    ) -> std::result::Result<Option<crate::SignedOperation>, crate::AppError> {
        Ok(self
            .sigma_installations()?
            .remove(name)
            .map(|(_, entry)| entry))
    }

    /// List authenticated latest receipts, including deactivation tombstones.
    pub fn sigma_installations(
        &self,
    ) -> std::result::Result<
        std::collections::BTreeMap<String, (SigmaPackageInstallationV1, crate::SignedOperation)>,
        crate::AppError,
    > {
        use crate::AppError;
        let entries = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&entries)?;
        let prefix = crate::hex(INSTALLATION);
        let mut latest = std::collections::BTreeMap::<
            String,
            (SigmaPackageInstallationV1, crate::SignedOperation),
        >::new();
        for entry in entries {
            if !entry.operation.starts_with(&prefix) {
                continue;
            }
            let receipt = decode_sigma_installation_operation(&entry)?;
            let old = latest
                .get(&receipt.name)
                .map(|(old, operation)| (old, operation.hash));
            receipt
                .validate_successor(old)
                .map_err(|_| AppError::InvalidChain(entry.seq))?;
            latest.insert(receipt.name.clone(), (receipt, entry));
        }
        Ok(latest)
    }

    pub fn deactivate_sigma_package(
        &self,
        name: &str,
        expected: Digest,
    ) -> std::result::Result<crate::SignedOperation, crate::AppError> {
        use crate::AppError;
        let mut history = self.sigma_installations()?;
        let (mut receipt, head) = history
            .remove(name)
            .filter(|(receipt, operation)| receipt.active && operation.hash == expected)
            .ok_or_else(|| AppError::Policy("Sigma package changed after preview".into()))?;
        receipt.active = false;
        receipt.previous_installation = Some(head.hash);
        self.commit_local_sigma_package(&receipt, |signed, append| {
            append()?;
            Ok(signed.clone())
        })
    }

    /// Commit a local installation or deactivation only after the caller has
    /// staged and checked the exact approved bytes. The global lock covers the
    /// preview check, signing and durable publication.
    pub fn commit_local_sigma_package<T>(
        &self,
        receipt: &SigmaPackageInstallationV1,
        publish: impl FnOnce(
            &crate::SignedOperation,
            &dyn Fn() -> std::result::Result<(), crate::AppError>,
        ) -> std::result::Result<T, crate::AppError>,
    ) -> std::result::Result<T, crate::AppError> {
        use crate::AppError;
        self.require_attended_analyst("install or deactivate Sigma package")?;
        if receipt.active && receipt.origin != SigmaPackageOriginV1::Local {
            return Err(AppError::Policy(
                "Catalog installation requires a verified catalog preview".into(),
            ));
        }
        let _lock = self.audit_log.lock_global_operations()?;
        self.commit_sigma_package_unlocked(receipt, publish)
    }

    /// Serialize catalog and local operations under the same global lock.
    /// Old publisher receipts supply the floor even after deactivation.
    pub fn commit_catalog_sigma_package<T>(
        &self,
        receipt: &SigmaPackageInstallationV1,
        index: &crate::catalog::SigmaCatalogIndex,
        mut read_history: impl FnMut(
            Digest,
        ) -> std::result::Result<
            crate::catalog::SigmaCatalogReleaseStamp,
            crate::AppError,
        >,
        publish: impl FnOnce(
            &crate::SignedOperation,
            &dyn Fn() -> std::result::Result<(), crate::AppError>,
        ) -> std::result::Result<T, crate::AppError>,
    ) -> std::result::Result<T, crate::AppError> {
        use crate::{
            AppError,
            catalog::{CatalogError, SigmaCatalogSource},
        };
        self.require_attended_analyst("install Sigma catalog package")?;
        let entry = index
            .entries()
            .iter()
            .find(|item| item.name == receipt.name)
            .ok_or(CatalogError::InvalidData)?;
        let proof = crate::sha256(index.proof());
        let (expected_origin, asset) = match &entry.source {
            SigmaCatalogSource::CatalogAsset { sha256, .. } => {
                (SigmaPackageOriginV1::CatalogAsset(proof), sha256)
            }
            SigmaCatalogSource::SigmahqArchive { sha256, .. } => {
                (SigmaPackageOriginV1::SigmaHqArchive(proof), sha256)
            }
        };
        if !receipt.active
            || receipt.origin != expected_origin
            || receipt.manifest != *entry.manifest_sha256.as_bytes()
            || receipt.asset != *asset.as_bytes()
            || receipt.version != entry.version
            || receipt.license != entry.license
        {
            return Err(CatalogError::AssetMismatch.into());
        }
        let _lock = self.audit_log.lock_global_operations()?;
        let history = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&history)?;
        let mut checked = std::collections::BTreeSet::new();
        let prefix = crate::hex(INSTALLATION);
        for operation in &history {
            if operation.operation.starts_with(&prefix) {
                let old = decode_sigma_installation_operation(operation)?;
                if let SigmaPackageOriginV1::CatalogAsset(old_proof)
                | SigmaPackageOriginV1::SigmaHqArchive(old_proof) = old.origin
                    && checked.insert(old_proof)
                {
                    index.check_release_history([read_history(old_proof)?]).map_err(|_| {
                        AppError::Policy("Sigma catalog release would roll back or conflict with a signed installation".into())
                    })?;
                }
            }
        }
        self.commit_sigma_package_unlocked(receipt, publish)
    }

    fn commit_sigma_package_unlocked<T>(
        &self,
        receipt: &SigmaPackageInstallationV1,
        publish: impl FnOnce(
            &crate::SignedOperation,
            &dyn Fn() -> std::result::Result<(), crate::AppError>,
        ) -> std::result::Result<T, crate::AppError>,
    ) -> std::result::Result<T, crate::AppError> {
        use crate::AppError;
        let previous = self.local_sigma_package_operation(&receipt.name)?;
        if let Some(old) = &previous {
            let old_receipt = decode_sigma_installation_operation(old)?;
            receipt.validate_successor(Some((&old_receipt, old.hash)))
        } else {
            receipt.validate_successor(None)
        }
        .map_err(|_| {
            AppError::Policy(
                "Sigma package preview is stale or would roll back or replace a committed version"
                    .into(),
            )
        })?;
        let body = receipt
            .encode()
            .map_err(|_| AppError::Policy("Invalid Sigma package installation receipt".into()))?;
        let signed = self.sign_global_operation_unlocked(crate::hex(&body))?;
        publish(&signed, &|| self.audit_log.append_global_operation(&signed))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn package_license_expression_rejects_invalid_structure() {
        for expression in [
            "DRL-1.1",
            "MIT OR (Apache-2.0 AND BSD-3-Clause)",
            "GPL-2.0-only WITH Classpath-exception-2.0",
            "DocumentRef-package:LicenseRef-Local",
        ] {
            assert!(valid_sigma_license_expression(expression), "{expression}");
        }
        for expression in [
            "",
            "MIT OR",
            "(MIT AND Apache-2.0",
            "AND MIT",
            "MIT Apache-2.0",
            "MIT WITH WITH Apache-2.0",
            "MIT\nOR Apache-2.0",
            "DRL-1.1 OR MIT",
        ] {
            assert!(!valid_sigma_license_expression(expression), "{expression}");
        }
    }

    #[test]
    fn deactivation_preserves_the_version_floor_and_the_exact_package() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/development/sigma-package-vectors/wire.json"
        ))
        .unwrap();
        let raw =
            hex::decode(vectors["local_installation"]["bytes_hex"].as_str().unwrap()).unwrap();
        let first = SigmaPackageInstallationV1::decode(&raw).unwrap();
        let first_hash = crate::sha256(b"synthetic signed installation");
        assert!(first.validate_successor(None).is_ok());

        let mut removed = first.clone();
        removed.active = false;
        removed.previous_installation = Some(first_hash);
        assert!(
            removed
                .validate_successor(Some((&first, first_hash)))
                .is_ok()
        );
        let removal_hash = crate::sha256(b"synthetic signed removal");
        let mut candidate = removed.clone();
        candidate.active = true;
        candidate.previous_installation = Some(removal_hash);
        assert!(
            candidate
                .validate_successor(Some((&removed, removal_hash)))
                .is_ok()
        );

        candidate.version = "0.9.0".into();
        assert!(
            candidate
                .validate_successor(Some((&removed, removal_hash)))
                .is_err()
        );
        candidate.version.clone_from(&removed.version);
        candidate.asset[0] ^= 1;
        assert!(
            candidate
                .validate_successor(Some((&removed, removal_hash)))
                .is_err()
        );
    }

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
