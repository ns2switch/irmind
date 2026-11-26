use super::{
    AppError, CancellationToken, Engine, File, LocalStore, Path, Read, SignedOperation, invalid,
};
use crate::sigma_pack::{
    SigmaPackageBundle, inspect_sigma_catalog_asset, inspect_sigma_package_bundle,
    inspect_sigmahq_catalog_reference,
};
use irmind_app::{
    catalog::{SigmaCatalogIndex, SigmaCatalogReleaseStamp},
    sha256,
    v10_proofs::{
        SigmaPackageInstallationV1, SigmaPackageOriginV1, decode_sigma_installation_operation,
    },
};
use std::io::Write;

const MAX_CATALOG_PROOF: u64 = irmind_app::catalog::MAX_CATALOG_INDEX_BYTES as u64 + 128;

pub struct CatalogSigmaInstallApproval<'a> {
    pub name: &'a str,
    pub proof: [u8; 32],
    pub asset: [u8; 32],
    pub previous: Option<[u8; 32]>,
    pub selection: Option<&'a [u8]>,
}

const MAX_BUNDLE: u64 = 2 * 64 * 1024 * 1024 + 8192 + 64;

impl LocalStore {
    /// Freeze the approved package and predecessor under the global lock.
    /// This does not admit a case run.
    pub fn install_local_sigma_package(
        &self,
        engine: &Engine<'_>,
        bytes: &[u8],
        approved_asset: [u8; 32],
        previous: Option<[u8; 32]>,
        cancel: &CancellationToken,
    ) -> Result<SignedOperation, AppError> {
        if bytes.len() as u64 > MAX_BUNDLE || sha256(bytes) != approved_asset {
            return Err(AppError::Policy(
                "Sigma package changed after preview".into(),
            ));
        }
        let bundle = inspect_sigma_package_bundle(bytes, cancel)?;
        let receipt = SigmaPackageInstallationV1 {
            name: bundle.metadata.name,
            version: bundle.metadata.version,
            active: true,
            previous_installation: previous,
            metadata: bundle.metadata_sha256,
            manifest: bundle.manifest_sha256,
            asset: approved_asset,
            license: bundle.metadata.license,
            origin: SigmaPackageOriginV1::Local,
        };
        let staged = self.stage_package_bytes(bytes, cancel)?;
        engine.commit_local_sigma_package(&receipt, |signed, append| {
            self.persist_package_bytes(staged, bytes, &bundle_name(&receipt), cancel)?;
            append()?;
            Ok(signed.clone())
        })
    }

    /// The index must already be authenticated with the compiled catalog key.
    /// The analyst's confirmation freezes both the proof and the selected asset.
    pub fn install_catalog_sigma_package(
        &self,
        engine: &Engine<'_>,
        index: &SigmaCatalogIndex,
        bytes: &[u8],
        approved: &CatalogSigmaInstallApproval<'_>,
        cancel: &CancellationToken,
    ) -> Result<SignedOperation, AppError> {
        if sha256(index.proof()) != approved.proof
            || bytes.len() as u64 > MAX_BUNDLE
            || sha256(bytes) != approved.asset
        {
            return Err(AppError::Policy(
                "Sigma catalog package changed after preview".into(),
            ));
        }
        let (bundle, origin) = if let Some(selection) = approved.selection {
            (
                inspect_sigmahq_catalog_reference(index, approved.name, bytes, selection, cancel)?,
                SigmaPackageOriginV1::SigmaHqArchive(approved.proof),
            )
        } else {
            (
                inspect_sigma_catalog_asset(index, approved.name, bytes, cancel)?,
                SigmaPackageOriginV1::CatalogAsset(approved.proof),
            )
        };
        let receipt = SigmaPackageInstallationV1 {
            name: bundle.metadata.name,
            version: bundle.metadata.version,
            active: true,
            previous_installation: approved.previous,
            metadata: bundle.metadata_sha256,
            manifest: bundle.manifest_sha256,
            asset: bundle.asset_sha256,
            license: bundle.metadata.license,
            origin,
        };
        let staged_proof = self.stage_package_bytes(index.proof(), cancel)?;
        let staged_bundle = self.stage_package_bytes(bytes, cancel)?;
        let staged_selection = approved
            .selection
            .map(|selection| self.stage_package_bytes(selection, cancel))
            .transpose()?;
        engine.commit_catalog_sigma_package(
            &receipt,
            index,
            |digest| {
                let bytes = self.read_sigma_catalog_proof(digest, cancel)?;
                Ok(SigmaCatalogReleaseStamp::from_signed_installation(
                    &bytes, digest,
                )?)
            },
            |signed, append| {
                self.persist_package_bytes(
                    staged_proof,
                    index.proof(),
                    &catalog_proof_name(approved.proof),
                    cancel,
                )?;
                self.persist_package_bytes(staged_bundle, bytes, &bundle_name(&receipt), cancel)?;
                if let Some((stage, selection)) = staged_selection.zip(approved.selection) {
                    self.persist_package_bytes(
                        stage,
                        selection,
                        &selection_name(receipt.manifest),
                        cancel,
                    )?;
                }
                append()?;
                Ok(signed.clone())
            },
        )
    }

    pub fn read_sigma_catalog_proof(
        &self,
        digest: [u8; 32],
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let root = self.sigma_pack_root(false)?;
        let file = open_owned(&root, &catalog_proof_name(digest))?;
        let bytes = read_pinned(file, MAX_CATALOG_PROOF, cancel)?;
        if sha256(&bytes) != digest {
            return Err(invalid());
        }
        Ok(bytes)
    }

    pub fn open_local_sigma_package(
        &self,
        engine: &Engine<'_>,
        name: &str,
        cancel: &CancellationToken,
    ) -> Result<Option<SigmaPackageBundle>, AppError> {
        let Some(operation) = engine.local_sigma_package_operation(name)? else {
            return Ok(None);
        };
        let receipt = decode_sigma_installation_operation(&operation)?;
        if !receipt.active {
            return Ok(None);
        }
        let root = self.sigma_pack_root(false)?;
        let file = open_owned(&root, &bundle_name(&receipt))?;
        let bytes = read_pinned(file, MAX_BUNDLE, cancel)?;
        if sha256(&bytes) != receipt.asset {
            return Err(invalid());
        }
        let bundle = if let SigmaPackageOriginV1::SigmaHqArchive(proof_digest) = receipt.origin {
            let proof = self.read_sigma_catalog_proof(proof_digest, cancel)?;
            let stamp = SigmaCatalogReleaseStamp::from_signed_installation(&proof, proof_digest)?;
            let publisher =
                self.catalog_verifier
                    .verify_sigma_proof(&proof, proof_digest, stamp.tag())?;
            let selection = read_pinned(
                open_owned(&root, &selection_name(receipt.manifest))?,
                64 * 1024 * 1024,
                cancel,
            )?;
            inspect_sigmahq_catalog_reference(&publisher, name, &bytes, &selection, cancel)?
        } else {
            inspect_sigma_package_bundle(&bytes, cancel)?
        };
        if bundle.metadata_sha256 != receipt.metadata
            || bundle.manifest_sha256 != receipt.manifest
            || bundle.metadata.name != receipt.name
            || bundle.metadata.version != receipt.version
            || bundle.metadata.license != receipt.license
        {
            return Err(invalid());
        }
        Ok(Some(bundle))
    }

    fn stage_package_bytes(
        &self,
        bytes: &[u8],
        cancel: &CancellationToken,
    ) -> Result<tempfile::NamedTempFile, AppError> {
        let root = self.sigma_pack_root(true)?;
        if fs4::available_space(&root).map_err(crate::storage)? < bytes.len() as u64 {
            return Err(AppError::Storage(
                "Insufficient disk space for the Sigma package".into(),
            ));
        }
        let mut staged = tempfile::NamedTempFile::new_in(&root).map_err(crate::storage)?;
        irmind_fs::private_file(staged.path()).map_err(crate::storage)?;
        for chunk in bytes.chunks(64 * 1024) {
            super::super::check_cancel(cancel)?;
            staged.write_all(chunk).map_err(crate::storage)?;
        }
        staged.as_file().sync_all().map_err(crate::storage)?;
        Ok(staged)
    }

    fn persist_package_bytes(
        &self,
        staged: tempfile::NamedTempFile,
        bytes: &[u8],
        name: &str,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let root = self.sigma_pack_root(false)?;
        let path = root.join(name);
        match staged.persist_noclobber(&path) {
            Ok(_) => (),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(crate::storage(error.error)),
        }
        irmind_fs::sync_directory(&root).map_err(crate::storage)?;
        // An interrupted publication leaves a content-addressed object with no
        // active receipt. A retry only publishes after comparing its exact bytes.
        let mut file = open_owned(&root, name)?;
        let mut observed = [0; 16 * 1024];
        for chunk in bytes.chunks(observed.len()) {
            super::super::check_cancel(cancel)?;
            file.read_exact(&mut observed[..chunk.len()])
                .map_err(crate::storage)?;
            if observed[..chunk.len()] != *chunk {
                return Err(invalid());
            }
        }
        if file.read(&mut observed[..1]).map_err(crate::storage)? != 0 {
            return Err(invalid());
        }
        super::super::check_cancel(cancel)?;
        Ok(())
    }
}

fn bundle_name(receipt: &SigmaPackageInstallationV1) -> String {
    format!("{}.sigma", irmind_app::hex(&receipt.asset))
}

fn selection_name(digest: [u8; 32]) -> String {
    format!("{}.selection", irmind_app::hex(&digest))
}

fn catalog_proof_name(digest: [u8; 32]) -> String {
    format!("{}.catalog", irmind_app::hex(&digest))
}

fn open_owned(root: &Path, name: &str) -> Result<File, AppError> {
    let file = irmind_fs::open_regular_no_follow(root, Path::new(name)).map_err(crate::storage)?;
    if !irmind_fs::regular_file_has_single_link(&file).map_err(crate::storage)? {
        return Err(invalid());
    }
    Ok(file)
}

fn read_pinned(
    mut file: File,
    limit: u64,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, AppError> {
    let size = file.metadata().map_err(crate::storage)?.len();
    if size > limit {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).map_err(|_| invalid())?);
    let mut chunk = [0; 16 * 1024];
    loop {
        super::super::check_cancel(cancel)?;
        let count = file.read(&mut chunk).map_err(crate::storage)?;
        if count == 0 {
            break;
        }
        if bytes.len() as u64 + count as u64 > size {
            return Err(invalid());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    if bytes.len() as u64 != size {
        return Err(invalid());
    }
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::{CryptoPorts, EnginePorts, Verifier};
    use irmind_domain::{Actor, ExecutionMode};
    use std::sync::Arc;

    #[test]
    fn local_package_activation_and_deactivation_use_the_signed_global_history() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../docs/development/sigma-package-vectors/wire.json"
        ))
        .unwrap();
        let raw = hex::decode(vectors["package"]["bytes_hex"].as_str().unwrap()).unwrap();
        let asset = sha256(&raw);
        let data = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalStore::open(data.path()).unwrap());
        let signer = Arc::new(crate::LocalSigner {
            key: ed25519_dalek::SigningKey::from_bytes(&[15; 32]),
            actor: Actor::Analyst,
        });
        let verifier = Arc::new(crate::LocalVerifier::from_signer(signer.as_ref()));
        let engine = Engine::new(
            EnginePorts::new(
                store.clone(),
                store.clone(),
                store.clone(),
                store.clone(),
                CryptoPorts::new(signer, verifier.clone()),
                Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
            ),
            ExecutionMode::Attended,
            Arc::new(crate::SystemClock),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        assert!(
            store
                .install_local_sigma_package(&engine, &raw, [0; 32], None, &cancel)
                .is_err()
        );
        assert!(
            engine
                .local_sigma_package_operation("synthetic")
                .unwrap()
                .is_none()
        );
        let activation = store
            .install_local_sigma_package(&engine, &raw, asset, None, &cancel)
            .unwrap();
        verifier
            .verify(&activation.public_key, &activation.hash, &activation.sig)
            .unwrap();
        let current = store
            .open_local_sigma_package(&engine, "synthetic", &cancel)
            .unwrap()
            .unwrap();
        assert_eq!(current.asset_sha256, asset);
        assert_eq!(current.pack.rules.len(), 1);
        let removed = engine
            .deactivate_sigma_package("synthetic", activation.hash)
            .unwrap();
        assert!(
            store
                .open_local_sigma_package(&engine, "synthetic", &cancel)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .install_local_sigma_package(&engine, &raw, asset, Some(activation.hash), &cancel)
                .is_err()
        );
        let restored = store
            .install_local_sigma_package(&engine, &raw, asset, Some(removed.hash), &cancel)
            .unwrap();
        assert_eq!(
            decode_sigma_installation_operation(&restored)
                .unwrap()
                .previous_installation,
            Some(removed.hash)
        );
        engine.verify_global_operations().unwrap();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod catalog_tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use irmind_app::{CryptoPorts, EnginePorts};
    use irmind_domain::{Actor, ExecutionMode};
    use std::sync::Arc;

    struct Fixture {
        store: Arc<LocalStore>,
        engine: Engine<'static>,
    }

    impl Fixture {
        fn open(root: &Path) -> Self {
            let store = Arc::new(LocalStore::open(root).unwrap());
            let signer = Arc::new(crate::LocalSigner {
                key: SigningKey::from_bytes(&[15; 32]),
                actor: Actor::Analyst,
            });
            let verifier = Arc::new(crate::LocalVerifier::from_signer(signer.as_ref()));
            let engine = Engine::new(
                EnginePorts::new(
                    store.clone(),
                    store.clone(),
                    store.clone(),
                    store.clone(),
                    CryptoPorts::new(signer, verifier),
                    Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
                ),
                ExecutionMode::Attended,
                Arc::new(crate::SystemClock),
            )
            .unwrap();
            Self { store, engine }
        }

        fn install(
            &self,
            index: &SigmaCatalogIndex,
            bytes: &[u8],
            previous: Option<[u8; 32]>,
        ) -> Result<SignedOperation, AppError> {
            self.store.install_catalog_sigma_package(
                &self.engine,
                index,
                bytes,
                &CatalogSigmaInstallApproval {
                    name: "synthetic",
                    proof: sha256(index.proof()),
                    asset: sha256(bytes),
                    previous,
                    selection: None,
                },
                &CancellationToken::new(),
            )
        }
    }

    fn signed_index(key: &SigningKey, raw: &str, tag: &str) -> SigmaCatalogIndex {
        let mut preimage = b"irmind-sigma-catalog-index-v1\0".to_vec();
        preimage.extend((raw.len() as u64).to_be_bytes());
        preimage.extend(raw.as_bytes());
        let signature = key.sign(&preimage).to_bytes();
        let verifier = crate::LocalVerifier {
            trusted: std::collections::BTreeMap::new(),
        };
        SigmaCatalogIndex::authenticate(
            raw.as_bytes(),
            &signature,
            tag,
            &[key.verifying_key().to_bytes()],
            &verifier,
        )
        .unwrap()
    }

    #[test]
    fn signed_sigmahq_reference_checks_archive_and_selection_before_activation() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../docs/development/sigma-package-vectors/wire.json"
        ))
        .unwrap();
        let decode =
            |name: &str| hex::decode(vectors[name]["bytes_hex"].as_str().unwrap()).unwrap();
        let original = String::from_utf8(decode("index")).unwrap();
        let (before, tail) = original.split_once("\"source\":").unwrap();
        let (_, after) = tail.split_once(",\"coverage\":").unwrap();
        let raw = decode("package");
        let cancel = CancellationToken::new();
        let pack = inspect_sigma_package_bundle(&raw, &cancel).unwrap().pack;
        let manifest = pack.manifest.encode().unwrap();
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zip.start_file(
            "rule.yml",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        zip.write_all(&pack.rules[0]).unwrap();
        let archive = zip.finish().unwrap().into_inner();
        let record = format!(
            r#"{{"kind":"sigmahq-archive","url":"https://github.com/SigmaHQ/sigma/releases/download/v1.0.0/synthetic.zip","bytes":{},"sha256":"{}","attribution":"Synthetic example","selection_asset":"selection.bin","selection_bytes":{}}}"#,
            archive.len(),
            irmind_app::hex(&sha256(&archive)),
            manifest.len(),
        );
        let index_text = format!("{before}\"source\":{record},\"coverage\":{after}")
            .replace("\"license\":\"MIT\"", "\"license\":\"DRL-1.1\"");
        let publisher =
            SigningKey::from_bytes(&sha256(b"synthetic shared skills and Sigma publisher"));
        let index = signed_index(&publisher, &index_text, "v1.0.0");
        let root = tempfile::tempdir().unwrap();
        let session = Fixture::open(root.path());
        let approved = CatalogSigmaInstallApproval {
            name: "synthetic",
            proof: sha256(index.proof()),
            asset: sha256(&archive),
            previous: None,
            selection: Some(&manifest),
        };
        let mut bad_manifest = manifest.clone();
        bad_manifest[0] ^= 1;
        let invalid = CatalogSigmaInstallApproval {
            selection: Some(&bad_manifest),
            ..approved
        };
        assert!(
            session
                .store
                .install_catalog_sigma_package(&session.engine, &index, &archive, &invalid, &cancel)
                .is_err()
        );
        assert!(session.engine.sigma_installations().unwrap().is_empty());
        let receipt = session
            .store
            .install_catalog_sigma_package(&session.engine, &index, &archive, &approved, &cancel)
            .unwrap();
        let receipt = decode_sigma_installation_operation(&receipt).unwrap();
        assert_eq!(
            receipt.origin,
            SigmaPackageOriginV1::SigmaHqArchive(approved.proof)
        );
        assert_eq!(receipt.manifest, sha256(&manifest));
    }

    #[test]
    fn signed_catalog_history_rejects_rollback_and_equivocation_after_reopen_and_removal() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../docs/development/sigma-package-vectors/wire.json"
        ))
        .unwrap();
        let decode =
            |name: &str| hex::decode(vectors[name]["bytes_hex"].as_str().unwrap()).unwrap();
        let original = String::from_utf8(decode("index")).unwrap();
        let next = original
            .replace("\"release_tag\":\"v1.0.0\"", "\"release_tag\":\"v2.0.0\"")
            .replace("\"release_sequence\":1", "\"release_sequence\":2");
        let publisher =
            SigningKey::from_bytes(&sha256(b"synthetic shared skills and Sigma publisher"));
        let first = signed_index(&publisher, &original, "v1.0.0");
        let latest = signed_index(&publisher, &next, "v2.0.0");
        let conflict = signed_index(
            &publisher,
            &next.replace(
                "\"aws\",\"cloudtrail\",null",
                "\"aws\",\"cloudtrail\",\"authentication\"",
            ),
            "v2.0.0",
        );
        let raw = decode("package");
        let root = tempfile::tempdir().unwrap();
        let installed = {
            let session = Fixture::open(root.path());
            let first_entry = session.install(&first, &raw, None).unwrap();
            session
                .install(&latest, &raw, Some(first_entry.hash))
                .unwrap()
        };
        let fresh = Fixture::open(root.path());
        let removed = fresh
            .engine
            .deactivate_sigma_package("synthetic", installed.hash)
            .unwrap();
        assert!(fresh.install(&first, &raw, Some(removed.hash)).is_err());
        assert!(fresh.install(&conflict, &raw, Some(removed.hash)).is_err());
        assert!(
            fresh
                .store
                .open_local_sigma_package(&fresh.engine, "synthetic", &CancellationToken::new())
                .unwrap()
                .is_none()
        );
        assert!(fresh.install(&latest, &raw, Some(removed.hash)).is_ok());
        fresh.engine.verify_global_operations().unwrap();
    }
}
