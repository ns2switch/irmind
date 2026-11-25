use super::{
    AppError, CancellationToken, Engine, File, LocalStore, Path, Read, SignedOperation, invalid,
};
use crate::sigma_pack::{SigmaPackageBundle, inspect_sigma_package_bundle};
use irmind_app::{
    sha256,
    v10_proofs::{
        SigmaPackageInstallationV1, SigmaPackageOriginV1, decode_sigma_installation_operation,
    },
};
use std::io::Write;

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
        let staged = self.stage_local_bundle(bytes, cancel)?;
        engine.commit_local_sigma_package(&receipt, |signed, append| {
            self.publish_local_bundle(staged, bytes, &receipt, cancel, append)?;
            Ok(signed.clone())
        })
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
        if receipt.origin != SigmaPackageOriginV1::Local {
            return Err(invalid());
        }
        let root = self.sigma_pack_root(false)?;
        let mut file = open_bundle(&root, &receipt)?;
        let size = file.metadata().map_err(crate::storage)?.len();
        if size > MAX_BUNDLE {
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
        if bytes.len() as u64 != size || sha256(&bytes) != receipt.asset {
            return Err(invalid());
        }
        let bundle = inspect_sigma_package_bundle(&bytes, cancel)?;
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

    pub fn deactivate_local_sigma_package(
        &self,
        engine: &Engine<'_>,
        name: &str,
        approved_installed_operation: [u8; 32],
    ) -> Result<SignedOperation, AppError> {
        let operation = engine
            .local_sigma_package_operation(name)?
            .filter(|operation| operation.hash == approved_installed_operation)
            .ok_or_else(|| AppError::Policy("Sigma package changed after preview".into()))?;
        let mut receipt = decode_sigma_installation_operation(&operation)?;
        receipt.previous_installation = Some(operation.hash);
        receipt.active = false;
        engine.commit_local_sigma_package(&receipt, |signed, append| {
            append()?;
            Ok(signed.clone())
        })
    }

    fn stage_local_bundle(
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

    fn publish_local_bundle(
        &self,
        staged: tempfile::NamedTempFile,
        bytes: &[u8],
        receipt: &SigmaPackageInstallationV1,
        cancel: &CancellationToken,
        append: &dyn Fn() -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        let root = self.sigma_pack_root(false)?;
        let path = root.join(bundle_name(receipt));
        match staged.persist_noclobber(&path) {
            Ok(_) => (),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(crate::storage(error.error)),
        }
        irmind_fs::sync_directory(&root).map_err(crate::storage)?;
        // An interrupted publication leaves a content-addressed object with no
        // active receipt. A retry only publishes after comparing its exact bytes.
        let mut file = open_bundle(&root, receipt)?;
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
        append()
    }
}

fn bundle_name(receipt: &SigmaPackageInstallationV1) -> String {
    format!("{}.sigma", irmind_app::hex(&receipt.asset))
}

fn open_bundle(root: &Path, receipt: &SigmaPackageInstallationV1) -> Result<File, AppError> {
    let file = irmind_fs::open_regular_no_follow(root, Path::new(&bundle_name(receipt)))
        .map_err(crate::storage)?;
    if !irmind_fs::regular_file_has_single_link(&file).map_err(crate::storage)? {
        return Err(invalid());
    }
    Ok(file)
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
        let removed = store
            .deactivate_local_sigma_package(&engine, "synthetic", activation.hash)
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
