//! Store analyst-admitted rule bytes without reopening the analyst's directory.
use super::{LocalSigmaPack, inspect_local_sigma_pack, invalid};
use crate::LocalStore;
use irmind_app::{
    AppError, CancellationToken, Engine, SignedOperation,
    v10_proofs::{
        SigmaPackAdmissionV1, SigmaPackOriginV1, V10ObjectSection, V10ProofDescriptor,
        V10ProofFamily, read_v10_sigma_admission, sigma_pack_operation, v10_proof_commitment,
        write_v10_object_section,
    },
};
mod installation;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

pub struct AdmittedSigmaPack {
    pub operation: SignedOperation,
    pub pack: LocalSigmaPack,
}

impl LocalStore {
    /// Bind installation to the manifest displayed before Analyst confirmation.
    pub fn admit_local_sigma_pack(
        &self,
        engine: &Engine<'_>,
        directory: &Path,
        confirmed_manifest: [u8; 32],
        license: &str,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let pack = inspect_local_sigma_pack(directory, cancel)?;
        let manifest = pack.manifest.encode().map_err(|_| invalid())?;
        if irmind_app::sha256(&manifest) != confirmed_manifest {
            return Err(AppError::Policy(
                "Sigma pack changed after preview. Inspect it again before signing.".into(),
            ));
        }
        let family = V10ProofFamily::Sigma;
        let mut objects = BTreeMap::new();
        for (kind, bytes) in std::iter::once((0, manifest.as_slice()))
            .chain(pack.rules.iter().map(|rule| (1, rule.as_slice())))
        {
            let descriptor =
                V10ProofDescriptor::from_body(family, kind, bytes).map_err(|_| invalid())?;
            objects.insert(descriptor, bytes);
        }
        let descriptors = objects.keys().copied().collect::<Vec<_>>();
        let receipt = SigmaPackAdmissionV1 {
            pack_manifest: confirmed_manifest,
            proof_set: v10_proof_commitment(family, &descriptors).map_err(|_| invalid())?,
            origin: SigmaPackOriginV1::LocalDirectory,
            origin_label: "Local directory".into(),
            license: license.to_owned(),
        };
        engine.admit_sigma_pack(&receipt, |_, append| {
            self.publish_sigma_pack(&receipt, &objects, &descriptors, cancel, append)
        })
    }

    pub fn open_admitted_sigma_pack(
        &self,
        engine: &Engine<'_>,
        manifest: [u8; 32],
        cancel: &CancellationToken,
    ) -> Result<AdmittedSigmaPack, AppError> {
        let operation = engine
            .admitted_sigma_pack(manifest)?
            .ok_or_else(|| AppError::Policy("Sigma pack has no signed admission".into()))?;
        let receipt =
            sigma_pack_operation(&operation)?.ok_or(AppError::InvalidChain(operation.seq))?;
        let pack = self.read_signed_sigma_pack(&receipt, cancel)?;
        Ok(AdmittedSigmaPack { operation, pack })
    }

    pub(crate) fn read_signed_sigma_pack(
        &self,
        receipt: &SigmaPackAdmissionV1,
        cancel: &CancellationToken,
    ) -> Result<LocalSigmaPack, AppError> {
        let root = self.sigma_pack_root(false)?;
        let file = open_pack(&root, receipt.pack_manifest)?;
        read_pack(file, receipt, cancel)
    }

    fn publish_sigma_pack(
        &self,
        receipt: &SigmaPackAdmissionV1,
        objects: &BTreeMap<V10ProofDescriptor, &[u8]>,
        descriptors: &[V10ProofDescriptor],
        cancel: &CancellationToken,
        append: &dyn Fn() -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        let root = self.sigma_pack_root(true)?;
        let required = descriptors
            .iter()
            .map(|descriptor| descriptor.size() + V10ProofDescriptor::BYTE_LEN as u64)
            .sum::<u64>()
            + 8;
        if fs4::available_space(&root).map_err(crate::storage)? < required {
            return Err(AppError::Storage(
                "Insufficient disk space for the Sigma pack".into(),
            ));
        }
        let mut staged = tempfile::NamedTempFile::new_in(&root).map_err(crate::storage)?;
        irmind_fs::private_file(staged.path()).map_err(crate::storage)?;
        write_v10_object_section(
            &mut staged,
            V10ProofFamily::Sigma,
            descriptors,
            |descriptor| objects.get(&descriptor).copied().ok_or_else(invalid),
            cancel,
        )?;
        staged.as_file().sync_all().map_err(crate::storage)?;
        let path = root.join(pack_name(receipt.pack_manifest));
        let created = match staged.persist_noclobber(&path) {
            Ok(_) => true,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(crate::storage(error.error)),
        };
        let result = (|| {
            irmind_fs::sync_directory(&root).map_err(crate::storage)?;
            read_pack(open_pack(&root, receipt.pack_manifest)?, receipt, cancel)?;
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            append()
        })();
        if result.is_err() && created {
            fs::remove_file(&path).map_err(crate::storage)?;
            irmind_fs::sync_directory(&root).map_err(crate::storage)?;
        }
        result
    }

    fn sigma_pack_root(&self, create: bool) -> Result<PathBuf, AppError> {
        let parent = self.lock_dir.parent().ok_or_else(invalid)?;
        let root = parent.join("sigma-packs");
        if create {
            match fs::create_dir(&root) {
                Ok(()) => {
                    irmind_fs::private_dir(&root).map_err(crate::storage)?;
                    irmind_fs::sync_directory(parent).map_err(crate::storage)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(crate::storage(error)),
            }
        }
        let metadata = fs::symlink_metadata(&root).map_err(crate::storage)?;
        if !metadata.is_dir() || super::is_link(&metadata) {
            return Err(invalid());
        }
        Ok(root)
    }
}

fn pack_name(manifest: [u8; 32]) -> String {
    format!("{}.proof", irmind_app::hex(&manifest))
}

fn open_pack(root: &Path, manifest: [u8; 32]) -> Result<File, AppError> {
    let file = irmind_fs::open_regular_no_follow(root, Path::new(&pack_name(manifest)))
        .map_err(crate::storage)?;
    if !irmind_fs::regular_file_has_single_link(&file).map_err(crate::storage)? {
        return Err(invalid());
    }
    Ok(file)
}

fn read_pack(
    mut file: File,
    receipt: &SigmaPackAdmissionV1,
    cancel: &CancellationToken,
) -> Result<LocalSigmaPack, AppError> {
    let section = V10ObjectSection::scan(&mut file, V10ProofFamily::Sigma, cancel)?;
    if file.read(&mut [0]).map_err(crate::storage)? != 0 {
        return Err(invalid());
    }
    let mut referenced = BTreeSet::new();
    let manifest = read_v10_sigma_admission(&section, &mut file, receipt, &mut referenced, cancel)?;
    section.check_union(&referenced)?;
    let rules = manifest
        .0
        .iter()
        .map(|entry| section.body(&mut file, (1, entry.rule.sha256), cancel))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LocalSigmaPack { manifest, rules })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::{CryptoPorts, EnginePorts, Signer, Verifier};
    use irmind_domain::{Actor, ExecutionMode};
    use std::sync::Arc;

    #[test]
    fn admitted_sigma_pack_requires_the_preview_and_the_real_analyst_signature() {
        let data = tempfile::tempdir().unwrap();
        let input = tempfile::tempdir().unwrap();
        let path = input.path().join("test.yml");
        let rule = b"title: Synthetic test\nlogsource: {product: aws}\ndetection: {selection: {Outcome: failure}, condition: selection}\n";
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
                CryptoPorts::new(signer.clone(), verifier.clone()),
                Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
            ),
            ExecutionMode::Attended,
            Arc::new(crate::SystemClock),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        fs::write(&path, rule).unwrap();
        let draft = inspect_local_sigma_pack(input.path(), &cancel).unwrap();
        let digest = irmind_app::sha256(&draft.manifest.encode().unwrap());
        fs::write(&path, [rule.as_slice(), b"# edited\n"].concat()).unwrap();
        assert!(
            store
                .admit_local_sigma_pack(&engine, input.path(), digest, "MIT", &cancel)
                .is_err()
        );
        assert!(engine.admitted_sigma_pack(digest).unwrap().is_none());

        fs::write(&path, rule).unwrap();
        store
            .admit_local_sigma_pack(&engine, input.path(), digest, "MIT", &cancel)
            .unwrap();
        fs::remove_file(path).unwrap();
        let admitted = store
            .open_admitted_sigma_pack(&engine, digest, &cancel)
            .unwrap();
        let receipt = irmind_app::v10_proofs::verify_sigma_pack_operation(
            &admitted.operation,
            verifier.as_ref(),
        )
        .unwrap();
        assert_eq!(receipt.pack_manifest, digest);
        assert_eq!(receipt.license, "MIT");
        assert_eq!(admitted.pack.rules, vec![rule.to_vec()]);
        verifier
            .verify(
                &signer.public_key(),
                &admitted.operation.hash,
                &admitted.operation.sig,
            )
            .unwrap();

        let mut altered = admitted.operation;
        altered.sig[0] ^= 1;
        assert!(
            irmind_app::v10_proofs::verify_sigma_pack_operation(&altered, verifier.as_ref())
                .is_err()
        );

        let file = store
            .sigma_pack_root(false)
            .unwrap()
            .join(pack_name(digest));
        let mut broken = fs::read(&file).unwrap();
        *broken.last_mut().unwrap() ^= 1;
        fs::write(file, broken).unwrap();
        assert!(
            store
                .open_admitted_sigma_pack(&engine, digest, &cancel)
                .is_err()
        );
    }
}
