//! V10 includes only the objects and global admissions referenced by runs.
use super::{AppError, CancellationToken, CaseId, LocalStore};
use irmind_app::{
    SignedEntry, SignedOperation,
    v10_proofs::{V10ProofDescriptor, V10ProofFamily, write_v10_object_section},
};
use irmind_domain::AuditEventKind;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct SigmaArchive {
    pub operations: BTreeMap<[u8; 32], SignedOperation>,
    bodies: BTreeMap<V10ProofDescriptor, Vec<u8>>,
    #[cfg(feature = "sigma")]
    total_bytes: u64,
}

impl SigmaArchive {
    pub(super) fn collect(
        store: &LocalStore,
        case: &CaseId,
        entries: &[SignedEntry],
        analyst_key: &[u8],
        cancel: &CancellationToken,
    ) -> Result<Self, AppError> {
        let mut runs = entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SigmaRunV1)
            .peekable();
        if runs.peek().is_none() {
            return Ok(Self::default());
        }
        #[cfg(not(feature = "sigma"))]
        {
            let _ = (store, case, analyst_key, cancel);
            Err(AppError::Policy(
                "This build cannot export Sigma executions".into(),
            ))
        }
        #[cfg(feature = "sigma")]
        {
            use irmind_app::{AuditLog, v10_proofs::sigma_execution};
            let verifier = crate::LocalVerifier {
                trusted: BTreeMap::new(),
            }
            .with_trusted_key(&irmind_domain::Actor::Analyst, analyst_key)?;
            let signed = store
                .global_operations()?
                .into_iter()
                .map(|operation| (operation.hash, operation))
                .collect::<BTreeMap<_, _>>();
            let mut archive = Self::default();
            for entry in runs {
                let run = sigma_execution(entry)?;
                let operation = signed
                    .get(&run.pack_admission)
                    .ok_or(AppError::InvalidChain(entry.seq))?;
                let install =
                    if irmind_app::v10_proofs::requires_sigma_case_admission(&run.evaluator) {
                        use irmind_app::v10_proofs::SigmaCaseRunAdmissionV1;
                        let index = entries
                            .binary_search_by_key(&run.checkpoint.sequence, |entry| entry.seq)
                            .map_err(|_| AppError::InvalidChain(entry.seq))?;
                        let pack = irmind_app::v10_proofs::sigma_pack_operation(operation)?
                            .ok_or(AppError::InvalidChain(entry.seq))?;
                        let claim = SigmaCaseRunAdmissionV1::verify_following_run(
                            &entries[index],
                            &run,
                            pack.pack_manifest,
                        )?;
                        claim
                            .installation
                            .map(|digest| {
                                signed.get(&digest).ok_or(AppError::InvalidChain(entry.seq))
                            })
                            .transpose()?
                    } else {
                        None
                    };
                archive.add_run(store, case, &run, operation, install, &verifier, cancel)?;
            }
            Ok(archive)
        }
    }

    #[cfg(feature = "sigma")]
    fn insert(
        &mut self,
        descriptor: V10ProofDescriptor,
        read: impl FnOnce() -> Result<Vec<u8>, AppError>,
    ) -> Result<(), AppError> {
        if let std::collections::btree_map::Entry::Vacant(entry) = self.bodies.entry(descriptor) {
            self.total_bytes = self
                .total_bytes
                .checked_add(descriptor.size())
                .filter(|bytes| *bytes <= 128 * 1024 * 1024)
                .ok_or_else(|| AppError::Policy("Sigma proof section exceeds 128 MiB".into()))?;
            entry.insert(read()?);
        }
        Ok(())
    }

    #[cfg(feature = "sigma")]
    #[expect(
        clippy::too_many_arguments,
        reason = "the export uses the authenticated case and operation readers"
    )]
    fn add_run(
        &mut self,
        store: &LocalStore,
        case: &CaseId,
        run: &irmind_app::v10_proofs::SigmaRunV1,
        operation: &SignedOperation,
        install: Option<&SignedOperation>,
        verifier: &crate::LocalVerifier,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        use irmind_app::v10_proofs::v10_proof_commitment;
        use std::io::Read as _;
        let family = V10ProofFamily::Sigma;
        let invalid = || AppError::InvalidChain(run.checkpoint.sequence);
        if let Some(install) = install {
            self.add_case_package(store, case, operation, install, verifier, cancel)?;
        } else {
            self.add_pack(store, operation, verifier, cancel)?;
        }
        let fields = [
            (2, run.field_table),
            (3, run.selected_sources),
            (4, run.compiled_rules),
            (5, run.result_manifest),
        ];
        let mut descriptors = Vec::with_capacity(fields.len());
        for (kind, hash) in fields {
            let (descriptor, file) =
                store.open_addressed_v10_proof(case, family, kind, hash, cancel)?;
            self.insert(descriptor, || {
                let mut body = Vec::new();
                file.take(descriptor.size())
                    .read_to_end(&mut body)
                    .map_err(super::storage)?;
                Ok(body)
            })?;
            descriptors.push(descriptor);
        }
        if v10_proof_commitment(family, &descriptors).map_err(|_| invalid())? != run.proof_set {
            return Err(invalid());
        }
        Ok(())
    }

    #[cfg(feature = "sigma")]
    fn add_case_package(
        &mut self,
        store: &LocalStore,
        case: &CaseId,
        operation: &SignedOperation,
        installation: &SignedOperation,
        verifier: &crate::LocalVerifier,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        use irmind_app::v10_proofs::{
            SigmaPackManifestV1, SigmaPackageOriginV1, verify_sigma_installation_proof,
            verify_sigma_pack_operation,
        };
        let fail = || AppError::InvalidChain(0);
        let proof = serde_json::to_vec(installation).map_err(|_| fail())?;
        let installed = verify_sigma_installation_proof(&proof, installation.hash, verifier)?;
        let admission = verify_sigma_pack_operation(operation, verifier)?;
        if installed.manifest != admission.pack_manifest || installed.license != admission.license {
            return Err(fail());
        }
        let family = V10ProofFamily::Sigma;
        let manifest =
            store.read_addressed_v10_proof(case, family, 0, installed.manifest, cancel)?;
        let rules = SigmaPackManifestV1::decode(&manifest).map_err(|_| fail())?;
        let mut keys = vec![
            (0, installed.manifest),
            (6, irmind_app::sha256(&proof)),
            (8, installed.metadata),
        ];
        keys.extend(rules.0.iter().map(|entry| (1, entry.rule.sha256)));
        if let SigmaPackageOriginV1::CatalogAsset(hash)
        | SigmaPackageOriginV1::SigmaHqArchive(hash) = installed.origin
        {
            keys.push((7, hash));
        }
        for (kind, hash) in keys {
            use std::io::Read as _;
            let (descriptor, file) =
                store.open_addressed_v10_proof(case, family, kind, hash, cancel)?;
            self.insert(descriptor, || {
                let mut body = Vec::new();
                file.take(descriptor.size())
                    .read_to_end(&mut body)
                    .map_err(super::storage)?;
                Ok(body)
            })?;
        }
        self.operations.insert(operation.hash, operation.clone());
        Ok(())
    }

    #[cfg(feature = "sigma")]
    fn add_pack(
        &mut self,
        store: &LocalStore,
        operation: &SignedOperation,
        verifier: &crate::LocalVerifier,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        use irmind_app::v10_proofs::verify_sigma_pack_operation;
        if self.operations.contains_key(&operation.hash) {
            return Ok(());
        }
        let admission = verify_sigma_pack_operation(operation, verifier)?;
        let pack = store.read_signed_sigma_pack(&admission, cancel)?;
        let manifest = pack
            .manifest
            .encode()
            .map_err(|_| AppError::InvalidChain(0))?;
        for (kind, body) in
            std::iter::once((0, manifest)).chain(pack.rules.into_iter().map(|rule| (1, rule)))
        {
            let descriptor = V10ProofDescriptor::from_body(V10ProofFamily::Sigma, kind, &body)
                .map_err(|_| AppError::InvalidChain(0))?;
            self.insert(descriptor, || Ok(body))?;
        }
        self.operations.insert(operation.hash, operation.clone());
        Ok(())
    }

    pub(super) fn write(
        &self,
        out: &mut impl std::io::Write,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let descriptors = self.bodies.keys().copied().collect::<Vec<_>>();
        write_v10_object_section(
            out,
            V10ProofFamily::Sigma,
            &descriptors,
            |descriptor| {
                self.bodies
                    .get(&descriptor)
                    .map(Vec::as_slice)
                    .ok_or(AppError::InvalidChain(0))
            },
            cancel,
        )
    }
}

impl LocalStore {
    pub(crate) fn verify_local_sigma(
        &self,
        case: &CaseId,
        entries: &[SignedEntry],
        key: &[u8],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        use irmind_app::v10_proofs::V10ObjectSection;
        use std::{io::Seek as _, path::Path};
        let archive = SigmaArchive::collect(self, case, entries, key, cancel)?;
        let root = self.parquet.owned_case_path(case);
        let mut index = tempfile::tempfile_in(&self.lock_dir).map_err(super::storage)?;
        archive.write(&mut index, cancel)?;
        index.rewind().map_err(super::storage)?;
        let section = V10ObjectSection::scan(&mut index, V10ProofFamily::Sigma, cancel)?;
        super::extensions::verify_sigma(
            &mut index,
            &section,
            entries,
            &archive.operations,
            |artifact, rows, time, predicate| {
                let mut file = irmind_fs::open_regular_no_follow(&root, Path::new(artifact.path()))
                    .map_err(super::storage)?;
                super::parquet_frame::verify_v10_sigma_rows(
                    &mut file, 0, artifact, rows, time, predicate, cancel,
                )
            },
            cancel,
        )
    }
}

#[cfg(feature = "sigma")]
pub(crate) fn check_sigma_append(
    store: &LocalStore,
    case: &CaseId,
    run: &irmind_app::v10_proofs::SigmaRunV1,
    key: &[u8],
    objects: &[(V10ProofDescriptor, Vec<u8>)],
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    use irmind_app::AuditLog;
    let settle_cancel = CancellationToken::new();
    let cancel = if run.status == irmind_app::v10_proofs::SigmaRunStatusV1::Cancelled {
        &settle_cancel
    } else {
        cancel
    };
    let entries = store.entries(case)?;
    let mut archive = SigmaArchive::collect(store, case, &entries, key, cancel)?;
    let verifier = crate::LocalVerifier {
        trusted: BTreeMap::new(),
    }
    .with_trusted_key(&irmind_domain::Actor::Analyst, key)?;
    let operation = store
        .global_operations()?
        .into_iter()
        .find(|operation| operation.hash == run.pack_admission)
        .ok_or(AppError::InvalidChain(run.checkpoint.sequence))?;
    archive.add_pack(store, &operation, &verifier, cancel)?;
    for (descriptor, _) in objects {
        // The prepared material already owns the bodies; this pass only budgets.
        archive.insert(*descriptor, || Ok(Vec::new()))?;
    }
    Ok(())
}
