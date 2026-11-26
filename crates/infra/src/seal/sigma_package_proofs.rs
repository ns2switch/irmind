//! Authenticate the exact union of package installation, publisher and metadata proofs.
use irmind_app::{
    AppError, CancellationToken, SignedOperation,
    v10_proofs::{SigmaPackageInstallationV1, V10ObjectSection, verify_sigma_installation_proof},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek},
};

type Key = (u8, [u8; 32]);
pub(super) type Installations = BTreeMap<[u8; 32], (Key, SigmaPackageInstallationV1)>;

pub(super) fn collect(
    section: &V10ObjectSection,
    input: &mut (impl Read + Seek),
    operations: &BTreeMap<[u8; 32], SignedOperation>,
    cancel: &CancellationToken,
) -> Result<Installations, AppError> {
    let mut installations = BTreeMap::new();
    for descriptor in section.descriptors_of_kind(6) {
        let analyst = operations
            .values()
            .next()
            .ok_or(AppError::InvalidChain(0))?;
        let verifier = crate::LocalVerifier {
            trusted: BTreeMap::new(),
        }
        .with_trusted_key(&irmind_domain::Actor::Analyst, &analyst.public_key)?;
        let key = (6, descriptor.hash());
        let bytes = section.body(input, key, cancel)?;
        let entry: SignedOperation =
            serde_json::from_slice(&bytes).map_err(|_| AppError::InvalidChain(0))?;
        let receipt = verify_sigma_installation_proof(&bytes, entry.hash, &verifier)?;
        if installations.insert(entry.hash, (key, receipt)).is_some() {
            return Err(AppError::InvalidChain(entry.seq));
        }
    }
    Ok(installations)
}

pub(super) fn verify(
    section: &V10ObjectSection,
    input: &mut (impl Read + Seek),
    installed: &Installations,
    expected: [u8; 32],
    manifest: [u8; 32],
    referenced: &mut BTreeSet<Key>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    #[cfg(not(feature = "sigma"))]
    {
        let _ = (
            section, input, installed, expected, manifest, referenced, cancel,
        );
        Err(AppError::Policy(
            "This build cannot verify Sigma package proof objects".into(),
        ))
    }
    #[cfg(feature = "sigma")]
    {
        use crate::sigma_pack::SigmaPackageMetadata;
        use irmind_app::{
            catalog::{SigmaCatalogReleaseStamp, SigmaCatalogSource},
            v10_proofs::SigmaPackageOriginV1,
        };
        let invalid = || AppError::InvalidChain(0);
        let (key, receipt) = installed.get(&expected).ok_or_else(invalid)?;
        if receipt.manifest != manifest {
            return Err(invalid());
        }
        let meta = (8, receipt.metadata);
        let metadata = SigmaPackageMetadata::decode_proof(&section.body(input, meta, cancel)?)?;
        if metadata.name != receipt.name
            || metadata.version != receipt.version
            || metadata.license != receipt.license
        {
            return Err(invalid());
        }
        if let SigmaPackageOriginV1::CatalogAsset(digest)
        | SigmaPackageOriginV1::SigmaHqArchive(digest) = receipt.origin
        {
            let key = (7, digest);
            let proof = section.body(input, key, cancel)?;
            let stamp = SigmaCatalogReleaseStamp::from_signed_installation(&proof, digest)?;
            let index = crate::Ed25519CatalogIndexVerifier::production()?.verify_sigma_proof(
                &proof,
                digest,
                stamp.tag(),
            )?;
            let published = index
                .entries()
                .iter()
                .find(|entry| entry.name == receipt.name)
                .ok_or_else(invalid)?;
            if published.version != receipt.version
                || published.license != receipt.license
                || published.manifest_sha256.as_bytes() != &receipt.manifest
            {
                return Err(invalid());
            }
            match (&published.source, &receipt.origin) {
                (
                    SigmaCatalogSource::CatalogAsset { sha256, .. },
                    SigmaPackageOriginV1::CatalogAsset(_),
                ) if sha256.as_bytes() == &receipt.asset => (),
                (
                    SigmaCatalogSource::SigmahqArchive {
                        sha256,
                        attribution,
                        ..
                    },
                    SigmaPackageOriginV1::SigmaHqArchive(_),
                ) if sha256.as_bytes() == &receipt.asset
                    && attribution == &metadata.attribution => {}
                _ => return Err(invalid()),
            }
            referenced.insert(key);
        }
        referenced.insert(*key);
        referenced.insert(meta);
        Ok(())
    }
}

#[cfg(all(test, feature = "sigma"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::{
        Signer,
        v10_proofs::{V10ProofDescriptor, V10ProofFamily, write_v10_object_section},
    };
    use irmind_domain::Actor;
    use std::io::Cursor;

    #[test]
    fn v10_sigma_package_objects_bind_the_exact_installation_and_metadata() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/development/sigma-package-vectors/wire.json"
        ))
        .unwrap();
        let fixture = |key: &str| hex::decode(vectors[key]["bytes_hex"].as_str().unwrap()).unwrap();
        let payload = fixture("local_installation");
        let installation = SigmaPackageInstallationV1::decode(&payload).unwrap();
        let signer = crate::LocalSigner {
            key: ed25519_dalek::SigningKey::from_bytes(&[15; 32]),
            actor: Actor::Analyst,
        };
        let mut operation = SignedOperation {
            case_id: irmind_app::GLOBAL_OPERATION_SCOPE.into(),
            seq: 1,
            at: 100,
            actor: Actor::Analyst,
            operation: irmind_app::hex(&payload),
            prev: [0; 32],
            hash: [0; 32],
            sig: Vec::new(),
            public_key: signer.public_key(),
        };
        operation.hash = irmind_app::sha256(&operation.canonical());
        operation.sig = signer.sign(&operation.hash).unwrap();
        let bodies = [
            serde_json::to_vec(&operation).unwrap(),
            fixture("v10_object_8"),
        ];
        let family = V10ProofFamily::Sigma;
        let descriptors = [
            V10ProofDescriptor::from_body(family, 6, &bodies[0]).unwrap(),
            V10ProofDescriptor::from_body(family, 8, &bodies[1]).unwrap(),
        ];
        let mut wire = Vec::new();
        let cancel = CancellationToken::new();
        write_v10_object_section(
            &mut wire,
            family,
            &descriptors,
            |descriptor| Ok(bodies[usize::from(descriptor.kind() == 8)].as_slice()),
            &cancel,
        )
        .unwrap();
        let mut reader = Cursor::new(wire);
        let section = V10ObjectSection::scan(&mut reader, family, &cancel).unwrap();
        let operations = BTreeMap::from([(operation.hash, operation.clone())]);
        let installed = collect(&section, &mut reader, &operations, &cancel).unwrap();
        let mut referenced = BTreeSet::new();
        verify(
            &section,
            &mut reader,
            &installed,
            operation.hash,
            installation.manifest,
            &mut referenced,
            &cancel,
        )
        .unwrap();
        section.check_union(&referenced).unwrap();
        assert!(
            verify(
                &section,
                &mut reader,
                &installed,
                operation.hash,
                [0; 32],
                &mut referenced,
                &cancel
            )
            .is_err()
        );
        assert!(
            verify(
                &section,
                &mut reader,
                &installed,
                [0; 32],
                installation.manifest,
                &mut referenced,
                &cancel
            )
            .is_err()
        );
    }
}
