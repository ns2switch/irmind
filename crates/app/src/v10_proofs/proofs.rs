//! Shared V10 proof descriptors and exact custody coordinates.
use super::{Digest, INVALID, Result, Wire};
use sha2::{Digest as _, Sha256};

const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SECTION_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V10ProofFamily {
    Sigma,
    Report,
}

impl V10ProofFamily {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Sigma => b"irmind-sigma-proof-set-v1\0",
            Self::Report => b"irmind-report-proof-set-v1\0",
        }
    }

    fn body_limit(self, kind: u8) -> Result<u64> {
        match (self, kind) {
            (Self::Sigma, 1) => Ok(64 * 1024),
            (Self::Sigma, 6) => Ok(32 * 1024),
            (Self::Sigma, 7) => Ok(crate::catalog::MAX_CATALOG_INDEX_BYTES as u64 + 128),
            (Self::Sigma, 8) => Ok(8 * 1024),
            (Self::Sigma, 2) => Ok(512 * 1024),
            (Self::Sigma, 0 | 3..=5) | (Self::Report, 0..=3) => Ok(MAX_OBJECT_BYTES),
            _ => Err(INVALID),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct V10ProofDescriptor {
    kind: u8,
    hash: Digest,
    size: u64,
}

impl V10ProofDescriptor {
    pub const BYTE_LEN: usize = 41;

    pub fn new(family: V10ProofFamily, kind: u8, hash: Digest, size: u64) -> Result<Self> {
        if size == 0 || size > family.body_limit(kind)? {
            return Err(INVALID);
        }
        Ok(Self { kind, hash, size })
    }

    pub fn from_body(family: V10ProofFamily, kind: u8, body: &[u8]) -> Result<Self> {
        let size = u64::try_from(body.len()).map_err(|_| INVALID)?;
        if size == 0 || size > family.body_limit(kind)? {
            return Err(INVALID);
        }
        Ok(Self {
            kind,
            hash: Sha256::digest(body).into(),
            size,
        })
    }

    pub fn decode(family: V10ProofFamily, bytes: &[u8]) -> Result<Self> {
        let mut wire = Wire(bytes);
        let result = Self::new(family, wire.byte()?, wire.fixed()?, wire.u64()?)?;
        wire.finish()?;
        Ok(result)
    }

    pub fn encode(self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0; Self::BYTE_LEN];
        bytes[0] = self.kind;
        bytes[1..33].copy_from_slice(&self.hash);
        bytes[33..].copy_from_slice(&self.size.to_be_bytes());
        bytes
    }

    pub fn kind(self) -> u8 {
        self.kind
    }

    pub fn hash(self) -> Digest {
        self.hash
    }

    pub fn size(self) -> u64 {
        self.size
    }
}

pub fn v10_proof_commitment(
    family: V10ProofFamily,
    descriptors: &[V10ProofDescriptor],
) -> Result<Digest> {
    let mut digest = Sha256::new();
    digest.update(family.domain());
    digest.update(
        u64::try_from(descriptors.len())
            .map_err(|_| INVALID)?
            .to_be_bytes(),
    );
    let mut previous = None;
    let mut bytes = 0u64;
    for descriptor in descriptors {
        let key = (descriptor.kind, descriptor.hash);
        bytes = bytes.checked_add(descriptor.size).ok_or(INVALID)?;
        if previous.is_some_and(|previous| previous >= key)
            || bytes > MAX_SECTION_BYTES
            || descriptor.size > family.body_limit(descriptor.kind)?
        {
            return Err(INVALID);
        }
        digest.update(descriptor.encode());
        previous = Some(key);
    }
    Ok(digest.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct V10AuditReference {
    pub sequence: u64,
    pub entry_sha256: Digest,
}

impl V10AuditReference {
    pub(super) fn write(self, out: &mut Vec<u8>) -> Result<()> {
        if self.sequence == 0 {
            return Err(INVALID);
        }
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.entry_sha256);
        Ok(())
    }

    pub(super) fn read(wire: &mut Wire<'_>) -> Result<Self> {
        let sequence = wire.u64()?;
        if sequence == 0 {
            return Err(INVALID);
        }
        Ok(Self {
            sequence,
            entry_sha256: wire.fixed()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct V10SourceReference {
    pub manifest: V10AuditReference,
    pub evidence_sha256: Digest,
}

impl V10SourceReference {
    pub(super) fn write(self, out: &mut Vec<u8>) -> Result<()> {
        self.manifest.write(out)?;
        out.extend_from_slice(&self.evidence_sha256);
        Ok(())
    }

    pub(super) fn read(wire: &mut Wire<'_>) -> Result<Self> {
        Ok(Self {
            manifest: V10AuditReference::read(wire)?,
            evidence_sha256: wire.fixed()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct V10ArtifactReference {
    pub entry: V10AuditReference,
    pub artifact_sha256: Digest,
}

impl V10ArtifactReference {
    pub(super) fn write(self, out: &mut Vec<u8>) -> Result<()> {
        self.entry.write(out)?;
        out.extend_from_slice(&self.artifact_sha256);
        Ok(())
    }

    pub(super) fn read(wire: &mut Wire<'_>) -> Result<Self> {
        Ok(Self {
            entry: V10AuditReference::read(wire)?,
            artifact_sha256: wire.fixed()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct V10RowReference {
    pub source: V10SourceReference,
    pub record: u64,
    pub artifact: V10ArtifactReference,
    pub physical_row: u64,
}

impl V10RowReference {
    pub(super) fn write(self, out: &mut Vec<u8>) -> Result<()> {
        self.source.write(out)?;
        out.extend_from_slice(&self.record.to_be_bytes());
        self.artifact.write(out)?;
        out.extend_from_slice(&self.physical_row.to_be_bytes());
        Ok(())
    }

    pub(super) fn read(wire: &mut Wire<'_>) -> Result<Self> {
        Ok(Self {
            source: V10SourceReference::read(wire)?,
            record: wire.u64()?,
            artifact: V10ArtifactReference::read(wire)?,
            physical_row: wire.u64()?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_commitments_match_the_approved_receipt() {
        let body = b"synthetic-pack-manifest";
        let descriptors = [
            V10ProofDescriptor::from_body(V10ProofFamily::Sigma, 0, body).unwrap(),
            V10ProofDescriptor::from_body(V10ProofFamily::Sigma, 1, b"synthetic-rule-body")
                .unwrap(),
        ];
        let admission = super::super::SigmaPackAdmissionV1::decode(&super::super::tests::vector(
            "sigma_pack_admission_v1",
        ))
        .unwrap();
        assert_eq!(
            v10_proof_commitment(V10ProofFamily::Sigma, &descriptors).unwrap(),
            admission.proof_set
        );
        assert_eq!(
            V10ProofDescriptor::decode(V10ProofFamily::Sigma, &descriptors[0].encode()).unwrap(),
            descriptors[0]
        );
        assert!(
            v10_proof_commitment(V10ProofFamily::Sigma, &[descriptors[0], descriptors[0]]).is_err()
        );
        assert!(
            v10_proof_commitment(V10ProofFamily::Sigma, &[descriptors[1], descriptors[0]]).is_err()
        );
        assert_ne!(
            v10_proof_commitment(V10ProofFamily::Sigma, &descriptors[1..]).unwrap(),
            admission.proof_set
        );
        assert!(V10ProofDescriptor::new(V10ProofFamily::Sigma, 1, [0; 32], 64 * 1024 + 1).is_err());
        assert!(V10ProofDescriptor::new(V10ProofFamily::Report, 4, [0; 32], 1).is_err());
    }
}
