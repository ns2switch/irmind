use crate::{CaseId, DomainError};

/// Data that originated outside the trusted case and policy boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct Tainted<T> {
    pub(crate) value: T,
    provenance: Provenance,
}

impl<T> std::fmt::Debug for Tainted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tainted")
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    File,
    ToolResult,
    Graph,
    ModelProposal,
    AnalystInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    evidence_hash: [u8; 32],
    record_index: Option<u64>,
    source_kind: SourceKind,
    parser_location: Option<ParserLocation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParserLocation {
    source: String,
    parser_id: String,
    byte_offset: u64,
}

impl ParserLocation {
    pub fn new(source: &str, parser_id: &str, byte_offset: u64) -> Result<Self, DomainError> {
        if !crate::custody_manifest::valid_source(source)
            || parser_id.is_empty()
            || parser_id.len() > 64
            || !parser_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(DomainError::InvalidManifest);
        }
        Ok(Self {
            source: source.into(),
            parser_id: parser_id.into(),
            byte_offset,
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn parser_id(&self) -> &str {
        &self.parser_id
    }

    pub fn byte_offset(&self) -> u64 {
        self.byte_offset
    }
}

impl Provenance {
    pub fn new(
        evidence_hash: [u8; 32],
        record_index: Option<u64>,
        source_kind: SourceKind,
    ) -> Self {
        Self {
            evidence_hash,
            record_index,
            source_kind,
            parser_location: None,
        }
    }

    #[must_use]
    pub fn with_parser_location(mut self, location: ParserLocation) -> Self {
        self.parser_location = Some(location);
        self
    }

    pub fn parser_location(&self) -> Option<&ParserLocation> {
        self.parser_location.as_ref()
    }

    pub fn evidence_hash(&self) -> &[u8; 32] {
        &self.evidence_hash
    }
    pub fn record_index(&self) -> Option<u64> {
        self.record_index
    }
    pub fn source_kind(&self) -> SourceKind {
        self.source_kind
    }

    pub fn approval_challenge(&self, case_id: &CaseId) -> Vec<u8> {
        if let Some(location) = &self.parser_location {
            let mut out = b"irmind-declassify-v2\0".to_vec();
            crate::canonical::put(&mut out, case_id.as_str().as_bytes());
            out.extend_from_slice(&self.evidence_hash);
            out.extend_from_slice(&self.record_index.unwrap_or(u64::MAX).to_be_bytes());
            out.push(self.source_kind as u8);
            crate::canonical::put(&mut out, location.source.as_bytes());
            crate::canonical::put(&mut out, location.parser_id.as_bytes());
            out.extend_from_slice(&location.byte_offset.to_be_bytes());
            return out;
        }
        let mut out = b"irmind-declassify-v1\0".to_vec();
        out.extend_from_slice(case_id.as_str().as_bytes());
        out.push(0);
        out.extend_from_slice(&self.evidence_hash);
        out.extend_from_slice(&self.record_index.unwrap_or(u64::MAX).to_be_bytes());
        out.push(self.source_kind as u8);
        out
    }
}

pub trait DeclassificationAuthority {
    fn verify_and_audit(&self, challenge: &[u8], signature: &[u8], provenance: &Provenance)
    -> bool;
}

impl<T> Tainted<T> {
    pub fn from_external(value: T, provenance: Provenance) -> Self {
        Self { value, provenance }
    }

    #[must_use]
    pub fn with_parser_location(mut self, location: ParserLocation) -> Self {
        self.provenance = self.provenance.with_parser_location(location);
        self
    }

    /// Permits local processing without returning an untainted value.
    pub fn inspect(&self, visitor: impl FnOnce(&T)) {
        visitor(&self.value);
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    pub fn release_with_approval(
        self,
        case_id: &CaseId,
        signature: &[u8],
        authority: &dyn DeclassificationAuthority,
    ) -> Result<T, DomainError> {
        let challenge = self.provenance.approval_challenge(case_id);
        if !authority.verify_and_audit(&challenge, signature, &self.provenance) {
            return Err(DomainError::InvalidApproval);
        }
        Ok(self.value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{ParserLocation, Provenance, SourceKind};
    use crate::CaseId;

    #[test]
    fn parser_location_is_bound_to_a_separate_approval_domain() {
        let case = CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap();
        let old = Provenance::new([4; 32], Some(7), SourceKind::File);
        let located = old.clone().with_parser_location(
            ParserLocation::new("logs/auth.log", "parser-linux", 123).unwrap(),
        );
        let other_offset = old.with_parser_location(
            ParserLocation::new("logs/auth.log", "parser-linux", 124).unwrap(),
        );
        assert!(
            located
                .approval_challenge(&case)
                .starts_with(b"irmind-declassify-v2\0")
        );
        assert_ne!(
            located.approval_challenge(&case),
            other_offset.approval_challenge(&case)
        );
        assert_ne!(
            located.approval_challenge(&case),
            Provenance::new([4; 32], Some(7), SourceKind::File).approval_challenge(&case)
        );
    }
}
