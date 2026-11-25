//! Canonical report proof objects. The ledger resolves each coordinate at the checkpoint.
use super::{
    INVALID, Result, V10ArtifactReference, V10AuditReference, V10RowReference, V10SourceReference,
    Wire, canonical_uuid, put_text_with_empty,
};
use std::collections::BTreeSet;

const CITATIONS: &[u8] = b"irmind-report-citations-v1\0";
const SECTIONS: &[u8] = b"irmind-report-analyst-sections-v1\0";
const COVERAGE: &[u8] = b"irmind-report-coverage-v2\0";
const MAX_LIST_ITEMS: usize = 1_000_000;
const MAX_SECTION_TEXT: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum V10Citation {
    Row(V10RowReference),
    Artifact {
        source: V10SourceReference,
        artifact: V10ArtifactReference,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V10FindingCitations {
    pub finding_id: String,
    pub confirmation: V10AuditReference,
    pub citations: Vec<V10Citation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportCitationsV1(pub Vec<V10FindingCitations>);

impl ReportCitationsV1 {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire::object(body, CITATIONS)?;
        let findings = wire.list(4 + 36 + 40 + 8 + 1 + 144, |wire| {
            let finding_id = wire.text(36)?;
            let confirmation = V10AuditReference::read(wire)?;
            let citations = wire.list(1 + 144, |wire| match wire.byte()? {
                0 => V10RowReference::read(wire).map(V10Citation::Row),
                1 => Ok(V10Citation::Artifact {
                    source: V10SourceReference::read(wire)?,
                    artifact: V10ArtifactReference::read(wire)?,
                }),
                _ => Err(INVALID),
            })?;
            Ok(V10FindingCitations {
                finding_id,
                confirmation,
                citations,
            })
        })?;
        wire.finish()?;
        let result = Self(findings);
        result.validate()?;
        Ok(result)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = CITATIONS.to_vec();
        put_count(&mut out, self.0.len())?;
        for finding in &self.0 {
            put_text_with_empty(&mut out, &finding.finding_id, 36)?;
            finding.confirmation.write(&mut out)?;
            put_count(&mut out, finding.citations.len())?;
            for citation in &finding.citations {
                match citation {
                    V10Citation::Row(row) => {
                        out.push(0);
                        row.write(&mut out)?;
                    }
                    V10Citation::Artifact { source, artifact } => {
                        out.push(1);
                        source.write(&mut out)?;
                        artifact.write(&mut out)?;
                    }
                }
                check_size(out.len())?;
            }
        }
        Ok(out)
    }

    fn validate(&self) -> Result<()> {
        let mut ids = BTreeSet::new();
        for finding in &self.0 {
            if !canonical_uuid(&finding.finding_id)
                || !ids.insert(&finding.finding_id)
                || finding.citations.is_empty()
                || finding.citations.iter().collect::<BTreeSet<_>>().len()
                    != finding.citations.len()
            {
                return Err(INVALID);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReportAnalystSectionsV1(pub [String; 4]);

impl ReportAnalystSectionsV1 {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire::object(body, SECTIONS)?;
        let sections = [
            wire.text_or_empty(MAX_SECTION_TEXT)?,
            wire.text_or_empty(MAX_SECTION_TEXT)?,
            wire.text_or_empty(MAX_SECTION_TEXT)?,
            wire.text_or_empty(MAX_SECTION_TEXT)?,
        ];
        wire.finish()?;
        Ok(Self(sections))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = SECTIONS.to_vec();
        for section in &self.0 {
            put_text_with_empty(&mut out, section, MAX_SECTION_TEXT)?;
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum V10SourceAvailability {
    Unavailable = 0,
    Unknown = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V10DelegatedSkillGap {
    pub checkpoint: V10AuditReference,
    pub task_id: [u8; 32],
    pub load_sequence: u64,
    pub load_sha256: [u8; 32],
    pub gap_index: u64,
}

impl V10DelegatedSkillGap {
    fn key(&self) -> (u64, [u8; 32], u64, u64) {
        (
            self.checkpoint.sequence,
            self.task_id,
            self.load_sequence,
            self.gap_index,
        )
    }

    fn read(wire: &mut Wire<'_>) -> Result<Self> {
        Ok(Self {
            checkpoint: V10AuditReference::read(wire)?,
            task_id: wire.fixed()?,
            load_sequence: wire.u64()?,
            load_sha256: wire.fixed()?,
            gap_index: wire.u64()?,
        })
    }

    fn write(self, out: &mut Vec<u8>) -> Result<()> {
        self.checkpoint.write(out)?;
        out.extend_from_slice(&self.task_id);
        out.extend_from_slice(&self.load_sequence.to_be_bytes());
        out.extend_from_slice(&self.load_sha256);
        out.extend_from_slice(&self.gap_index.to_be_bytes());
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReportCoverageV2 {
    pub unavailable_sources: Vec<(V10SourceReference, V10SourceAvailability)>,
    pub skill_gaps: Vec<(V10AuditReference, u64)>,
    pub query_limits: Vec<V10AuditReference>,
    pub partial_sigma_runs: Vec<V10AuditReference>,
    pub delegated_skill_gaps: Vec<V10DelegatedSkillGap>,
}

impl ReportCoverageV2 {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire::object(body, COVERAGE)?;
        let result = Self {
            unavailable_sources: wire.list(73, |wire| {
                let source = V10SourceReference::read(wire)?;
                let reason = match wire.byte()? {
                    0 => V10SourceAvailability::Unavailable,
                    1 => V10SourceAvailability::Unknown,
                    _ => return Err(INVALID),
                };
                Ok((source, reason))
            })?,
            skill_gaps: wire.list(48, |wire| Ok((V10AuditReference::read(wire)?, wire.u64()?)))?,
            query_limits: wire.list(40, V10AuditReference::read)?,
            partial_sigma_runs: wire.list(40, V10AuditReference::read)?,
            delegated_skill_gaps: wire.list(120, V10DelegatedSkillGap::read)?,
        };
        wire.finish()?;
        result.validate()?;
        Ok(result)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = COVERAGE.to_vec();
        put_count(&mut out, self.unavailable_sources.len())?;
        for (source, availability) in &self.unavailable_sources {
            source.write(&mut out)?;
            out.push(*availability as u8);
            check_size(out.len())?;
        }
        put_count(&mut out, self.skill_gaps.len())?;
        for (skill_load, index) in &self.skill_gaps {
            skill_load.write(&mut out)?;
            out.extend_from_slice(&index.to_be_bytes());
            check_size(out.len())?;
        }
        for receipts in [&self.query_limits, &self.partial_sigma_runs] {
            put_count(&mut out, receipts.len())?;
            for receipt in receipts {
                receipt.write(&mut out)?;
                check_size(out.len())?;
            }
        }
        put_count(&mut out, self.delegated_skill_gaps.len())?;
        for gap in &self.delegated_skill_gaps {
            gap.write(&mut out)?;
            check_size(out.len())?;
        }
        check_size(out.len())?;
        Ok(out)
    }

    fn validate(&self) -> Result<()> {
        increasing(&self.unavailable_sources, |(source, _)| {
            source.manifest.sequence
        })?;
        increasing(&self.skill_gaps, |(load, slot)| (load.sequence, *slot))?;
        increasing(&self.query_limits, |receipt| receipt.sequence)?;
        increasing(&self.partial_sigma_runs, |receipt| receipt.sequence)?;
        if self
            .delegated_skill_gaps
            .iter()
            .any(|gap| !(1..=4096).contains(&gap.load_sequence))
        {
            return Err(INVALID);
        }
        increasing(&self.delegated_skill_gaps, V10DelegatedSkillGap::key)
    }
}

pub(super) fn increasing<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> Result<()> {
    if items.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(INVALID);
    }
    Ok(())
}

pub(super) fn put_count(out: &mut Vec<u8>, count: usize) -> Result<()> {
    if count > MAX_LIST_ITEMS {
        return Err(INVALID);
    }
    out.extend_from_slice(&u64::try_from(count).map_err(|_| INVALID)?.to_be_bytes());
    Ok(())
}

pub(super) fn check_size(size: usize) -> Result<()> {
    if size > 64 * 1024 * 1024 {
        return Err(INVALID);
    }
    Ok(())
}

impl<'a> Wire<'a> {
    pub(super) fn object(body: &'a [u8], tag: &[u8]) -> Result<Self> {
        check_size(body.len())?;
        Ok(Wire(body.strip_prefix(tag).ok_or(INVALID)?))
    }

    pub(super) fn list<T>(
        &mut self,
        min_item_bytes: usize,
        read: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<Vec<T>> {
        self.bounded_list(MAX_LIST_ITEMS, min_item_bytes, read)
    }

    pub(super) fn bounded_list<T>(
        &mut self,
        item_limit: usize,
        min_item_bytes: usize,
        mut read: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<Vec<T>> {
        let count = usize::try_from(self.u64()?).map_err(|_| INVALID)?;
        if count > item_limit || count > self.0.len() / min_item_bytes {
            return Err(INVALID);
        }
        // Each successfully decoded element accounts for actual body bytes.
        let mut items = Vec::new();
        for _ in 0..count {
            items.push(read(self)?);
        }
        Ok(items)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(super) mod tests {
    use super::*;

    pub(in crate::v10_proofs) fn object(name: &str) -> Vec<u8> {
        let all: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testkit/fixtures/contracts/sigma_report_objects.json"
        ))
        .unwrap();
        hex::decode(all[name]["bytes_hex"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn approved_report_proof_bodies_round_trip() {
        let cites = object("report_citations");
        let decoded = ReportCitationsV1::decode(&cites).unwrap();
        assert_eq!(decoded.encode().unwrap(), cites);
        assert!(matches!(
            decoded.0[0].citations[0],
            V10Citation::Row(V10RowReference {
                physical_row: 5,
                ..
            })
        ));
        assert!(ReportCitationsV1::decode(&object("reject_uncited_finding")).is_err());

        let sections = object("report_analyst_sections");
        let decoded = ReportAnalystSectionsV1::decode(&sections).unwrap();
        assert_eq!(decoded.0[1], "");
        assert_eq!(decoded.encode().unwrap(), sections);

        assert!(ReportCoverageV2::decode(&object("report_coverage")).is_err());
    }

    pub(in crate::v10_proofs) fn coverage_vector(name: &str) -> Vec<u8> {
        let all: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testkit/fixtures/contracts/report_coverage_v2.json"
        ))
        .unwrap();
        let bytes = hex::decode(all[name]["bytes_hex"].as_str().unwrap()).unwrap();
        assert_eq!(crate::hex(&crate::sha256(&bytes)), all[name]["sha256"]);
        bytes
    }

    #[test]
    fn approved_coverage_v2_vectors_round_trip_and_reject_invalid_coordinates() {
        for name in [
            "report_coverage_v2_empty_delegated",
            "report_coverage_v2_two_tasks_same_local_sequence",
        ] {
            let bytes = coverage_vector(name);
            assert_eq!(
                ReportCoverageV2::decode(&bytes).unwrap().encode().unwrap(),
                bytes
            );
        }
        for name in ["reject_duplicate_branch_gap", "reject_zero_branch_sequence"] {
            assert!(ReportCoverageV2::decode(&coverage_vector(name)).is_err());
        }
    }
}
