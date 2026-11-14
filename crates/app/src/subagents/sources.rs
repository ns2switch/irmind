use super::{SubagentDigest, SubagentRecord, SubagentRecordError, codec};
use crate::AuditEventKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentSourcePageV1 {
    format_version: u8,
    case_id: String,
    ordinal: u64,
    sources: Vec<SubagentDigest>,
}
impl SubagentSourcePageV1 {
    pub fn new(
        case: &crate::CaseId,
        ordinal: u64,
        sources: Vec<SubagentDigest>,
    ) -> Result<Self, SubagentRecordError> {
        let value = Self {
            format_version: 1,
            case_id: case.as_str().into(),
            ordinal,
            sources,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn case_id(&self) -> &str {
        &self.case_id
    }
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub fn sources(&self) -> &[SubagentDigest] {
        &self.sources
    }
}
impl SubagentRecord for SubagentSourcePageV1 {
    const KIND: AuditEventKind = AuditEventKind::SubagentSourcePageV1;
    const DOMAIN: &'static [u8] = b"irmind-subagent-source-page-v1\0";
    fn validate(&self) -> Result<(), SubagentRecordError> {
        codec::uuid(&self.case_id)?;
        if self.format_version != 1 || self.ordinal >= 64 || self.sources.is_empty() {
            return Err(SubagentRecordError);
        }
        codec::sorted(&self.sources, 256)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentSourceSetV1 {
    format_version: u8,
    case_id: String,
    count: u64,
    pages: Vec<SubagentDigest>,
}
impl SubagentSourceSetV1 {
    pub fn new(
        case: &crate::CaseId,
        count: u64,
        pages: Vec<SubagentDigest>,
    ) -> Result<Self, SubagentRecordError> {
        let value = Self {
            format_version: 1,
            case_id: case.as_str().into(),
            count,
            pages,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn case_id(&self) -> &str {
        &self.case_id
    }
    pub const fn count(&self) -> u64 {
        self.count
    }
    pub fn pages(&self) -> &[SubagentDigest] {
        &self.pages
    }
    pub fn verify_pages(&self, pages: &[SubagentSourcePageV1]) -> Result<(), SubagentRecordError> {
        self.validate()?;
        if pages.len() != self.pages.len() {
            return Err(SubagentRecordError);
        }
        let mut sources = std::collections::BTreeSet::new();
        let mut previous = None;
        for (ordinal, (page, identity)) in pages.iter().zip(&self.pages).enumerate() {
            if page.case_id != self.case_id
                || page.ordinal != ordinal as u64
                || page.identity()? != *identity
            {
                return Err(SubagentRecordError);
            }
            for hash in &page.sources {
                if previous.is_some_and(|prior| prior >= *hash) || !sources.insert(*hash) {
                    return Err(SubagentRecordError);
                }
                previous = Some(*hash);
            }
        }
        if sources.len() as u64 != self.count {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}
impl SubagentRecord for SubagentSourceSetV1 {
    const KIND: AuditEventKind = AuditEventKind::SubagentSourceSetV1;
    const DOMAIN: &'static [u8] = b"irmind-subagent-source-set-v1\0";
    fn validate(&self) -> Result<(), SubagentRecordError> {
        codec::uuid(&self.case_id)?;
        if self.format_version != 1
            || self.pages.len() > 64
            || self.count > 16_384
            || (self.count == 0) != self.pages.is_empty()
            || self.count < self.pages.len() as u64
            || self.count > self.pages.len() as u64 * 256
            || self
                .pages
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.pages.len()
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}
