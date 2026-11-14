//! Reproduce a signed decoded input set without executing a mapping or spooling.
use super::{AppError, OffsetState, SourceMetadata, SourceRecordV1, invalid, validation};
use irmind_domain::{EvidenceHash, SourceFormatIdentityV1, SourceRecordSetV1, Tainted};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub struct SourceRecordReplay<'a> {
    expected: &'a SourceRecordSetV1,
    metadata: SourceMetadata<'a>,
    size: u64,
    requested: u64,
    count: u64,
    failed: bool,
    previous: Option<u64>,
    offset: OffsetState,
    formats: BTreeSet<SourceFormatIdentityV1>,
    digest: Sha256,
    selected: Option<Tainted<SourceRecordV1>>,
}

impl<'a> SourceRecordReplay<'a> {
    pub fn new(
        expected: &'a SourceRecordSetV1,
        metadata: SourceMetadata<'a>,
        size: u64,
        requested: u64,
    ) -> Result<Self, AppError> {
        if requested >= 100_000
            || expected.source() != &EvidenceHash::from_bytes(metadata.evidence_hash)
            || expected.reference() != metadata.source
            || expected.cluster_context() != metadata.cluster_context
            || expected.time_context()
                != super::super::time::domain_time_context(metadata.time_context)?
        {
            return Err(invalid());
        }
        let mut digest = Sha256::new();
        digest.update(b"irmind-source-records-commitment-v1\0");
        digest.update(expected.records().to_be_bytes());
        Ok(Self {
            expected,
            metadata,
            size,
            requested,
            count: 0,
            failed: false,
            previous: None,
            offset: OffsetState::Initial,
            formats: BTreeSet::new(),
            digest,
            selected: None,
        })
    }

    pub fn accept(&mut self, record: &Tainted<SourceRecordV1>) -> Result<(), AppError> {
        if self.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if self.failed {
            return Err(invalid());
        }
        let mut checked = Err(invalid());
        record.inspect(|source| checked = self.accept_one(source, record));
        self.failed = checked.is_err();
        checked
    }

    fn accept_one(
        &mut self,
        source: &SourceRecordV1,
        tainted: &Tainted<SourceRecordV1>,
    ) -> Result<(), AppError> {
        validation::validate_binding(
            &validation::Binding {
                metadata: self.metadata,
                identity: self.expected.decoder(),
                hash: self.expected.source(),
                size: self.size,
            },
            source,
            tainted.provenance(),
        )?;
        if self.count >= self.expected.records()
            || self.previous.is_some_and(|n| source.origin().record() <= n)
        {
            return Err(invalid());
        }
        let next = source.origin().offset();
        match (self.offset, next) {
            (OffsetState::Known(old), Some(new)) if new < old => return Err(invalid()),
            (OffsetState::Known(_), None) | (OffsetState::Unavailable, Some(_)) => {
                return Err(invalid());
            }
            _ => {}
        }
        let format =
            SourceFormatIdentityV1::try_new(source.format().id(), source.format().version())
                .map_err(|_| invalid())?;
        if !self.expected.formats().contains(&format) {
            return Err(invalid());
        }
        self.formats.insert(format);
        feed_tuple(&mut self.digest, self.expected.source(), source);
        if source.origin().record() == self.requested {
            self.selected = Some(tainted.clone());
        }
        self.count += 1;
        self.previous = Some(source.origin().record());
        self.offset = next.map_or(OffsetState::Unavailable, OffsetState::Known);
        Ok(())
    }

    pub fn finish(self, report: &crate::ParseReport) -> Result<Tainted<SourceRecordV1>, AppError> {
        if self.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if self.failed
            || self.count != self.expected.records()
            || self.count != report.accepted as u64
            || report.rejected != self.expected.rejected()
            || self.formats.iter().ne(self.expected.formats().iter())
            || EvidenceHash::from_bytes(self.digest.finalize().into())
                != *self.expected.records_commitment()
        {
            return Err(invalid());
        }
        self.selected.ok_or_else(invalid)
    }
}

fn feed_tuple(digest: &mut Sha256, hash: &EvidenceHash, source: &SourceRecordV1) {
    let raw = super::commitment::spool_tuple(source);
    let header_len = raw.len() - 32;
    let mut tuple = Vec::with_capacity(129);
    tuple.extend_from_slice(&(hash.as_str().len() as u64).to_be_bytes());
    tuple.extend_from_slice(hash.as_str().as_bytes());
    tuple.extend_from_slice(&raw[..header_len]);
    tuple.extend_from_slice(&32u64.to_be_bytes());
    tuple.extend_from_slice(&raw[header_len..]);
    digest.update((tuple.len() as u64).to_be_bytes());
    digest.update(tuple);
}
