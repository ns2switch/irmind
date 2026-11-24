//! Canonical receipt bodies introduced by case marker 6.
use irmind_domain::{CaseId, DomainError};

mod bindings;
pub use bindings::*;
mod checkpoint;
pub use checkpoint::*;
mod proofs;
pub use proofs::*;
mod report_objects;
mod report_skills;
pub use report_objects::*;
pub use report_skills::*;
mod section;
pub use section::{V10ObjectSection, write_v10_object_section};
mod sigma_admission;
pub use sigma_admission::*;
mod sigma_execution;
pub use sigma_execution::*;
mod sigma_objects;
pub use sigma_objects::*;

const ADMISSION: &[u8] = b"irmind-sigma-pack-admission-v1\0";
const RUN: &[u8] = b"irmind-sigma-run-v1\0";
const REPORT: &[u8] = b"irmind-report-published-v1\0";
const MAX_LABEL: usize = 256;
const MAX_IDENTIFIER: usize = 128;
const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;
const INVALID: DomainError = DomainError::InvalidManifest;

type Digest = [u8; 32];
type Result<T> = std::result::Result<T, DomainError>;

// Every receipt has only bounded text slots and fixed-width numeric fields.
fn encode_payload(bytes: &[u8]) -> Result<String> {
    if bytes.len() > 1024 {
        return Err(INVALID);
    }
    Ok(crate::hex(bytes))
}

fn decode_payload(value: &str, tag: &[u8]) -> Result<Vec<u8>> {
    if value.len() > 2048
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(INVALID);
    }
    let bytes = hex::decode(value).map_err(|_| INVALID)?;
    if !bytes.starts_with(tag) {
        return Err(INVALID);
    }
    Ok(bytes)
}

#[derive(Clone, Eq, PartialEq)]
pub enum SigmaPackOriginV1 {
    LocalDirectory,
    PinnedReleaseArchive(Digest),
}

#[derive(Clone, Eq, PartialEq)]
pub struct SigmaPackAdmissionV1 {
    pub pack_manifest: Digest,
    pub proof_set: Digest,
    pub origin: SigmaPackOriginV1,
    pub origin_label: String,
    pub license: String,
}

impl SigmaPackAdmissionV1 {
    pub fn encode(&self) -> Result<String> {
        let mut out = ADMISSION.to_vec();
        out.extend_from_slice(&self.pack_manifest);
        out.extend_from_slice(&self.proof_set);
        let (origin, archive) = match self.origin {
            SigmaPackOriginV1::LocalDirectory => (0, None),
            SigmaPackOriginV1::PinnedReleaseArchive(hash) => (1, Some(hash)),
        };
        out.push(origin);
        put_text(&mut out, &self.origin_label, MAX_LABEL)?;
        put_optional_hash(&mut out, archive);
        put_text(&mut out, &self.license, MAX_IDENTIFIER)?;
        encode_payload(&out)
    }

    pub fn decode(payload: &str) -> Result<Self> {
        let bytes = decode_payload(payload, ADMISSION)?;
        let mut input = Wire(&bytes[ADMISSION.len()..]);
        let pack_manifest = input.fixed()?;
        let proof_set = input.fixed()?;
        let origin = input.byte()?;
        let origin_label = input.text(MAX_LABEL)?;
        let origin = match (origin, input.optional_hash()?) {
            (0, None) => SigmaPackOriginV1::LocalDirectory,
            (1, Some(hash)) => SigmaPackOriginV1::PinnedReleaseArchive(hash),
            _ => return Err(INVALID),
        };
        let license = input.text(MAX_IDENTIFIER)?;
        input.finish()?;
        Ok(Self {
            pack_manifest,
            proof_set,
            origin,
            origin_label,
            license,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CaseCheckpointV1 {
    pub case_id: CaseId,
    pub sequence: u64,
    pub entry_hash: Digest,
}

impl CaseCheckpointV1 {
    fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        let case_id = self.case_id.as_str();
        if self.sequence == 0 || !canonical_uuid(case_id) {
            return Err(INVALID);
        }
        put_text(out, case_id, 36)?;
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.entry_hash);
        Ok(())
    }

    fn read(input: &mut Wire<'_>) -> Result<Self> {
        let case_id = input.text(36)?;
        let sequence = input.u64()?;
        if sequence == 0 || !canonical_uuid(&case_id) {
            return Err(INVALID);
        }
        Ok(Self {
            case_id: CaseId::parse(&case_id)?,
            sequence,
            entry_hash: input.fixed()?,
        })
    }
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum SigmaRunStatusV1 {
    Complete = 0,
    TimeLimit = 1,
    WorkLimit = 2,
    OversizedInput = 3,
    Cancelled = 4,
}

impl SigmaRunStatusV1 {
    fn read(input: &mut Wire<'_>) -> Result<Self> {
        match input.byte()? {
            0 => Ok(Self::Complete),
            1 => Ok(Self::TimeLimit),
            2 => Ok(Self::WorkLimit),
            3 => Ok(Self::OversizedInput),
            4 => Ok(Self::Cancelled),
            _ => Err(INVALID),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SigmaRunV1 {
    pub checkpoint: CaseCheckpointV1,
    pub pack_admission: Digest,
    pub artifact_inventory: Digest,
    pub selected_sources: Digest,
    pub start_utc_micros: i64,
    pub end_utc_micros: i64,
    pub compiled_rules: Digest,
    pub field_table: Digest,
    pub evaluator: String,
    pub reserved_units: u64,
    pub used_units: u64,
    pub status: SigmaRunStatusV1,
    pub matched_rows: u64,
    pub result_manifest: Digest,
    pub proof_set: Digest,
}

impl SigmaRunV1 {
    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        let mut out = RUN.to_vec();
        self.checkpoint.write(&mut out)?;
        for hash in [
            self.pack_admission,
            self.artifact_inventory,
            self.selected_sources,
        ] {
            out.extend_from_slice(&hash);
        }
        out.extend_from_slice(&self.start_utc_micros.to_be_bytes());
        out.extend_from_slice(&self.end_utc_micros.to_be_bytes());
        out.extend_from_slice(&self.compiled_rules);
        out.extend_from_slice(&self.field_table);
        put_text(&mut out, &self.evaluator, MAX_IDENTIFIER)?;
        out.extend_from_slice(&self.reserved_units.to_be_bytes());
        out.extend_from_slice(&self.used_units.to_be_bytes());
        out.push(self.status as u8);
        out.extend_from_slice(&self.matched_rows.to_be_bytes());
        out.extend_from_slice(&self.result_manifest);
        out.extend_from_slice(&self.proof_set);
        encode_payload(&out)
    }

    pub fn decode(payload: &str) -> Result<Self> {
        let bytes = decode_payload(payload, RUN)?;
        let mut input = Wire(&bytes[RUN.len()..]);
        let record = Self {
            checkpoint: CaseCheckpointV1::read(&mut input)?,
            pack_admission: input.fixed()?,
            artifact_inventory: input.fixed()?,
            selected_sources: input.fixed()?,
            start_utc_micros: i64::from_be_bytes(input.fixed()?),
            end_utc_micros: i64::from_be_bytes(input.fixed()?),
            compiled_rules: input.fixed()?,
            field_table: input.fixed()?,
            evaluator: input.text(MAX_IDENTIFIER)?,
            reserved_units: input.u64()?,
            used_units: input.u64()?,
            status: SigmaRunStatusV1::read(&mut input)?,
            matched_rows: input.u64()?,
            result_manifest: input.fixed()?,
            proof_set: input.fixed()?,
        };
        input.finish()?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        if self.start_utc_micros >= self.end_utc_micros || self.used_units > self.reserved_units {
            return Err(INVALID);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum ReportLanguageV1 {
    English = 0,
    Spanish = 1,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum ReportMediaV1 {
    Markdown = 0,
    Pdf = 1,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReportPublishedV1 {
    pub checkpoint: CaseCheckpointV1,
    pub citations: Digest,
    pub reviewed_model_draft: Option<Digest>,
    pub analyst_sections: Option<Digest>,
    pub coverage: Digest,
    pub language: ReportLanguageV1,
    pub renderer: String,
    pub media: ReportMediaV1,
    pub rendered_length: u64,
    pub rendered_sha256: Digest,
    pub proof_set: Digest,
}

impl ReportPublishedV1 {
    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        let mut out = REPORT.to_vec();
        self.checkpoint.write(&mut out)?;
        out.extend_from_slice(&self.citations);
        put_optional_hash(&mut out, self.reviewed_model_draft);
        put_optional_hash(&mut out, self.analyst_sections);
        out.extend_from_slice(&self.coverage);
        out.push(self.language as u8);
        put_text(&mut out, &self.renderer, MAX_IDENTIFIER)?;
        out.push(self.media as u8);
        out.extend_from_slice(&self.rendered_length.to_be_bytes());
        out.extend_from_slice(&self.rendered_sha256);
        out.extend_from_slice(&self.proof_set);
        encode_payload(&out)
    }

    pub fn decode(payload: &str) -> Result<Self> {
        let bytes = decode_payload(payload, REPORT)?;
        let mut input = Wire(&bytes[REPORT.len()..]);
        let checkpoint = CaseCheckpointV1::read(&mut input)?;
        let citations = input.fixed()?;
        let reviewed_model_draft = input.optional_hash()?;
        let analyst_sections = input.optional_hash()?;
        let coverage = input.fixed()?;
        let language = match input.byte()? {
            0 => ReportLanguageV1::English,
            1 => ReportLanguageV1::Spanish,
            _ => return Err(INVALID),
        };
        let renderer = input.text(MAX_IDENTIFIER)?;
        let media = match input.byte()? {
            0 => ReportMediaV1::Markdown,
            1 => ReportMediaV1::Pdf,
            _ => return Err(INVALID),
        };
        let record = Self {
            checkpoint,
            citations,
            reviewed_model_draft,
            analyst_sections,
            coverage,
            language,
            renderer,
            media,
            rendered_length: input.u64()?,
            rendered_sha256: input.fixed()?,
            proof_set: input.fixed()?,
        };
        input.finish()?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        if !(1..=MAX_REPORT_BYTES).contains(&self.rendered_length) {
            return Err(INVALID);
        }
        Ok(())
    }
}

fn put_text(out: &mut Vec<u8>, value: &str, limit: usize) -> Result<()> {
    if value.is_empty() {
        return Err(INVALID);
    }
    put_text_with_empty(out, value, limit)
}

fn put_text_with_empty(out: &mut Vec<u8>, value: &str, limit: usize) -> Result<()> {
    if value.len() > limit {
        return Err(INVALID);
    }
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| INVALID)?
            .to_be_bytes(),
    );
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_optional_hash(out: &mut Vec<u8>, value: Option<Digest>) {
    match value {
        Some(hash) => {
            out.push(1);
            out.extend_from_slice(&hash);
        }
        None => out.push(0),
    }
}

struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let (value, rest) = self.0.split_at_checked(length).ok_or(INVALID)?;
        self.0 = rest;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| INVALID)
    }

    fn byte(&mut self) -> Result<u8> {
        let [value] = self.fixed()?;
        Ok(value)
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn text(&mut self, limit: usize) -> Result<String> {
        let value = self.text_or_empty(limit)?;
        if value.is_empty() {
            return Err(INVALID);
        }
        Ok(value)
    }

    fn text_or_empty(&mut self, limit: usize) -> Result<String> {
        let length = usize::try_from(u32::from_be_bytes(self.fixed()?)).map_err(|_| INVALID)?;
        if length > limit {
            return Err(INVALID);
        }
        Ok(std::str::from_utf8(self.take(length)?)
            .map_err(|_| INVALID)?
            .to_owned())
    }

    fn optional_hash(&mut self) -> Result<Option<Digest>> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.fixed().map(Some),
            _ => Err(INVALID),
        }
    }

    fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(INVALID)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    pub(super) fn vector(name: &str) -> String {
        let all: serde_json::Value = serde_json::from_str(include_str!(
            "../../testkit/fixtures/contracts/sigma_report_v10.json"
        ))
        .unwrap();
        all[name]["bytes_hex"].as_str().unwrap().to_owned()
    }

    #[test]
    fn approved_receipt_vectors_round_trip() {
        let bytes = vector("sigma_pack_admission_v1");
        let admission = SigmaPackAdmissionV1::decode(&bytes).unwrap();
        assert!(matches!(
            admission.origin,
            SigmaPackOriginV1::PinnedReleaseArchive(_)
        ));
        assert_eq!(admission.encode().unwrap(), bytes);
        for (name, expected) in [
            ("sigma_run_v1_complete", SigmaRunStatusV1::Complete),
            ("sigma_run_v1_work_limit", SigmaRunStatusV1::WorkLimit),
        ] {
            let bytes = vector(name);
            let run = SigmaRunV1::decode(&bytes).unwrap();
            assert!(run.status == expected);
            assert_eq!(run.encode().unwrap(), bytes);
        }
        let bytes = vector("report_published_v1");
        let report = ReportPublishedV1::decode(&bytes).unwrap();
        assert!(report.language == ReportLanguageV1::Spanish);
        assert!(report.analyst_sections.is_some());
        assert_eq!(report.encode().unwrap(), bytes);
    }

    #[test]
    fn receipts_reject_malformed_or_noncanonical_bytes() {
        let bytes = vector("sigma_run_v1_complete");
        assert!(SigmaRunV1::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(SigmaRunV1::decode(&bytes.to_ascii_uppercase()).is_err());
        assert!(SigmaRunV1::decode(&format!("{bytes}00")).is_err());
        assert!(ReportPublishedV1::decode(&bytes).is_err());
        let mut raw = decode_payload(&bytes, RUN).unwrap();
        let time = RUN.len() + 4 + 36 + 8 + 32 + 3 * 32;
        raw[time..time + 16].fill(0);
        assert!(SigmaRunV1::decode(&encode_payload(&raw).unwrap()).is_err());
        let mut run = SigmaRunV1::decode(&bytes).unwrap();
        run.used_units = run.reserved_units + 1;
        assert!(run.encode().is_err());

        let bytes = vector("report_published_v1");
        let mut raw = decode_payload(&bytes, REPORT).unwrap();
        let draft = REPORT.len() + 4 + 36 + 8 + 32 + 32;
        raw[draft] = 2;
        assert!(ReportPublishedV1::decode(&encode_payload(&raw).unwrap()).is_err());
        let mut report = ReportPublishedV1::decode(&bytes).unwrap();
        report.rendered_length = MAX_REPORT_BYTES + 1;
        assert!(report.encode().is_err());

        let mut raw = decode_payload(&vector("sigma_pack_admission_v1"), ADMISSION).unwrap();
        raw[ADMISSION.len() + 64] = 0;
        assert!(SigmaPackAdmissionV1::decode(&encode_payload(&raw).unwrap()).is_err());
    }
}
