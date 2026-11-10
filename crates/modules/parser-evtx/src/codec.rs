use super::{bad, strict};
use irmind_app::{AppError, IndexedGraphRecord, ParseReport};
use irmind_domain::Tainted;
use serde::Deserialize;

pub(super) const PROTOCOL: &str = "irmind-evtx-ndjson-v1";
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Frame {
    Ready {
        protocol: String,
        decoder: String,
    },
    Record {
        record_id: u64,
        offset: u64,
        timestamp: String,
        event: serde_json::Value,
    },
    Rejected {
        record_id: Option<u64>,
        offset: Option<u64>,
        code: String,
    },
    Complete {
        accepted: u64,
        rejected: u64,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    kind: String,
    protocol: String,
    isolated: bool,
}
pub(super) fn probe(bytes: &[u8]) -> Result<(), AppError> {
    let probe: Probe = serde_json::from_value(strict::decode(bytes)?)
        .map_err(|_| bad("invalid EVTX isolation response"))?;
    if probe.kind != "probe" || probe.protocol != PROTOCOL || !probe.isolated {
        return Err(bad("EVTX isolation is not verified"));
    }
    Ok(())
}
pub(super) struct DecodedRecord {
    pub accepted_index: u64,
    pub index: u64,
    pub record_id: u64,
    pub offset: u64,
    pub timestamp: String,
    pub event: serde_json::Value,
}
pub(super) struct State<'a> {
    source: &'a str,
    hash: [u8; 32],
    size: u64,
    ready: bool,
    complete: bool,
    report: ParseReport,
    seen: u64,
    decoder_accepted: u64,
    decoder_rejected: u64,
}
impl<'a> State<'a> {
    pub(super) fn new(source: &'a str, hash: [u8; 32], size: u64) -> Self {
        Self {
            source,
            hash,
            size,
            ready: false,
            complete: false,
            report: ParseReport {
                accepted: 0,
                rejected: 0,
                samples: Vec::new(),
            },
            seen: 0,
            decoder_accepted: 0,
            decoder_rejected: 0,
        }
    }
    pub(super) fn frame(
        &mut self,
        bytes: &[u8],
        emit: &mut dyn FnMut(Tainted<IndexedGraphRecord>) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        let (source, hash) = (self.source, self.hash);
        self.project_frame(bytes, &mut |row| {
            if let Ok(record) = super::normalize::record(
                source,
                hash,
                row.index,
                row.record_id,
                row.offset,
                &row.timestamp,
                &row.event,
            ) {
                emit(record)?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }
    pub(super) fn project_frame(
        &mut self,
        bytes: &[u8],
        project: &mut dyn FnMut(DecodedRecord) -> Result<bool, AppError>,
    ) -> Result<(), AppError> {
        if self.complete {
            return Err(bad("EVTX output after completion"));
        }
        let frame: Frame = serde_json::from_value(strict::decode(bytes)?)
            .map_err(|_| bad("invalid EVTX protocol frame"))?;
        match frame {
            Frame::Ready { protocol, decoder }
                if !self.ready && protocol == PROTOCOL && decoder == "0.15.1" =>
            {
                self.ready = true;
            }
            Frame::Record {
                record_id,
                offset,
                timestamp,
                event,
            } if self.ready => {
                self.next()?;
                self.offset(offset)?;
                self.decoder_accepted += 1;
                if project(DecodedRecord {
                    accepted_index: self.report.accepted as u64,
                    index: self.seen - 1,
                    record_id,
                    offset,
                    timestamp,
                    event,
                })? {
                    self.report.accepted += 1;
                } else {
                    self.report.rejected += 1;
                    if self.report.samples.len() < 3 {
                        self.report.samples.push(format!(
                            "EVTX record {record_id} has invalid normalized fields"
                        ));
                    }
                }
            }
            Frame::Rejected {
                record_id,
                offset,
                code,
            } if self.ready => {
                self.next()?;
                if let Some(offset) = offset {
                    self.offset(offset)?;
                }
                if code != "invalid-record" {
                    return Err(bad("unknown EVTX rejection code"));
                }
                self.report.rejected += 1;
                self.decoder_rejected += 1;
                if self.report.samples.len() < 3 {
                    self.report.samples.push(format!(
                        "EVTX record {} rejected by decoder",
                        record_id.map_or_else(|| "unknown".into(), |id| id.to_string())
                    ));
                }
            }
            Frame::Complete { accepted, rejected } if self.ready => {
                if accepted != self.decoder_accepted || rejected != self.decoder_rejected {
                    return Err(bad("EVTX completion count mismatch"));
                }
                self.complete = true;
            }
            _ => return Err(bad("unexpected EVTX protocol frame or version")),
        }
        Ok(())
    }
    fn next(&mut self) -> Result<(), AppError> {
        self.seen += 1;
        if self.seen > 8_000_000 {
            return Err(bad(
                "EVTX record limit reached (8000000 records); entire file rejected; no partial ingestion",
            ));
        }
        Ok(())
    }
    fn offset(&self, offset: u64) -> Result<(), AppError> {
        if offset < 4096 + 512 || offset >= self.size {
            return Err(bad("EVTX offset outside source"));
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<ParseReport, AppError> {
        if !self.complete {
            return Err(bad("EVTX decoder ended without completion"));
        }
        Ok(self.report)
    }
}

pub(super) fn detect(sample: &[u8]) -> bool {
    if sample.len() < 128
        || sample.get(..8) != Some(b"ElfFile\0")
        || sample[38..40] != 3u16.to_le_bytes()
        || sample[40..42] != 4096u16.to_le_bytes()
    {
        return false;
    }
    let mut crc = u32::MAX;
    for byte in &sample[..120] {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320u32.wrapping_mul(crc & 1));
        }
    }
    !crc == u32::from_le_bytes([sample[124], sample[125], sample[126], sample[127]])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod budget_tests {
    use super::*;
    #[test]
    fn exact_record_ceiling_is_accepted_and_the_next_record_is_an_error() {
        let mut state = State::new("source.evtx", [0; 32], 69632);
        state.seen = 7_999_999;
        state.next().unwrap();
        let message = state.next().unwrap_err().to_string();
        assert!(message.contains("8000000 records"));
        assert!(message.contains("entire file rejected"));
        assert!(message.contains("no partial ingestion"));
    }
}
