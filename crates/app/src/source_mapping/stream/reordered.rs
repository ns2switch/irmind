//! Compact replay has no event offsets and uses contiguous accepted positions.
use super::{
    AppError, DecodedSourceCommitmentV1, MappedSourceRecord, ParseReport, SourceRecordAccumulator,
    SourceRecordV1, Tainted, commitment, invalid,
};
use sha2::{Digest, Sha256};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};

const TUPLE_LEN: usize = 41;
const SLOT_LEN: usize = TUPLE_LEN + 32;

pub struct ReorderedRecords<'a> {
    accounting: SourceRecordAccumulator<'a>,
    expected: u64,
    salt: [u8; 16],
}

impl<'a> ReorderedRecords<'a> {
    pub const SLOT_BYTES: u64 = SLOT_LEN as u64;

    pub fn new(accounting: SourceRecordAccumulator<'a>, expected: u64) -> Result<Self, AppError> {
        if accounting.records != 0 || !(1..=10_000_000).contains(&expected) {
            return Err(invalid());
        }
        Ok(Self {
            accounting,
            expected,
            salt: *uuid::Uuid::new_v4().as_bytes(),
        })
    }

    pub fn accept(
        &mut self,
        record: Tainted<SourceRecordV1>,
        spool: &mut (impl Write + Seek),
    ) -> Result<MappedSourceRecord, AppError> {
        let prepared = self.accounting.preparer().prepare(record)?;
        if self.accounting.records >= self.expected
            || prepared.tuple.len() != TUPLE_LEN
            || (self.accounting.formats.len() == 128
                && !self.accounting.formats.contains(&prepared.format))
        {
            return Err(invalid());
        }
        let mut saved = Err(invalid());
        prepared.source.inspect(|source| {
            saved = (|| {
                let record = source.origin();
                if record.offset().is_some() || record.record() >= self.expected {
                    return Err(invalid());
                }
                let mut slot = [0u8; SLOT_LEN];
                slot[..TUPLE_LEN].copy_from_slice(&prepared.tuple);
                slot[TUPLE_LEN..].copy_from_slice(&tag(&self.salt, &prepared.tuple));
                spool
                    .seek(SeekFrom::Start(record.record() * Self::SLOT_BYTES))
                    .and_then(|_| spool.write_all(&slot))
                    .map_err(|_| invalid())?;
                Ok(())
            })();
        });
        saved?;
        prepared.source.inspect(|source| {
            prepared.mapped.output.inspect(|output| {
                self.accounting.count_mapping(
                    source,
                    prepared.format.clone(),
                    prepared.mapped.identity.as_ref(),
                    output,
                );
            });
        });
        Ok(prepared.mapped)
    }

    pub fn finish(
        self,
        spool: &mut (impl Read + Seek),
        report: &ParseReport,
    ) -> Result<DecodedSourceCommitmentV1, AppError> {
        if self.accounting.records != self.expected {
            return Err(invalid());
        }
        spool.rewind().map_err(|_| invalid())?;
        let mut slots = Slots {
            reader: BufReader::with_capacity(64 * 1024, spool),
            expected: self.expected,
            index: 0,
            salt: self.salt,
            bytes: [0; SLOT_LEN],
            offset: TUPLE_LEN,
        };
        let hash = commitment::fold(&mut slots, self.expected, self.accounting.metadata, None)?;
        self.accounting.finish_accounting(report, hash)
    }
}

fn tag(salt: &[u8; 16], tuple: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"irmind-compact-scratch-v1\0");
    digest.update(salt);
    // Always the same length, with the source index in the authenticated bytes.
    digest.update(tuple);
    digest.finalize().into()
}

struct Slots<R> {
    reader: R,
    expected: u64,
    index: u64,
    salt: [u8; 16],
    bytes: [u8; SLOT_LEN],
    offset: usize,
}

impl<R: Read> Read for Slots<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset == TUPLE_LEN {
            if self.index == self.expected {
                return self.reader.read(output);
            }
            self.reader.read_exact(&mut self.bytes)?;
            if self.bytes[..8] != self.index.to_be_bytes()
                || self.bytes[8] != 0
                || self.bytes[TUPLE_LEN..] != tag(&self.salt, &self.bytes[..TUPLE_LEN])
            {
                return Err(io::Error::other("invalid original-order receipt slot"));
            }
            self.offset = 0;
            self.index += 1;
        }
        let count = output.len().min(TUPLE_LEN - self.offset);
        output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}
