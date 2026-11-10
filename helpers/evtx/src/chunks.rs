//! Decode owned chunks in bounded groups without changing the record protocol.
use super::{MAX_RECORDS, invalid, output};
use evtx::{EvtxChunkData, ParserSettings};
use std::{
    io,
    sync::{Arc, mpsc},
    thread,
};

struct Frame {
    accepted: bool,
    bytes: Vec<u8>,
}

struct Output<'a, 'b> {
    writer: &'a mut output::Output<'b>,
    accepted: u64,
    rejected: u64,
}

impl Output<'_, '_> {
    fn check_record(&self) -> io::Result<()> {
        if self.accepted + self.rejected >= MAX_RECORDS {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "EVTX record limit reached (8000000 records); entire file rejected; no partial ingestion",
            ))
        } else {
            Ok(())
        }
    }

    fn emit(&mut self, frame: &Frame) -> io::Result<()> {
        self.check_record()?;
        self.writer.encoded(&frame.bytes)?;
        if frame.accepted {
            self.accepted += 1;
        } else {
            self.rejected += 1;
        }
        Ok(())
    }
}

pub(super) fn decode<E>(
    chunks: impl Iterator<Item = Result<EvtxChunkData, E>>,
    size: u64,
    settings: &Arc<ParserSettings>,
    workers: usize,
    writer: &mut output::Output<'_>,
) -> io::Result<(u64, u64)> {
    let workers = workers.clamp(1, 7);
    let mut output = Output {
        writer,
        accepted: 0,
        rejected: 0,
    };
    let mut chunks = chunks.map(|chunk| chunk.map_err(|_| invalid()));
    if workers == 1 {
        for chunk in chunks {
            visit(chunk?, size, settings, |item| match item {
                Record::Before => output.check_record(),
                Record::Ready(frame) => output.emit(&frame),
            })?;
        }
    } else {
        loop {
            let group = chunks.by_ref().take(workers).collect::<Vec<_>>();
            if group.is_empty() {
                break;
            }
            write_group(group, size, settings, &mut output)?;
        }
    }
    Ok((output.accepted, output.rejected))
}

fn write_group(
    chunks: Vec<io::Result<EvtxChunkData>>,
    size: u64,
    settings: &Arc<ParserSettings>,
    output: &mut Output<'_, '_>,
) -> io::Result<()> {
    thread::scope(|scope| {
        let mut receivers = Vec::with_capacity(chunks.len());
        let mut handles = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            // At most one serialized frame waits per worker. The supervisor
            // still owns the whole-helper timeout and can stop blocked output.
            let (tx, rx) = mpsc::sync_channel(1);
            let handle = thread::Builder::new().spawn_scoped(scope, move || {
                let result = chunk.and_then(|chunk| {
                    visit(chunk, size, settings, |item| match item {
                        Record::Before => Ok(()),
                        Record::Ready(frame) => tx.send(Ok(frame)).map_err(|_| invalid()),
                    })
                });
                if let Err(error) = result {
                    let _ = tx.send(Err(error));
                }
            })?;
            receivers.push(rx);
            handles.push(handle);
        }
        let mut result = Ok(());
        for receiver in receivers {
            if result.is_ok() {
                result = receiver
                    .into_iter()
                    .try_for_each(|frame| output.emit(&frame?));
            }
        }
        for worker in handles {
            let joined = worker.join().map_err(|_| invalid());
            if result.is_ok() {
                result = joined;
            }
        }
        result
    })
}

enum Record {
    Before,
    Ready(Frame),
}

fn visit(
    mut chunk: EvtxChunkData,
    size: u64,
    settings: &Arc<ParserSettings>,
    mut sink: impl FnMut(Record) -> io::Result<()>,
) -> io::Result<()> {
    let base = chunk
        .number
        .ok_or_else(invalid)?
        .checked_mul(65_536)
        .and_then(|v| v.checked_add(4096))
        .ok_or_else(invalid)?;
    let mut parsed = chunk.parse(settings.clone()).map_err(|_| invalid())?;
    for record in parsed.iter() {
        sink(Record::Before)?;
        let frame = if let Ok(record) = record {
            let offset = base
                .checked_add(record.binxml_offset)
                .and_then(|v| v.checked_sub(24))
                .ok_or_else(invalid)?;
            if offset >= size {
                return Err(invalid());
            }
            let id = record.event_record_id;
            let time = record.timestamp.to_string();
            if let Ok(value) = record.into_json_value() {
                Frame {
                    accepted: true,
                    bytes: output::encode(
                        &serde_json::json!({"kind":"record","record_id":id,"offset":offset,"timestamp":time,"event":value.data}),
                    )?,
                }
            } else {
                rejected(Some(id), Some(offset))?
            }
        } else {
            rejected(None, None)?
        };
        sink(Record::Ready(frame))?;
    }
    Ok(())
}
fn rejected(record_id: Option<u64>, offset: Option<u64>) -> io::Result<Frame> {
    Ok(Frame {
        accepted: false,
        bytes: output::encode(
            &serde_json::json!({"kind":"rejected","record_id":record_id,"offset":offset,"code":"invalid-record"}),
        )?,
    })
}
