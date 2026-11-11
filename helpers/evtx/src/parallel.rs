use crate::{MAX_RECORDS, invalid, output};
use evtx::{EvtxChunkData, EvtxParser, ParserSettings};
use std::{
    io::{self, Read, Seek},
    sync::{
        Arc,
        mpsc::{self, Receiver, SyncSender},
    },
    thread,
};

enum Frame {
    Record(Vec<u8>, bool),
    End,
    Error(io::Error),
}
struct Slot {
    send: SyncSender<EvtxChunkData>,
    receive: Receiver<Frame>,
    active: bool,
}

pub(super) fn chunks<R: Read + Seek + Send>(
    parser: &mut EvtxParser<R>,
    settings: &Arc<ParserSettings>,
    size: u64,
    workers: usize,
    writer: &mut output::Output<'_>,
) -> io::Result<(u64, u64)> {
    if workers == 1 {
        let mut counts = (0, 0);
        for chunk in parser.chunks() {
            decode(
                chunk.map_err(|_| invalid())?,
                settings,
                size,
                &mut |bytes, valid| append(writer, &mut counts, &bytes, valid),
            )?;
        }
        return Ok(counts);
    }
    thread::scope(|scope| {
        let mut slots = Vec::new();
        for _ in 0..workers {
            let (send, jobs) = mpsc::sync_channel::<EvtxChunkData>(1);
            let (frames, receive) = mpsc::sync_channel(1);
            let settings = Arc::clone(settings);
            thread::Builder::new().spawn_scoped(scope, move || {
                while let Ok(chunk) = jobs.recv() {
                    if let Err(error) = decode(chunk, &settings, size, &mut |bytes, valid| {
                        frames
                            .send(Frame::Record(bytes, valid))
                            .map_err(|_| invalid())
                    })
                    .and_then(|()| frames.send(Frame::End).map_err(|_| invalid()))
                    {
                        let _ = frames.send(Frame::Error(error));
                        return;
                    }
                }
            })?;
            slots.push(Slot {
                send,
                receive,
                active: false,
            });
        }
        let result = ordered(parser, &mut slots, writer);
        // Disconnect both directions before scope joins; a producer must never
        // retain a blocked output send after a sink error or early termination.
        drop(slots);
        result
    })
}
fn ordered<R: Read + Seek + Send>(
    parser: &mut EvtxParser<R>,
    slots: &mut [Slot],
    writer: &mut output::Output<'_>,
) -> io::Result<(u64, u64)> {
    let mut chunks = parser.chunks();
    for slot in &mut *slots {
        if let Some(chunk) = chunks.next() {
            slot.send
                .send(chunk.map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
            slot.active = true;
        }
    }
    let (mut accepted, mut rejected) = (0, 0);
    while slots.iter().any(|slot| slot.active) {
        for slot in &mut *slots {
            if !slot.active {
                continue;
            }
            loop {
                match slot.receive.recv().map_err(|_| invalid())? {
                    Frame::Record(bytes, valid) => {
                        let mut counts = (accepted, rejected);
                        append(writer, &mut counts, &bytes, valid)?;
                        (accepted, rejected) = counts;
                    }
                    Frame::End => break,
                    Frame::Error(error) => return Err(error),
                }
            }
            slot.active = false;
            if let Some(chunk) = chunks.next() {
                slot.send
                    .send(chunk.map_err(|_| invalid())?)
                    .map_err(|_| invalid())?;
                slot.active = true;
            }
        }
    }
    Ok((accepted, rejected))
}
fn decode(
    mut chunk: EvtxChunkData,
    settings: &Arc<ParserSettings>,
    size: u64,
    emit: &mut dyn FnMut(Vec<u8>, bool) -> io::Result<()>,
) -> io::Result<()> {
    let base = chunk
        .number
        .ok_or_else(invalid)?
        .checked_mul(65_536)
        .and_then(|v| v.checked_add(4096))
        .ok_or_else(invalid)?;
    let mut parsed = chunk.parse(Arc::clone(settings)).map_err(|_| invalid())?;
    for record in parsed.iter() {
        let (frame, valid) = if let Ok(record) = record {
            let offset = base
                .checked_add(record.binxml_offset)
                .and_then(|v| v.checked_sub(24))
                .ok_or_else(invalid)?;
            if offset >= size {
                return Err(invalid());
            }
            let id = record.event_record_id;
            let timestamp = record.timestamp.to_string();
            if let Ok(value) = record.into_json_value() {
                (
                    serde_json::json!({"kind":"record","record_id":id,"offset":offset,"timestamp":timestamp,"event":value.data}),
                    true,
                )
            } else {
                (rejected(Some(id), Some(offset)), false)
            }
        } else {
            (rejected(None, None), false)
        };
        let bytes = output::encode(&frame)?;
        emit(bytes, valid)?;
    }
    Ok(())
}
fn rejected(record: Option<u64>, offset: Option<u64>) -> serde_json::Value {
    serde_json::json!({"kind":"rejected","record_id":record,"offset":offset,"code":"invalid-record"})
}

fn append(
    writer: &mut output::Output<'_>,
    counts: &mut (u64, u64),
    bytes: &[u8],
    valid: bool,
) -> io::Result<()> {
    if counts.0 + counts.1 >= MAX_RECORDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "EVTX record limit reached (8000000 records); entire file rejected; no partial ingestion",
        ));
    }
    writer.encoded(bytes)?;
    if valid {
        counts.0 += 1;
    } else {
        counts.1 += 1;
    }
    Ok(())
}
