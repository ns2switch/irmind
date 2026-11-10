#![forbid(unsafe_code)]
mod chunks;
mod output;
use evtx::{EvtxParser, ParserSettings};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    sync::Arc,
};

pub const PROTOCOL: &str = "irmind-evtx-ndjson-v1";
pub const MAX_SOURCE: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_RECORD: usize = 4 * 1024 * 1024;
pub const MAX_RECORDS: u64 = 8_000_000;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "EVTX source or decoder output is invalid",
    )
}

/// Decode only an already-authorized, seekable source. The executable establishes
/// its OS containment before calling this function. Fuzzing exercises it directly.
pub fn decode<R: Read + Seek + Send>(input: R, output: &mut dyn Write) -> io::Result<()> {
    decode_with_workers(input, output, 1)
}

/// Used by the native benchmark helper. The shipped entry point still uses one
/// worker. This function never starts or changes OS containment.
pub fn decode_with_workers<R: Read + Seek + Send>(
    mut input: R,
    output: &mut dyn Write,
    workers: usize,
) -> io::Result<()> {
    let size = input.seek(SeekFrom::End(0))?;
    if !(4096..=MAX_SOURCE).contains(&size) || !(size - 4096).is_multiple_of(65_536) {
        return Err(invalid());
    }
    input.rewind()?;
    let mut header = [0u8; 128];
    input.read_exact(&mut header)?;
    if evtx::checksum_ieee(&header[..120])
        != u32::from_le_bytes(header[124..128].try_into().map_err(|_| invalid())?)
    {
        return Err(invalid());
    }
    input.rewind()?;
    let config = ParserSettings::new().validate_checksums(true).indent(false);
    let mut parser = EvtxParser::from_read_seek(input)
        .map_err(|_| invalid())?
        .with_configuration(config.clone());
    let settings = Arc::new(config);
    let mut writer = output::Output::new(output, size);
    writer.frame(&serde_json::json!({"kind":"ready","protocol":PROTOCOL,"decoder":"0.15.1"}))?;
    let (accepted, rejected) =
        chunks::decode(parser.chunks(), size, &settings, workers, &mut writer)?;
    writer
        .frame(&serde_json::json!({"kind":"complete","accepted":accepted,"rejected":rejected}))?;
    writer.flush()
}
