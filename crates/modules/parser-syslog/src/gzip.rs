use super::{AppError, CancellationToken, GraphRecord, ParseReport, SyslogParser, Tainted};
use flate2::read::MultiGzDecoder;
use std::io::{self, Cursor, Read};

const MAX_GZIP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(super) fn sample(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    // A detector inspects a bounded prefix, not the stream's validity.
    let _ = MultiGzDecoder::new(Cursor::new(input))
        .take(4096)
        .read_to_end(&mut output);
    output
}

pub(super) fn parse(
    parser: &SyslogParser,
    source: &str,
    reader: &mut dyn Read,
    hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut prefix = [0; 2];
    let mut used = 0;
    while used < prefix.len() {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let count = reader.read(&mut prefix[used..]).map_err(|_| failure())?;
        if count == 0 {
            break;
        }
        used += count;
    }
    let replay = Cursor::new(&prefix[..used]).chain(reader);
    if prefix != [0x1f, 0x8b] || used < 2 {
        return super::input::parse(parser, source, &mut { replay }, hash, cancel, emit);
    }
    let compressed = Bounded {
        inner: replay,
        bytes: 0,
        limit: MAX_GZIP_BYTES,
        cancel,
    };
    let decoded = MultiGzDecoder::new(compressed);
    let mut decoded = Bounded {
        inner: decoded,
        bytes: 0,
        limit: MAX_GZIP_BYTES,
        cancel,
    };
    let result = super::input::parse(parser, source, &mut decoded, hash, cancel, &mut |row| {
        let location = irmind_domain::ParserLocation::new(source, "parser-syslog", 0)
            .map_err(|_| failure())?;
        emit(row.with_parser_location(location))
    });
    if cancel.is_cancelled() {
        Err(AppError::Cancelled)
    } else {
        result.map_err(|error| {
            if matches!(error, AppError::Storage(_)) {
                failure()
            } else {
                error
            }
        })
    }
}

struct Bounded<'a, R> {
    inner: R,
    bytes: u64,
    limit: u64,
    cancel: &'a CancellationToken,
}
impl<R: Read> Read for Bounded<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::other("cancelled"));
        }
        let capacity = output.len().min(
            usize::try_from(self.limit.saturating_sub(self.bytes))
                .unwrap_or(usize::MAX)
                .saturating_add(1),
        );
        let count = self.inner.read(&mut output[..capacity])?;
        self.bytes = self.bytes.saturating_add(count as u64);
        if self.bytes > self.limit {
            return Err(io::Error::other("gzip size limit exceeded"));
        }
        Ok(count)
    }
}

fn failure() -> AppError {
    AppError::Storage(
        "invalid or oversized gzip syslog source (2 GiB compressed/decompressed limit)".into(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn decompressed_limit_and_cancellation_fail_closed() {
        let cancel = CancellationToken::new();
        let mut reader = Bounded {
            inner: Cursor::new(b"12345678"),
            bytes: 0,
            limit: 4,
            cancel: &cancel,
        };
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        cancel.cancel();
        assert!(reader.read(&mut [0; 1]).is_err());
    }
}
