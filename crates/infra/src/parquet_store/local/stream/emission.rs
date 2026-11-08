use super::{AppError, CancellationToken, File, ParseReport, StreamingEventParser};
use irmind_domain::Tainted;
use std::io::Read;
#[derive(Clone, Copy)]
pub(super) struct Input<'a> {
    pub(super) source: &'a str,
    pub(super) parser: &'a dyn StreamingEventParser,
    pub(super) hash: [u8; 32],
    pub(super) cancel: &'a CancellationToken,
    pub(super) precise: bool,
}
pub(super) fn file(
    i: Input<'_>,
    file: &mut File,
    emit: &mut dyn FnMut(Tainted<irmind_app::IndexedGraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    if i.precise {
        i.parser
            .parse_indexed_local_file_report(i.source, file, i.hash, i.cancel, emit)
    } else {
        i.parser
            .parse_local_file_report(i.source, file, i.hash, i.cancel, &mut |row| {
                emit(super::wrap_replay(&row)?)
            })
    }
}
pub(super) fn reader(
    i: Input<'_>,
    reader: &mut dyn Read,
    emit: &mut dyn FnMut(Tainted<irmind_app::IndexedGraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    if i.precise {
        i.parser
            .parse_indexed_reader_report(i.source, reader, i.hash, i.cancel, emit)
    } else {
        i.parser
            .parse_reader_report(i.source, reader, i.hash, i.cancel, &mut |row| {
                emit(super::wrap_replay(&row)?)
            })
    }
}
