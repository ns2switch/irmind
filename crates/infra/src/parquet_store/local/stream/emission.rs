use super::{AppError, CancellationToken, File, ParseReport, StreamingEventParser, invalid_source};
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
pub(super) trait Emission {
    type Record;
    fn file(
        input: Input<'_>,
        file: &mut File,
        emit: &mut dyn FnMut(Tainted<Self::Record>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError>;
    fn reader(
        input: Input<'_>,
        reader: &mut dyn Read,
        emit: &mut dyn FnMut(Tainted<Self::Record>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError>;
}
pub(super) struct Indexed;
impl Emission for Indexed {
    type Record = irmind_app::IndexedGraphRecord;
    fn file(
        i: Input<'_>,
        file: &mut File,
        emit: &mut dyn FnMut(Tainted<Self::Record>) -> Result<(), AppError>,
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
    fn reader(
        i: Input<'_>,
        reader: &mut dyn Read,
        emit: &mut dyn FnMut(Tainted<Self::Record>) -> Result<(), AppError>,
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
}
pub(super) struct Common;
impl Emission for Common {
    type Record = irmind_app::CommonGraphRecord;
    fn file(
        i: Input<'_>,
        file: &mut File,
        emit: &mut dyn FnMut(Tainted<Self::Record>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        if !i.precise {
            return Err(invalid_source());
        }
        i.parser
            .parse_common_local_file_report(i.source, file, i.hash, i.cancel, emit)
    }
    fn reader(
        i: Input<'_>,
        reader: &mut dyn Read,
        emit: &mut dyn FnMut(Tainted<Self::Record>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        if !i.precise {
            return Err(invalid_source());
        }
        i.parser
            .parse_common_reader_report(i.source, reader, i.hash, i.cancel, emit)
    }
}
