use super::{
    AppError, CancellationToken, GraphRecord, LinuxParser, ParseReport, Tainted,
    audit::{AuditState, Completed},
    bad, bounds,
    time::Calendar,
};
use irmind_domain::{ParserLocation, Provenance, SourceKind};
use std::io::{BufReader, Read};

pub(super) fn parse(
    parser: &LinuxParser,
    source: &str,
    reader: &mut dyn Read,
    hash: [u8; 32],
    cancel: &CancellationToken,
    emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut reader = BufReader::new(reader);
    let mut state = State {
        parser,
        source,
        hash,
        cancel,
        emit,
        calendar: parser.context.map(Calendar::new),
        audit: AuditState::default(),
        report: ParseReport {
            accepted: 0,
            rejected: 0,
            samples: vec![],
        },
    };
    let (mut index, mut offset) = (0usize, 0u64);
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (bytes, consumed) = bounds::line(&mut reader, cancel)?;
        if consumed == 0 {
            break;
        }
        if index >= bounds::MAX_RECORDS || offset + consumed > bounds::MAX_SOURCE {
            return Err(bad("Linux source exceeds its record or byte limit"));
        }
        if consumed > bounds::MAX_LINE as u64 {
            bounds::reject(&mut state.report, &bytes);
        } else if !bytes.iter().all(u8::is_ascii_whitespace) {
            match std::str::from_utf8(&bytes) {
                Ok(line) => match state.process(line.trim_end_matches(['\r', '\n']), index, offset)
                {
                    Ok(records) => state.emit(records)?,
                    Err(error @ AppError::ParserTimeContextRequired { .. }) => return Err(error),
                    Err(_) => bounds::reject(&mut state.report, &bytes),
                },
                Err(_) => bounds::reject(&mut state.report, &bytes),
            }
        }
        index += 1;
        offset += consumed;
    }
    let remaining = state.audit.finish()?;
    state.emit(remaining)?;
    Ok(state.report)
}
struct State<'a> {
    parser: &'a LinuxParser,
    source: &'a str,
    hash: [u8; 32],
    cancel: &'a CancellationToken,
    emit: &'a mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    calendar: Option<Calendar>,
    audit: AuditState,
    report: ParseReport,
}
impl State<'_> {
    fn process(
        &mut self,
        line: &str,
        index: usize,
        offset: u64,
    ) -> Result<Vec<Completed>, AppError> {
        if super::audit::detect(line) {
            return self.audit.push(line, index, offset);
        }
        let record = if line.starts_with('{') {
            super::journal::parse(line, index)?
        } else if super::auth::header(line).is_some() {
            super::auth::parse(self.parser, self.source, line, index, &mut self.calendar)?
        } else {
            super::web::parse(line, index)?
        };
        Ok(vec![Completed { record, offset }])
    }
    fn emit(&mut self, records: Vec<Completed>) -> Result<(), AppError> {
        for item in records {
            if self.cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let provenance =
                Provenance::new(self.hash, Some(item.record.index as u64), SourceKind::File);
            let location = ParserLocation::new(self.source, "parser-linux", item.offset)
                .map_err(|_| bad("invalid Linux source provenance"))?;
            (self.emit)(
                Tainted::from_external(item.record, provenance).with_parser_location(location),
            )?;
            self.report.accepted += 1;
        }
        Ok(())
    }
}
