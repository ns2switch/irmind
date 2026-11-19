use super::*;
use irmind_app::{
    CancellationToken, ParserTimeBasis, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};
use irmind_domain::Tainted;

const TEXT: &str = include_str!("../../../testkit/fixtures/parser-windows-dns/source/dns.log");

fn decode(
    text: &str,
    context: Option<&ParserTimeContext>,
) -> Result<(irmind_app::ParseReport, Vec<SourceRecordV1>), AppError> {
    let cancel = CancellationToken::new();
    let reference = SourceReferenceV1::file("dns.log").unwrap();
    let mut bytes = text.as_bytes();
    let mut output = Vec::new();
    let report = WindowsDnsSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &reference,
                evidence_hash: irmind_app::sha256(bytes),
                time_context: context,
                cluster_context: None,
                cancel: &cancel,
            },
            reader: &mut bytes,
        },
        &mut |record: Tainted<SourceRecordV1>| {
            record.inspect(|record| output.push(record.clone()));
            Ok(())
        },
    )?;
    Ok((report, output))
}

#[test]
fn detection_requires_header_and_does_not_choose_ambiguous_calendar_dates() {
    let parser = WindowsDnsParser;
    assert_eq!(
        parser.detect("evidence", TEXT.as_bytes()).unwrap().value(),
        98
    );
    let ambiguous = TEXT.replace("11/17/2026", "11/07/2026");
    assert!(
        !parser
            .detect("dns.log", ambiguous.as_bytes())
            .unwrap()
            .is_high()
    );
    let missing_header = TEXT.lines().skip(1).collect::<Vec<_>>().join("\n");
    assert!(
        parser
            .detect("dns.log", missing_header.as_bytes())
            .is_none()
    );
    let bad = TEXT.replace("11/17/2026", "17/11/2026");
    assert!(parser.detect("dns.log", bad.as_bytes()).is_none());
    assert!(
        parser
            .time_context_requirement("dns.log", TEXT.as_bytes())
            .unwrap()
            .unwrap()
            .required
    );
}

#[test]
fn offset_is_explicit_and_provenance_survives_invalid_lines() {
    let time = ParserTimeContext::new(2026, -300, false, ParserTimeBasis::Command).unwrap();
    assert!(decode(TEXT, None).is_err());
    let wrong_year = ParserTimeContext::new(2025, 0, false, ParserTimeBasis::Analyst).unwrap();
    assert!(decode(TEXT, Some(&wrong_year)).is_err());
    let text = TEXT.replace("\n11/17/2026 8:00:02", "\nbad record\n11/17/2026 8:00:02");
    let (report, rows) = decode(&text, Some(&time)).unwrap();
    assert_eq!((report.accepted, report.rejected), (4, 1));
    assert_eq!(
        rows[1].origin().offset(),
        Some(text.find("11/17/2026 8:00:02").unwrap() as u64)
    );
    assert_eq!(
        rows[0].timestamp().unwrap().to_rfc3339(),
        "2026-11-18T01:00:01Z"
    );
    assert!(rows[0].timestamp().unwrap().inferred());
    assert_eq!(
        rows[0].fields().field("query_name").unwrap().as_text(),
        Some("resolver.example.test.")
    );
    assert_eq!(
        rows[3].fields().field("query_type").unwrap().as_text(),
        Some("TYPE65000")
    );
}
