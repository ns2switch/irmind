use super::*;
use crate::{
    CancellationToken,
    source_mapping::{SourceInput, SourceReferenceV1},
};
use std::{collections::BTreeMap, io::Cursor};
fn frame(fields: SourceValue) -> DecodedSourceFrame {
    DecodedSourceFrame {
        fields,
        timestamp: None,
        format: SourceFormatV1::try_new("synthetic", "v1", BTreeMap::new()).unwrap(),
    }
}
fn decode(
    bytes: &[u8],
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let source = SourceReferenceV1::file("synthetic.jsonl").unwrap();
    let cancel = CancellationToken::new();
    decode_json_source(
        SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: crate::sha256(bytes),
                time_context: None,
                cancel: &cancel,
            },
            reader: &mut Cursor::new(bytes),
        },
        ParserIdentity {
            name: "parser-synthetic",
            version: "v1",
        },
        &mut |fields| Ok(frame(fields)),
        emit,
    )
}
#[test]
fn callback_errors_never_become_rejected_records() {
    for error in [
        AppError::Cancelled,
        invalid(),
        AppError::Fixed(crate::FixedAppError::AdapterStorage(
            crate::AdapterStorageError::LocalStorageOperationFailed,
        )),
    ] {
        let mut pending = Some(error);
        let result = decode(b"{\"key\":1}\n", &mut |_| Err(pending.take().unwrap()));
        assert!(result.is_err());
        assert!(pending.is_none());
    }
}
#[test]
fn bounded_rejection_preserves_later_rows_and_real_offsets() {
    let mut pointers = Vec::new();
    let report = decode(b"{bad}\n{\"ok\":1}\n", &mut |row| {
        row.inspect(|r| pointers.push((r.origin().offset(), r.annotations().members()[0].ordinal)));
        Ok(())
    })
    .unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 1));
    assert_eq!(pointers, [(Some(6), 1)]);
}
#[test]
fn record_wrapper_names_remain_original_fields() {
    let bytes = b"{\"events\":[{\"key\":1}],\"Records\":[2]}";
    let mut seen = 0;
    let report = decode(bytes, &mut |row| {
        row.inspect(|r| {
            assert!(r.fields().field("events").is_some());
            assert!(r.fields().field("Records").is_some());
            seen += 1;
        });
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, 1);
    assert_eq!(report.accepted, 1);
}
#[test]
fn pretty_objects_and_large_single_line_arrays_use_the_same_original_fields() {
    let one = "{\"value\":\"synthetic only\"}";
    let count = 5 * 1024 * 1024 / one.len() + 1;
    let bytes = format!(
        "[{}]",
        std::iter::repeat_n(one, count)
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut seen = 0;
    let report = decode(bytes.as_bytes(), &mut |_| {
        seen += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!((report.accepted, report.rejected, seen), (count, 0, count));
    let report = decode(b"{\n  \"key\":\n   1\n}", &mut |_| Ok(())).unwrap();
    assert_eq!((report.accepted, report.rejected), (1, 0));
}
#[test]
fn time_parser_retains_precision_and_requires_declared_offset_for_naive_text() {
    assert!(source_datetime("2026-11-01T00:00:00", None).is_err());
    let time = source_datetime("2026-11-01 01:02:03.123456789 +01:00", None).unwrap();
    assert_eq!(time.to_rfc3339(), "2026-11-01T00:02:03.123456789Z");
}
