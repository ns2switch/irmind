use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};

const LOG: &str = include_str!("../../../testkit/fixtures/parser-s3-access/source/access.log");

#[test]
fn s3_preserves_request_quotes_queries_and_valid_suffixes() {
    assert_eq!(
        S3AccessParser
            .detect("evidence.txt", LOG.as_bytes())
            .unwrap()
            .value(),
        98
    );
    assert!(
        S3AccessParser
            .detect("s3.log", b"not a server log")
            .is_none()
    );
    let log = LOG.replace("\n0", "\ncorrupt entry\n0");
    let source = SourceReferenceV1::file("access.log").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::<SourceRecordV1>::new();
    let report = S3AccessSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(log.as_bytes()),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut log.as_bytes(),
            },
            &mut |record| {
                record.inspect(|row| rows.push(row.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (3, 2));
    assert_eq!(
        rows[0].fields().field("request_query").unwrap().as_text(),
        Some("q=%2522")
    );
    assert_eq!(
        rows[1].fields().field("request_query").unwrap().as_text(),
        Some(r#"q=\"literal"token"#)
    );
    assert_eq!(
        rows[2].fields().field("operation").unwrap().as_text(),
        Some("REST.FUTURE.EXAMPLE")
    );
    assert_eq!(
        rows[1].origin().offset(),
        Some(log.find("\n0").unwrap() as u64 + 1)
    );
}
