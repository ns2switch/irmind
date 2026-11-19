use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceRecordV1, SourceReferenceV1},
};

const LOG: &str = include_str!("../../../testkit/fixtures/parser-iis-w3c/source/access.log");

#[test]
fn fields_apply_only_after_their_declaration_and_offsets_are_physical() {
    let augmented = LOG.replace(
        "#Fields: time date c-ip cs-uri-stem cs-method s-ip sc-status custom-field",
        concat!(
            "#Fields: date time sc-status sc-status\r\n",
            "2026-11-17 20:00:02 200 500\r\n",
            "#Fields: time date c-ip cs-uri-stem cs-method s-ip sc-status custom-field",
        ),
    );
    let source = SourceReferenceV1::file("access.log").unwrap();
    let cancel = CancellationToken::new();
    let mut rows = Vec::<SourceRecordV1>::new();
    let report = IisW3cSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(augmented.as_bytes()),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut augmented.as_bytes(),
            },
            &mut |record| {
                record.inspect(|row| rows.push(row.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (3, 2));
    assert_eq!(
        rows[2].origin().offset(),
        Some(augmented.find("20:00:03.000157").unwrap() as u64)
    );
    assert_eq!(
        rows[2].timestamp().unwrap().to_rfc3339(),
        "2026-11-17T20:00:03.000157Z"
    );
    assert_eq!(
        rows[2].fields().field("custom-field").unwrap().as_text(),
        Some("original-custom")
    );
    assert!(rows[2].fields().field("cs-uri-query").is_none());
    assert_eq!(
        rows[0].fields().field("cs-uri-query").unwrap().as_text(),
        Some("command=%2522%253Bkeep")
    );
}

#[test]
fn detector_uses_w3c_directives_independently_of_filename() {
    assert_eq!(
        IisW3cParser
            .detect("copy.bin", LOG.as_bytes())
            .unwrap()
            .value(),
        98
    );
    assert!(
        IisW3cParser
            .detect(
                "u_ex.log",
                b"#Software: IIS\n#Fields: date time arbitrary\n"
            )
            .is_none()
    );
}
