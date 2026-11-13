use super::*;
use crate::{
    CancellationToken,
    source_mapping::{SourceFormatV1, SourceMetadata, SourceReferenceV1},
};
use std::io::{Cursor, Read};

#[test]
fn oversized_whitespace_prefix_is_rejected_and_later_rows_keep_their_locations() {
    let row = b"{\"value\":\"synthetic\"}\n";
    let cancel = CancellationToken::new();
    let source = SourceReferenceV1::file("synthetic.ndjson").unwrap();
    for mib in [5, 50, 200] {
        for workers in [1, 4] {
            let prefix = mib * 1024 * 1024;
            let mut reader = Cursor::new(row)
                .chain(std::io::repeat(b' ').take(prefix))
                .chain(Cursor::new(row.repeat(2)));
            let mut output = Vec::new();
            let report = decode_json_source(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &source,
                        evidence_hash: [7; 32],
                        time_context: None,
                        cluster_context: None,
                        cancel: &cancel,
                    },
                    reader: &mut reader,
                },
                ParserIdentity {
                    name: "parser-synthetic",
                    version: "source-v1",
                },
                DecodeBudget::new(
                    std::num::NonZeroUsize::new(workers).unwrap(),
                    8 * 1024 * 1024,
                ),
                &|fields| {
                    Ok(DecodedSourceFrame {
                        fields,
                        timestamp: None,
                        format: SourceFormatV1::try_new(
                            "synthetic",
                            "v1",
                            std::collections::BTreeMap::new(),
                        )
                        .unwrap(),
                    })
                },
                &mut |row| {
                    row.inspect(|record| output.push(record.clone()));
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!((report.accepted, report.rejected), (2, 1));
            assert_eq!(output[0].annotations().members()[0].ordinal, 0);
            assert_eq!(output[1].annotations().members()[0].ordinal, 2);
            assert_eq!(
                output[1].origin().offset(),
                Some(prefix + 2 * row.len() as u64)
            );
            assert_eq!(
                output[1].fields().field("value").unwrap().as_text(),
                Some("synthetic")
            );
            assert!(report.samples.iter().all(|sample| sample.len() <= 256));
        }
    }
}
