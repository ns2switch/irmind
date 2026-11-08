use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder, StreamingEventParser,
    source_mapping::{SourceInput, SourceMetadata},
};
use irmind_domain::Tainted;

#[test]
fn compatibility_mapping_keeps_cloud_and_generic_lookup_identities_without_classification() {
    for data in [
        br#"{"eventTime":"2026-11-08T00:00:00Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","recipientAccountId":"111122223333","awsRegion":"eu-west-1","userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice","accountId":"111122223333"},"sourceIPAddress":"203.0.113.77","requestParameters":{"roleArn":"arn:aws:iam::111122223333:role/admin"}}"#.as_slice(),
        br#"{"eventTime":"2026-11-08T00:00:00Z","action":"original","host":"synthetic","user":"alice","source_ip":"203.0.113.77"}"#,
    ] {
        let cancel = CancellationToken::new();
        let hash = irmind_app::sha256(data);
        let mut legacy = Vec::new();
        irmind_mod_parser_json::JsonParser.parse_reader_report("input.json", &mut std::io::Cursor::new(data), hash, &cancel,
            &mut |r| { r.inspect(|record| legacy.push(record.clone())); Ok(()) }).unwrap();
        let mapper = JsonCompatibilityMapping::new().unwrap();
        let mut outputs = Vec::new();
        irmind_mod_parser_json::JsonSourceDecoder.decode_reader(SourceInput {
            metadata: SourceMetadata { source: &irmind_domain::SourceReferenceV1::file("input.json").unwrap(), evidence_hash: hash, time_context: None, cancel: &cancel },
            reader: &mut std::io::Cursor::new(data),
        }, &mut |source: Tainted<SourceRecordV1>| { source.inspect(|r| outputs.push(mapper.map(r).unwrap())); Ok(()) }).unwrap();
        assert_eq!(outputs.len(), legacy.len());
        for (output, expected) in outputs.iter().zip(&legacy) {
            let actual = &output.record().indexed.record;
            assert_eq!((&actual.entities, &actual.relations), (&expected.entities, &expected.relations));
            assert_eq!(actual.event, expected.event);
            assert_eq!(actual.text, expected.text);
            assert_eq!(output.record().common.event(), &irmind_domain::EventHeaderV1::default());
            assert!(output.record().common.observations().values().is_empty());
        }
    }
}

#[test]
fn build_identity_is_content_addressed_and_versioned_without_absolute_paths() {
    let mapping = JsonCompatibilityMapping::new().unwrap();
    let manifest = SourceMapper::manifest(&mapping);
    assert!(
        manifest
            .identity()
            .version()
            .ends_with(manifest.identity().implementation().as_str())
    );
    assert!(!BUILD.windows(6).any(|bytes| bytes == b"/home/"));
    assert!(!BUILD.windows(3).any(|bytes| bytes == b"C:\\"));
}
