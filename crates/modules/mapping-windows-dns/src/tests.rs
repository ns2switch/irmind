use super::*;
use irmind_app::{
    CancellationToken, ParserTimeBasis, ParserTimeContext, SourceDecoder,
    source_mapping::{DecodeBudget, DecodeInput, SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{CommonField, EntityRole, EventOutcome};
use irmind_mod_parser_windows_dns::WindowsDnsSourceDecoder;
use std::num::NonZeroUsize;

const TEXT: &[u8] = include_bytes!("../../../testkit/fixtures/parser-windows-dns/source/dns.log");

#[test]
fn responses_and_remote_packet_roles_match_at_one_and_four_workers() {
    let mapping = WindowsDnsMapping::new().unwrap();
    let source = SourceReferenceV1::file("dns.log").unwrap();
    let cancel = CancellationToken::new();
    let time = ParserTimeContext::new(2026, 0, false, ParserTimeBasis::Analyst).unwrap();
    let read = |workers| {
        let mut output = Vec::new();
        let report = WindowsDnsSourceDecoder
            .decode_with_budget(
                DecodeInput::Reader(SourceInput {
                    metadata: SourceMetadata {
                        source: &source,
                        evidence_hash: irmind_app::sha256(TEXT),
                        time_context: Some(&time),
                        cluster_context: None,
                        cancel: &cancel,
                    },
                    reader: &mut &TEXT[..],
                }),
                DecodeBudget::new(NonZeroUsize::new(workers).unwrap(), 64 * 1024 * 1024),
                &mut |record| {
                    record.inspect(|row| output.push(mapping.map(row).unwrap().into_record()));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!((report.accepted, report.rejected), (4, 0));
        output
    };
    let rows = read(1);
    assert_eq!(rows, read(4));
    for (index, outcome, role, ip) in [
        (0, EventOutcome::Unknown, EntityRole::Source, "203.0.113.77"),
        (
            1,
            EventOutcome::Success,
            EntityRole::Destination,
            "203.0.113.77",
        ),
        (
            2,
            EventOutcome::Failure,
            EntityRole::Destination,
            "2001:db8::57",
        ),
    ] {
        let event = &rows[index].common;
        assert_eq!(event.event().outcome(), outcome);
        assert!(
            event
                .observations()
                .values()
                .iter()
                .any(|reference| reference.role() == role && reference.entity().value() == ip)
        );
        assert_eq!(
            event.context().get(CommonField::DnsResponseCode).is_some(),
            index != 0
        );
    }
    assert!(rows[3].indexed.record.text.contains("TYPE65000"));
}
