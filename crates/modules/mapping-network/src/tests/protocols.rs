use super::*;

fn one(parser: &'static str, payload: &str) -> SourceRecordV1 {
    let (decoder, bytes): (Arc<dyn SourceDecoder>, Vec<u8>) = if parser == "parser-zeek" {
        (
            Arc::new(irmind_mod_parser_zeek::ZeekSourceDecoder),
            format!("{{\"ts\":1790000000.123456,\"uid\":\"Csynthetic\",{payload}}}\n").into_bytes(),
        )
    } else {
        (
            Arc::new(irmind_mod_parser_suricata::SuricataSourceDecoder),
            format!("{{\"timestamp\":\"2026-11-01T00:00:00.123456Z\",\"flow_id\":42,{payload}}}\n")
                .into_bytes(),
        )
    };
    let fixture = Fixture {
        parser,
        name: "synthetic.jsonl",
        bytes: b"",
        decoder,
    };
    let (report, mut records) = decoded(&fixture, &bytes);
    assert_eq!((report.accepted, report.rejected), (1, 0));
    records.remove(0)
}
#[test]
fn same_address_keeps_source_and_destination_occurrences_without_process_inference() {
    let source = one(
        "parser-zeek",
        r#""id.orig_h":"203.0.113.77","id.resp_h":"203.0.113.77","pid":123,"user":"unmapped""#,
    );
    let out = NetworkMapping::new("parser-zeek")
        .unwrap()
        .map(&source)
        .unwrap();
    let obs = out.record().common.observations().values();
    let src = obs.iter().find(|o| o.role() == EntityRole::Source).unwrap();
    let dst = obs
        .iter()
        .find(|o| o.role() == EntityRole::Destination)
        .unwrap();
    assert_eq!(src.entity(), dst.entity());
    assert_ne!(src.field(), dst.field());
    assert!(
        !obs.iter()
            .any(|o| o.entity().kind() == irmind_domain::ObservedEntityKind::Process)
    );
}
#[test]
fn explicit_http_status_has_success_failure_and_missing_outcomes_for_both_sources() {
    for parser in ["parser-zeek", "parser-suricata"] {
        let mapper = NetworkMapping::new(parser).unwrap();
        for (status, outcome) in [
            (Some(200), EventOutcome::Success),
            (Some(403), EventOutcome::Failure),
            (None, EventOutcome::Unknown),
        ] {
            let payload = if parser == "parser-zeek" {
                format!(
                    "\"method\":\"GET\",\"uri\":\"/synthetic\"{}",
                    status.map_or_else(String::new, |s| format!(",\"status_code\":{s}"))
                )
            } else {
                format!(
                    "\"event_type\":\"http\",\"http\":{{\"http_method\":\"GET\"{}}}",
                    status.map_or_else(String::new, |s| format!(",\"status\":{s}"))
                )
            };
            let out = mapper.map(&one(parser, &payload)).unwrap();
            assert_eq!(out.record().common.event().outcome(), outcome);
            assert!(
                out.record()
                    .common
                    .event()
                    .categories()
                    .contains(EventCategory::Web)
            );
            assert_eq!(
                out.record()
                    .common
                    .context()
                    .get(CommonField::NetworkProtocol),
                Some(&irmind_domain::CommonValue::Text(
                    irmind_domain::EventText::new("http").unwrap()
                ))
            );
        }
    }
}
#[test]
fn dns_tls_and_source_alerts_do_not_imply_confirmed_compromise() {
    for (parser, payload, protocol, outcome, alert) in [
        (
            "parser-zeek",
            r#""query":"synthetic.example.test","rcode":3"#,
            "dns",
            EventOutcome::Failure,
            false,
        ),
        (
            "parser-suricata",
            r#""event_type":"dns","dns":{"rrname":"synthetic.example.test","rcode":"NOERROR"}"#,
            "dns",
            EventOutcome::Success,
            false,
        ),
        (
            "parser-zeek",
            r#""server_name":"synthetic.example.test","established":true"#,
            "tls",
            EventOutcome::Success,
            false,
        ),
        (
            "parser-suricata",
            r#""event_type":"tls","tls":{"sni":"synthetic.example.test"}"#,
            "tls",
            EventOutcome::Unknown,
            false,
        ),
        (
            "parser-suricata",
            r#""event_type":"alert","alert":{"signature":"Synthetic rule","signature_id":42,"action":"allowed","severity":1}"#,
            "",
            EventOutcome::Unknown,
            true,
        ),
    ] {
        let out = NetworkMapping::new(parser)
            .unwrap()
            .map(&one(parser, payload))
            .unwrap();
        assert_eq!(out.record().common.event().outcome(), outcome);
        if alert {
            assert_eq!(out.record().common.event().kind(), EventKind::Alert);
        } else {
            assert_eq!(
                out.record()
                    .common
                    .context()
                    .get(CommonField::NetworkProtocol),
                Some(&irmind_domain::CommonValue::Text(
                    irmind_domain::EventText::new(protocol).unwrap()
                ))
            );
        }
    }
}

#[test]
fn suricata_v3_question_is_typed_and_multiple_questions_keep_explicit_coverage() {
    let source = one(
        "parser-suricata",
        r#""event_type":"dns","dns":{"version":3,"type":"answer","rcode":"NOERROR","queries":[{"rrname":"one.example.test","rrtype":"A"},{"rrname":"two.example.test","rrtype":"AAAA"}]}"#,
    );
    let out = NetworkMapping::new("parser-suricata")
        .unwrap()
        .map(&source)
        .unwrap();
    assert_eq!(out.record().common.event().outcome(), EventOutcome::Success);
    assert_eq!(
        out.record()
            .common
            .context()
            .get(CommonField::DnsQuestionName),
        Some(&irmind_domain::CommonValue::Text(
            irmind_domain::EventText::new("one.example.test").unwrap()
        ))
    );
    assert!(
        out.diagnostics()
            .contains(&irmind_app::source_mapping::MappingDiagnostic::UnsupportedValue)
    );
    assert!(
        out.record()
            .indexed
            .record
            .text
            .contains("two.example.test")
    );
}
#[test]
fn declared_dataset_cannot_be_overridden_by_an_unrelated_embedded_field() {
    let source = one(
        "parser-zeek",
        r#""_path":"conn","id.orig_h":"203.0.113.77","query":"injected.example.test","server_name":"injected.example.test""#,
    );
    let out = NetworkMapping::new("parser-zeek")
        .unwrap()
        .map(&source)
        .unwrap();
    assert!(
        out.record()
            .common
            .event()
            .types()
            .contains(irmind_domain::EventType::Connection)
    );
    assert!(
        out.record()
            .common
            .context()
            .get(CommonField::DnsQuestionName)
            .is_none()
    );
    assert!(
        out.record()
            .common
            .context()
            .get(CommonField::DestinationDomain)
            .is_none()
    );
    let source = one(
        "parser-zeek",
        r#""_path":"unrecognized","id.orig_h":"203.0.113.77""#,
    );
    let out = NetworkMapping::new("parser-zeek")
        .unwrap()
        .map(&source)
        .unwrap();
    assert_eq!(out.record().common.event().categories().bits(), 0);
}

#[test]
fn tsv_http_status_conversion_matches_json_without_changing_the_original_fields() {
    let bytes=b"#separator \\x09\n#path\thttp\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tmethod\turi\tstatus_code\n#types\ttime\tstring\taddr\taddr\tstring\tstring\tcount\n1790000000.123456\tCsynthetic\t203.0.113.77\t198.51.100.10\tGET\t/\t200\n1790000001.123456\tCsynthetic\t203.0.113.77\t198.51.100.10\tGET\t/\t403\n1790000002.123456\tCsynthetic\t203.0.113.77\t198.51.100.10\tGET\t/\t-\n";
    let f = Fixture {
        parser: "parser-zeek",
        name: "http.log",
        bytes,
        decoder: Arc::new(irmind_mod_parser_zeek::ZeekSourceDecoder),
    };
    let (report, rows) = decoded(&f, bytes);
    assert_eq!((report.accepted, report.rejected), (3, 0));
    let mapper = NetworkMapping::new("parser-zeek").unwrap();
    for (source, outcome) in rows.iter().zip([
        EventOutcome::Success,
        EventOutcome::Failure,
        EventOutcome::Unknown,
    ]) {
        let out = mapper.map(source).unwrap();
        assert_eq!(out.record().common.event().outcome(), outcome);
        assert!(source.fields().field("types").is_some());
        assert_eq!(out.record().common.origin(), source.origin());
    }
}

#[test]
fn tls_without_sni_and_ambiguous_json_have_conservative_coverage() {
    let mapper = NetworkMapping::new("parser-zeek").unwrap();
    let out = mapper
        .map(&one(
            "parser-zeek",
            r#""id.orig_h":"203.0.113.77","established":true"#,
        ))
        .unwrap();
    assert_eq!(out.record().common.event().outcome(), EventOutcome::Success);
    assert_eq!(
        out.record()
            .common
            .context()
            .get(CommonField::NetworkProtocol),
        Some(&irmind_domain::CommonValue::Text(
            irmind_domain::EventText::new("tls").unwrap()
        ))
    );
    let out = mapper
        .map(&one(
            "parser-zeek",
            r#""query":"synthetic.example.test","method":"GET""#,
        ))
        .unwrap();
    assert_eq!(out.record().common.event().categories().bits(), 0);
    assert!(
        out.diagnostics()
            .contains(&irmind_app::source_mapping::MappingDiagnostic::Unclassified)
    );
}
