use super::*;
use irmind_app::source_mapping::{
    SourceFormatV1, SourceRecordV1,
    json::{SourceJsonLimits, decode_json_fields},
};
use irmind_domain::{
    CommonField as F, EntityIdentityScope, EntityRole, EventOrigin, EventOutcome, IndexedTime,
    SourceDiscriminator,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn sources(name: &str) -> Vec<SourceRecordV1> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testkit/fixtures/mapping-evtx/protocol");
    std::fs::read_to_string(root.join(format!("{name}.jsonl")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|frame| frame["kind"] == "record")
        .enumerate()
        .map(|(ordinal, frame)| source(ordinal as u64, &frame["event"]))
        .collect()
}
fn source(ordinal: u64, original: &Value) -> SourceRecordV1 {
    let system = &original["Event"]["System"];
    let provider = system["Provider"]["#attributes"]["Name"].as_str().unwrap();
    let channel = system["Channel"].as_str().unwrap();
    let id = system["EventID"].get("#text").unwrap_or(&system["EventID"]);
    SourceRecordV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([7; 32]),
            ordinal,
            Some(4608),
            "parser-evtx",
            "evtx-source-v1",
        )
        .unwrap(),
        "synthetic.evtx",
        Some(IndexedTime::from_rfc3339("2026-11-01T00:00:00.1234567Z", false).unwrap()),
        SourceFormatV1::try_new(
            "evtx",
            "evtx-source-v1",
            BTreeMap::from([
                (SourceDiscriminator::Provider, provider.into()),
                (SourceDiscriminator::Channel, channel.into()),
                (
                    SourceDiscriminator::RecordType,
                    id.as_str().map_or_else(|| id.to_string(), str::to_owned),
                ),
            ]),
        )
        .unwrap(),
        decode_json_fields(
            &serde_json::to_vec(&original).unwrap(),
            SourceJsonLimits::default(),
        )
        .unwrap(),
        irmind_domain::DecodeAnnotationsV1::default(),
    )
    .unwrap()
}
fn original(source: &SourceRecordV1) -> Value {
    serde_json::from_str(
        &irmind_app::source_mapping::json::render_source_fields(source.fields()).unwrap(),
    )
    .unwrap()
}
#[test]
fn pinned_tables_cover_every_requested_id_and_preserve_original_data() {
    for (name, mapper, count) in [
        (
            "system",
            Box::new(SystemMapping::new().unwrap()) as Box<dyn SourceMapper>,
            1,
        ),
        ("powershell", Box::new(PowerShellMapping::new().unwrap()), 2),
        ("sysmon", Box::new(SysmonMapping::new().unwrap()), 5),
    ] {
        assert_eq!(sources(name).len(), count);
        for source in sources(name) {
            let out = mapper.map(&source).unwrap();
            assert!(out.record().common.event().categories().bits() != 0);
            assert_eq!(out.record().common.origin(), source.origin());
            assert_eq!(out.record().common.timestamp(), source.timestamp());
            assert!(
                out.record()
                    .indexed
                    .record
                    .text
                    .contains("synthetic-endpoint")
            );
        }
    }
    for (source, &id) in sources("security").iter().zip(SecurityMapping::EVENT_IDS) {
        let out = SecurityMapping::new(id).unwrap().map(source).unwrap();
        assert_ne!(out.record().common.event().categories().bits(), 0);
        assert_eq!(out.record().common.origin(), source.origin());
    }
}
#[test]
fn windows_authentication_failure_keeps_actor_target_and_source_ip_distinct() {
    let source = sources("security").remove(1);
    let output = SecurityMapping::new(4625).unwrap().map(&source).unwrap();
    let common = &output.record().common;
    assert_eq!(common.event().outcome(), EventOutcome::Failure);
    for (field, role, value) in [
        (F::UserName, EntityRole::Actor, "operator"),
        (F::UserTargetName, EntityRole::Target, "alice"),
        (F::SourceIp, EntityRole::Source, "203.0.113.77"),
    ] {
        assert!(
            common
                .observations()
                .values()
                .iter()
                .any(|o| o.field() == field && o.role() == role && o.entity().value() == value)
        );
    }
}
#[test]
fn missing_audit_state_is_unknown_and_no_network_address_is_invented() {
    let mapper = SecurityMapping::new(4776).unwrap();
    for (keyword, outcome) in [
        (None, EventOutcome::Unknown),
        (Some("0x8010000000000000"), EventOutcome::Failure),
        (Some("0x8020000000000000"), EventOutcome::Success),
    ] {
        let mut raw = original(sources("security").last().unwrap());
        if let Some(keyword) = keyword {
            raw["Event"]["System"]["Keywords"] = json!(keyword);
        }
        let out = mapper.map(&source(0, &raw)).unwrap();
        assert_eq!(out.record().common.event().outcome(), outcome);
        assert!(out.record().common.context().get(F::SourceIp).is_none());
    }
}
#[test]
fn documented_dash_markers_omit_only_projected_values() {
    let mut raw = original(&sources("security")[1]);
    for key in [
        "SubjectUserName",
        "SubjectUserSid",
        "SubjectDomainName",
        "TargetUserName",
        "TargetUserSid",
        "TargetDomainName",
        "IpAddress",
        "IpPort",
    ] {
        raw["Event"]["EventData"][key] = json!("-");
    }
    let out = SecurityMapping::new(4625)
        .unwrap()
        .map(&source(0, &raw))
        .unwrap();
    assert!(
        out.record()
            .common
            .observations()
            .values()
            .iter()
            .all(|o| o.entity().value() != "-")
    );
    assert!(
        out.record()
            .common
            .context()
            .get(F::UserTargetName)
            .is_none()
    );
    assert!(out.record().indexed.record.text.contains("TargetUserName"));
}

#[test]
fn provider_channel_and_unlisted_ids_do_not_infer_classification() {
    let mapper = SecurityMapping::new(4625).unwrap();
    let mut raw = original(&sources("security")[1]);
    raw["Event"]["System"]["Provider"]["#attributes"]["Name"] = json!("Unrelated-Provider");
    assert!(mapper.map(&source(0, &raw)).is_err());
    let mut raw = original(&sources("security")[1]);
    raw["Event"]["System"]["EventID"] = json!("9999");
    assert!(mapper.map(&source(0, &raw)).is_err());
}

#[test]
fn event_id_scalar_types_and_xml_qualifiers_have_identical_classification() {
    for (name, mapper) in [
        (
            "security",
            Box::new(SecurityMapping::new(4624).unwrap()) as Box<dyn SourceMapper>,
        ),
        ("system", Box::new(SystemMapping::new().unwrap())),
        ("powershell", Box::new(PowerShellMapping::new().unwrap())),
        ("sysmon", Box::new(SysmonMapping::new().unwrap())),
    ] {
        let original = original(&sources(name)[0]);
        let id: u16 = original["Event"]["System"]["EventID"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let first = mapper.map(&source(0, &original)).unwrap();
        for scalar in [
            json!(id),
            json!({"#attributes":{"Qualifiers":0},"#text":id}),
            json!({"#attributes":{"Qualifiers":"0"},"#text":id.to_string()}),
        ] {
            let mut raw = original.clone();
            raw["Event"]["System"]["EventID"] = scalar;
            let next = mapper.map(&source(0, &raw)).unwrap();
            assert_eq!(first.record().common.event(), next.record().common.event());
        }
    }
}
#[test]
fn reported_status_precedes_audit_keyword_fallback_and_missing_stays_unknown() {
    for id in [4768, 4769, 4776] {
        let mapper = SecurityMapping::new(id).unwrap();
        let fixture = sources("security").remove(
            SecurityMapping::EVENT_IDS
                .iter()
                .position(|n| *n == id)
                .unwrap(),
        );
        for (status, outcome) in [
            (Some("0x0"), EventOutcome::Success),
            (
                Some(if id == 4768 {
                    "0x6"
                } else if id == 4769 {
                    "0x7"
                } else {
                    "0xc000006a"
                }),
                EventOutcome::Failure,
            ),
            (None, EventOutcome::Unknown),
        ] {
            let mut raw = original(&fixture);
            if let Some(status) = status {
                raw["Event"]["EventData"]["Status"] = json!(status);
            }
            assert_eq!(
                mapper
                    .map(&source(0, &raw))
                    .unwrap()
                    .record()
                    .common
                    .event()
                    .outcome(),
                outcome
            );
        }
    }
}

mod identities;
