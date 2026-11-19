#![allow(clippy::unwrap_used)]
use super::{TableMapping, tests::mapper};
use irmind_app::{
    SourceMapper,
    source_mapping::{
        DecodeAnnotationsV1, SourceFormatV1, SourceNumber, SourceRecordV1, SourceValue,
    },
};
use irmind_domain::{EntityIdentityScope, EventOrigin, EvidenceHash};
use std::collections::BTreeMap;
const TENANT: &str = "00000000000000000000000000000001";
const HOST: &str = "00000000000000000000000000000100";
const DEF: &str = r#"interpreter = "irmind-mapping-tables-v2"
id = "mapping-synthetic-provider-process"
version = "1"
target_schema = "irmind-common-event-v1"
source_contract = "irmind-source-record-v1"
parser = "parser-fdr"
parser_versions = ["fdr-source-v1"]
format = "falcon-fdr"
format_version = "fdr-source-v1"
[partition]
host = ["aid"]
[[fields]]
source = ["aid"]
target = "host.id"
[[fields]]
source = ["TargetProcessId"]
target = "process.entity_id"
conversion = "u64_id"
observation = { kind = "process", role = "subject", scope = { kind = "provider_process", path = { provider = "crowdstrike-fdr", tenant = ["cid"], host = ["aid"] } } }
"#;
fn source(tenant: &str, host: &str, id: SourceValue, event: &str) -> SourceRecordV1 {
    SourceRecordV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([4; 32]),
            0,
            Some(0),
            "parser-fdr",
            "fdr-source-v1",
        )
        .unwrap(),
        "synthetic.ndjson",
        None,
        SourceFormatV1::try_new("falcon-fdr", "fdr-source-v1", BTreeMap::new()).unwrap(),
        SourceValue::object(vec![
            ("cid".into(), SourceValue::Text(tenant.into())),
            ("aid".into(), SourceValue::Text(host.into())),
            ("TargetProcessId".into(), id),
            ("event_simpleName".into(), SourceValue::Text(event.into())),
        ])
        .unwrap(),
        DecodeAnnotationsV1::default(),
    )
    .unwrap()
}
#[test]
fn provider_process_native_id_conversion_and_scope_follow_contract() {
    let mapping = mapper(DEF);
    for (input, expected) in [
        (SourceValue::Text("00042".into()), "42"),
        (
            SourceValue::Number(SourceNumber::try_new("42").unwrap()),
            "42",
        ),
        (
            SourceValue::Text("18446744073709551615".into()),
            "18446744073709551615",
        ),
    ] {
        let output = mapping
            .map(&source(TENANT, HOST, input, "ProcessRollup2"))
            .unwrap();
        let entity = output.record().common.observations().values()[0].entity();
        assert_eq!(entity.value(), expected);
        assert!(matches!(
            entity.scope(),
            EntityIdentityScope::ProviderProcess { .. }
        ));
    }
    for invalid in ["0", "-1", "1.5", "1e3", "18446744073709551616", "", " 42"] {
        assert!(
            mapping
                .map(&source(
                    TENANT,
                    HOST,
                    SourceValue::Text(invalid.into()),
                    "ProcessRollup2"
                ))
                .is_err()
        );
    }
    for invalid in [
        SourceValue::Boolean(true),
        SourceValue::Null,
        SourceValue::Number(SourceNumber::try_new("1.5").unwrap()),
    ] {
        assert!(
            mapping
                .map(&source(TENANT, HOST, invalid, "ProcessRollup2"))
                .is_err()
        );
    }
    assert!(
        mapping
            .map(&source(
                "bad-tenant",
                HOST,
                SourceValue::Text("42".into()),
                "ProcessRollup2"
            ))
            .is_err()
    );
    assert!(
        mapping
            .map(&source(
                TENANT,
                HOST,
                SourceValue::Text("42".into()),
                "UnknownEvent"
            ))
            .is_err()
    );
}
#[test]
fn provider_process_compiler_rejects_other_sources_fields_paths_and_providers() {
    for altered in [
        DEF.replace("parser-fdr", "parser-json"),
        DEF.replace("fdr-source-v1", "fdr-source-v2"),
        DEF.replace("falcon-fdr", "other-format"),
        DEF.replace("crowdstrike-fdr", "other-provider"),
        DEF.replace("TargetProcessId", "RawProcessId"),
        DEF.replace("process.entity_id", "process.pid"),
        DEF.replace("tenant = [\"cid\"]", "tenant = [\"other\"]"),
        DEF.replace("host = [\"aid\"]", "host = [\"other\"]"),
        DEF.replace("u64_id", "copy"),
    ] {
        assert!(TableMapping::review(&altered).is_err());
    }
}

#[test]
fn provider_process_null_or_missing_id_never_becomes_an_unscoped_observation() {
    let mapping = mapper(DEF);
    let original = source(TENANT, HOST, SourceValue::Null, "ProcessRollup2");
    assert!(mapping.map(&original).is_err());
    let fields = SourceValue::object(vec![
        ("cid".into(), SourceValue::Text(TENANT.into())),
        ("aid".into(), SourceValue::Text(HOST.into())),
        (
            "event_simpleName".into(),
            SourceValue::Text("ProcessRollup2".into()),
        ),
    ])
    .unwrap();
    let missing = SourceRecordV1::try_new(
        original.origin().clone(),
        "synthetic.ndjson",
        None,
        original.format().clone(),
        fields,
        DecodeAnnotationsV1::default(),
    )
    .unwrap();
    assert!(mapping.map(&missing).is_err());
}
