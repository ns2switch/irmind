#![allow(clippy::unwrap_used)]
use super::*;
use irmind_domain::{Actor, ParserSelectionMode};

fn entry(kind: AuditEventKind, payload: String) -> SignedEntry {
    SignedEntry {
        seq: 1,
        case_id: "11111111-1111-1111-1111-111111111111".into(),
        at: 0,
        actor: Actor::Analyst,
        origin: "system".into(),
        kind,
        payload,
        evidence: None,
        prev: [0; 32],
        hash: [0; 32],
        sig: Vec::new(),
        public_key: Vec::new(),
    }
}

fn source(version: &str, size: u64) -> SignedEntry {
    let manifest = SourceManifestV2 {
        source: SourceManifestV1 {
            source: "synthetic.json".into(),
            size,
            modified_unix_seconds: None,
            version: None,
            provider_checksum: None,
            sha256: EvidenceHash::parse(&"a".repeat(64)).unwrap(),
            copied: false,
        },
        parser_id: "parser-json".into(),
        parser_version: version.into(),
        confidence: 90,
        selection: ParserSelectionMode::Automatic,
        timestamp_context: None,
        rejected_records: 0,
        rejected_sample: Vec::new(),
    };
    entry(AuditEventKind::SourceManifestV2, manifest.encode().unwrap())
}

#[test]
fn only_affected_versions_over_the_signed_size_threshold_warn() {
    let versions = [
        "json-stream-v2",
        "ecs-ndjson-v1",
        "ocsf-stream-v1",
        "velociraptor-json-v1",
        "hayabusa-json-csv-v1",
        "chainsaw-json-v1",
        "plaso-json-v1",
        "declarative-v1",
    ];
    for version in versions {
        for size in [1, LARGE_FIRST_LINE, LARGE_FIRST_LINE + 1] {
            assert_eq!(
                parser_extraction_warning(&[source(version, size)])
                    .unwrap()
                    .is_some(),
                size > LARGE_FIRST_LINE,
                "{version}: {size}"
            );
        }
    }
    for version in [
        "json-stream-v3",
        "ecs-ndjson-v2",
        "ocsf-stream-v2",
        "linux-stream-v1",
        "json-stream-v20",
    ] {
        assert!(
            parser_extraction_warning(&[source(version, LARGE_FIRST_LINE + 1)])
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn hashed_declarative_and_compacted_versions_keep_the_warning() {
    let declarative = format!("declarative-v1:sha256={}", "b".repeat(64));
    for version in [declarative.as_str(), "json-stream-v2+compact-v1"] {
        assert!(
            parser_extraction_warning(&[source(version, LARGE_FIRST_LINE + 1)])
                .unwrap()
                .is_some()
        );
    }
    assert!(!affected_version("declarative-v1:sha256=invalid"));
    assert!(!affected_version(&declarative.replace("v1:", "v2:")));
}

#[test]
fn unknown_original_size_warns_but_a_signed_small_size_suppresses_it() {
    let mut indexed = entry(AuditEventKind::GraphIndexed, "legacy graph".into());
    indexed.evidence = Some("a".repeat(64));
    assert!(
        parser_extraction_warning(std::slice::from_ref(&indexed))
            .unwrap()
            .is_some()
    );
    assert!(
        parser_extraction_warning(&[indexed.clone(), source("json-stream-v2", LARGE_FIRST_LINE)])
            .unwrap()
            .is_none()
    );
    let large = source("json-stream-v2", LARGE_FIRST_LINE + 1);
    let warning = parser_extraction_warning(&[indexed, large.clone(), large])
        .unwrap()
        .unwrap()
        .to_string();
    assert!(warning.contains("1 source used"));
    assert!(warning.contains("chain is valid"));
    assert!(warning.contains("Create a new case"));
    assert!(warning.contains("CHANGELOG.md#known-issue-fixed"));
    assert!(warning.contains("docs/parsers.md#current-readers-and-existing-cases"));
    assert!(!warning.contains("synthetic.json"));
}

#[test]
fn malformed_metadata_is_not_silently_ignored() {
    assert!(
        parser_extraction_warning(&[entry(AuditEventKind::SourceManifestV2, "invalid".into())])
            .is_err()
    );
}

#[test]
fn v1_source_sizes_and_artifact_fallback_use_original_not_parquet_size() {
    let old =
        SourceManifestV2::decode(&source("json-stream-v2", LARGE_FIRST_LINE).payload).unwrap();
    let small = entry(
        AuditEventKind::SourceManifestV1,
        old.source.encode().unwrap(),
    );
    assert!(
        parser_extraction_warning(std::slice::from_ref(&small))
            .unwrap()
            .is_none()
    );
    let artifact = irmind_domain::ParquetArtifactV1 {
        path: "date=2026-11-01/account=unknown/region=unknown/old.parquet".into(),
        size: 1,
        sha256: EvidenceHash::parse(&"b".repeat(64)).unwrap(),
        parser_version: "json-stream-v2+compact-v1".into(),
        schema_version: "irmind-events-v2".into(),
        partition_date: "2026-11-01".into(),
        partition_account: "unknown".into(),
        partition_region: "unknown".into(),
        source_hashes: vec![old.source.sha256.clone()],
    };
    let artifact = entry(
        AuditEventKind::ParquetArtifactV1,
        artifact.encode().unwrap(),
    );
    assert!(
        parser_extraction_warning(std::slice::from_ref(&artifact))
            .unwrap()
            .is_some()
    );
    assert!(
        parser_extraction_warning(&[artifact, small])
            .unwrap()
            .is_none()
    );
    let mut large = old.source;
    large.size += 1;
    assert!(
        parser_extraction_warning(&[entry(
            AuditEventKind::SourceManifestV1,
            large.encode().unwrap()
        )])
        .unwrap()
        .is_some()
    );
}
