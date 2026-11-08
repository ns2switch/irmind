use super::*;
#[path = "common_event_values.rs"]
mod values;

#[test]
fn typed_common_payload_and_new_envelopes_are_feature_independent() {
    let wire = include_str!("../../../app/src/common_event/goldens/network-v1.json").trim();
    let event = irmind_app::decode_common_event(wire).unwrap();
    assert_eq!(irmind_app::encode_common_event(&event).unwrap(), wire);
    for wire in [
        include_str!("../../../domain/tests/fixtures/common-artifact-events-v2.hex"),
        include_str!("../../../domain/tests/fixtures/common-artifact-entities-v2.hex"),
        include_str!("../../../domain/tests/fixtures/common-artifact-coobservations-v2.hex"),
    ] {
        assert_eq!(
            irmind_domain::ParquetArtifactV2::decode(wire.trim())
                .unwrap()
                .encode()
                .unwrap(),
            wire.trim()
        );
    }
}

#[test]
fn source_decoder_and_independent_mapping_contracts_are_feature_independent() {
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_json::JsonSourceDecoder),
        Arc::new(irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap()),
        "fixture.json",
        br#"{"eventTime":"2026-11-01T00:00:00Z","sourceIPAddress":"203.0.113.77"}"#,
        1,
    )
    .unwrap();
    #[cfg(feature = "parser-linux")]
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_linux::JournalSourceDecoder),
        Arc::new(irmind_mod_mapping_journald_compat::JournaldCompatibilityMapping::new().unwrap()),
        "fixture.json", br#"{"__REALTIME_TIMESTAMP":"1793102400123456","_HOSTNAME":"synthetic","MESSAGE":"example"}"#, 1,
    ).unwrap();
}

#[test]
fn common_parquet_physical_bytes_are_feature_independent() {
    let actual = physical_fixture();
    let expected: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(include_str!("../fixtures/formats-common-event-v1.json")).unwrap();
    assert_eq!(actual, expected);
}

#[test]
#[ignore = "manual generator for the new common physical fixture"]
fn regenerate_new_common_physical_goldens() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/formats-common-event-v1.json");
    fs::write(
        path,
        serde_json::to_string_pretty(&physical_fixture()).unwrap() + "\n",
    )
    .unwrap();
}

fn physical_fixture() -> BTreeMap<String, serde_json::Value> {
    use irmind_app::{LocalBatchRequest, PartitionLimits};
    let root = tempfile::tempdir().unwrap();
    let bytes = br#"{"Records":[{"eventTime":"2026-11-01T00:00:00.123456789Z","eventName":"Observe","sourceIPAddress":"203.0.113.77"},{"eventName":"Unknown","userIdentity":{"userName":"alice"}}]}"#;
    fs::write(root.path().join("synthetic.json"), bytes).unwrap();
    let catalog = Arc::new(
        irmind_app::source_mapping::MappingCatalog::freeze(
            vec![Arc::new(irmind_mod_parser_json::JsonSourceDecoder)],
            vec![Arc::new(StableMapping::new())],
        )
        .unwrap(),
    );
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let store = ParquetStore::open_mapped(root.path(), catalog).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let paths = ["synthetic.json".into()];
    let prepared = store
        .prepare_local_batch(
            LocalBatchRequest {
                case_id: &id,
                source_root: root.path(),
                relative_paths: &paths,
                copy_original: false,
                parser: &parser,
                committed_artifacts: &[],
                limits: PartitionLimits::default(),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    prepared
        .into_iter()
        .flat_map(|p| {
            let mut source = p.manifest;
            source.modified_unix_seconds = None;
            let manifest = irmind_domain::SourceManifestV2 {
                source,
                parser_id: "parser-json".into(),
                parser_version: "json-source-v1".into(),
                confidence: 90,
                selection: irmind_domain::ParserSelectionMode::Automatic,
                timestamp_context: None,
                rejected_records: p.parse_report.rejected,
                rejected_sample: p.parse_report.samples,
            };
            p.mapping.unwrap().bind(&manifest).unwrap().into_artifacts()
        })
        .map(|a| {
            (
                a.core().path.clone(),
                serde_json::json!({"size":a.core().size,
        "sha256":a.core().sha256.as_str(), "envelope":a.encode().unwrap()}),
            )
        })
        .collect()
}

// A fixed synthetic mapping identity isolates wire/physical goldens from the
// production build manifest, whose identity intentionally includes features.
struct StableMapping {
    manifest: irmind_app::source_mapping::MappingManifest,
    inner: irmind_mod_mapping_json_compat::JsonCompatibilityMapping,
}
impl StableMapping {
    fn new() -> Self {
        use irmind_app::{
            SourceMapper as _,
            source_mapping::{MappingManifest, MappingProvenance},
        };
        let inner = irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap();
        let content = b"synthetic-stable-physical-mapping-fixture-v1".to_vec();
        let identity = irmind_domain::MappingIdentityV1::try_new(
            "mapping-fixture",
            "1",
            irmind_domain::COMMON_EVENT_V1,
            irmind_domain::EvidenceHash::from_bytes(sha256(&content)),
        )
        .unwrap();
        Self {
            manifest: MappingManifest::try_new(
                identity,
                inner.manifest().selectors().to_vec(),
                MappingProvenance::NativeBuild { manifest: content },
                true,
            )
            .unwrap(),
            inner,
        }
    }
}
impl irmind_app::SourceMapper for StableMapping {
    fn manifest(&self) -> &irmind_app::source_mapping::MappingManifest {
        &self.manifest
    }
    fn map(
        &self,
        source: &irmind_domain::SourceRecordV1,
    ) -> Result<irmind_app::source_mapping::MappingOutput, irmind_app::source_mapping::MappingError>
    {
        irmind_app::SourceMapper::map(&self.inner, source)
    }
}
