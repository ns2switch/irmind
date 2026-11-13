#![no_main]
use irmind_app::{SignedEntry, sha256};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    if let Ok(context) = irmind_domain::SourceClusterContext::decode(bytes) {
        let encoded = context.encode();
        assert_eq!(encoded, bytes);
        assert_eq!(
            irmind_domain::SourceClusterContext::decode(&encoded).unwrap(),
            context
        );
    }
    if let Ok(fields) = irmind_app::source_mapping::json::decode_json_fields(
        bytes,
        irmind_app::source_mapping::json::SourceJsonLimits::default(),
    ) {
        let rendered = irmind_app::source_mapping::json::render_source_fields(&fields).unwrap();
        let restored = irmind_app::source_mapping::json::decode_json_fields(
            rendered.as_bytes(),
            irmind_app::source_mapping::json::SourceJsonLimits::default(),
        )
        .unwrap();
        assert_eq!(fields, restored);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(manifest) = irmind_mapping_tables::TableMapping::review(text) {
            let mapping = irmind_mapping_tables::TableMapping::bundled(
                text,
                manifest.identity().implementation(),
            )
            .unwrap();
            assert_eq!(irmind_app::SourceMapper::manifest(&mapping), &manifest);
        }
        if let Ok(common) = irmind_app::decode_common_event(text) {
            let canonical = irmind_app::encode_common_event(&common).unwrap();
            assert_eq!(canonical, text);
            assert_eq!(irmind_app::decode_common_event(&canonical).unwrap(), common);
            assert!(irmind_app::decode_common_event(&(canonical + " ")).is_err());
        }
        if let Ok(inventory) = irmind_domain::SealInventoryV2::decode(text.trim()) {
            let wire = inventory.encode().unwrap();
            assert_eq!(
                irmind_domain::SealInventoryV2::decode(&wire).unwrap(),
                inventory
            );
            assert!(irmind_domain::SealInventoryV2::decode(&(wire + "00")).is_err());
        }
        for kind in [irmind_domain::AuditEventKind::ParquetArtifactV3] {
            if let Ok(artifact) = irmind_domain::ParquetArtifact::decode(kind, text.trim()) {
                let wire = artifact
                    .encode()
                    .expect("a validated artifact encodes canonically");
                assert_eq!(artifact.audit_kind(), kind);
                assert_eq!(
                    irmind_domain::ParquetArtifact::decode(kind, &wire).unwrap(),
                    artifact
                );
                assert!(irmind_domain::ParquetArtifact::decode(kind, &(wire + "00")).is_err());
            }
        }
        macro_rules! check_mapping_codec {
            ($type:ty) => {
                if let Ok(record) = <$type>::decode(text) {
                    let wire = record.encode().unwrap();
                    assert_eq!(wire, text);
                    assert!(<$type>::decode(&wire).unwrap() == record);
                    assert!(<$type>::decode(&(wire + "00")).is_err());
                }
            };
        }
        check_mapping_codec!(irmind_domain::SourceManifestV2);
        check_mapping_codec!(irmind_domain::SourceRecordSetV1);
        check_mapping_codec!(irmind_domain::MappingProfileRecordV1);
        check_mapping_codec!(irmind_domain::MappingRunV1);
        check_mapping_codec!(irmind_domain::ParquetLayoutV1);
        check_mapping_codec!(irmind_app::SkillSnapshotV1);
        check_mapping_codec!(irmind_app::SkillLoadV1);
        if let Ok(irmind_domain::MappingProfileRecordV1::Snapshot(snapshot)) =
            irmind_domain::MappingProfileRecordV1::decode(text)
        {
            if let Ok(manifest) =
                irmind_app::source_mapping::MappingManifest::from_snapshot(&snapshot)
            {
                assert!(manifest.snapshot().unwrap() == snapshot);
            }
        }
        for parsed in [
            irmind_app::IndexedTime::from_rfc3339(text, false),
            irmind_app::IndexedTime::from_epoch_decimal(text, false),
        ]
        .into_iter()
        .flatten()
        {
            let restored =
                irmind_app::IndexedTime::from_rfc3339(&parsed.to_rfc3339(), false).unwrap();
            assert_eq!(restored, parsed);
        }
    }
    if let Ok(entry) = serde_json::from_slice::<SignedEntry>(bytes) {
        let first = entry.canonical();
        let second = entry.canonical();
        assert_eq!(first, second);
        assert_eq!(sha256(&first), sha256(&second));
        let mut changed = entry;
        changed.payload.push('\0');
        let different = changed.canonical();
        assert_ne!(first, different);
        assert_ne!(sha256(&first), sha256(&different));
    }
});
