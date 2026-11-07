#![no_main]
use irmind_app::{SignedEntry, sha256};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
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
        if let Ok(migration) = irmind_domain::ParquetMigrationV1::decode(text.trim()) {
            let wire = migration.encode().unwrap();
            assert_eq!(
                irmind_domain::ParquetMigrationV1::decode(&wire).unwrap(),
                migration
            );
            assert!(irmind_domain::ParquetMigrationV1::decode(&(wire + "00")).is_err());
        }
        for kind in [
            irmind_domain::AuditEventKind::ParquetArtifactV1,
            irmind_domain::AuditEventKind::ParquetArtifactV2,
        ] {
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
