#![no_main]
use irmind_app::{SignedEntry, sha256};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
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
