use super::*;
use std::cmp::Ordering;

const INDEX: &[u8] =
    include_bytes!("../../../../docs/development/catalog-format-vectors/index.json");

fn altered(change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(INDEX).unwrap();
    change(&mut value);
    // Do not rely on serde_json::Map ordering in tests either.
    let index: CatalogIndex = serde_json::from_value(value).unwrap();
    serde_json::to_vec(&index).unwrap()
}

#[test]
fn catalog_canonical_index_rejects_noncanonical_unknown_duplicate_and_oversized_data() {
    let index = CatalogIndex::decode_untrusted(INDEX).unwrap();
    assert_eq!(serde_json::to_vec(&index).unwrap(), INDEX);
    assert!(index.entries()[0].supports_version("0.5.0").unwrap());
    assert!(!index.entries()[0].supports_version("0.5.0-rc.1").unwrap());
    for bad in [
        [INDEX, b"\n"].concat(),
        [b" ", INDEX].concat(),
        [b"{\"unknown\":0,", &INDEX[1..]].concat(),
        [b"{\"format_version\":1,", &INDEX[1..]].concat(),
        vec![b' '; MAX_CATALOG_INDEX_BYTES + 1],
    ] {
        assert!(CatalogIndex::decode_untrusted(&bad).is_err());
    }
    for bad in [
        altered(|v| v["release_sequence"] = 0.into()),
        altered(|v| v["release_commit"] = "A".repeat(40).into()),
        altered(|v| v["entries"][0]["asset_bytes"] = (1024 * 1024 + 1).into()),
        altered(|v| v["entries"][0]["sources"] = serde_json::json!(["z", "a"])),
        altered(|v| v["entries"][0]["mappings"] = serde_json::json!(["a", "a"])),
        altered(|v| v["entries"][0]["coverage"]["description"] = "x".repeat(513).into()),
        altered(|v| v["entries"] = vec![v["entries"][0].clone(); 1025].into()),
    ] {
        assert!(CatalogIndex::decode_untrusted(&bad).is_err());
    }
}

#[test]
fn catalog_asset_names_never_become_paths_devices_or_case_insensitive_aliases() {
    for asset in [
        "../asset",
        "a/b",
        "a\\b",
        "/absolute",
        ".hidden",
        "x.",
        "a..b",
        "C:asset",
        "CON",
        "nul.txt",
        "COM1.zip",
        "LPT9",
        "a\n",
    ] {
        assert!(
            CatalogIndex::decode_untrusted(&altered(|v| {
                v["entries"][0]["asset"] = asset.into();
            }))
            .is_err(),
            "accepted {asset:?}"
        );
    }
    let duplicate = altered(|v| {
        let mut entry = v["entries"][0].clone();
        entry["name"] = "synthetic-z".into();
        entry["asset"] = "SYNTHETIC-TRIAGE-1.SKILL.JSON".into();
        v["entries"].as_array_mut().unwrap().push(entry);
    });
    assert!(CatalogIndex::decode_untrusted(&duplicate).is_err());
}

#[test]
fn catalog_prepass_bounds_nesting_and_aggregate_values_without_building_a_tree() {
    assert!(limits::check(b"{\"a\":[true,false,null,0,\"text\"]}").is_ok());
    let nested = format!("{}0{}", "[".repeat(10), "]".repeat(10));
    assert!(limits::check(nested.as_bytes()).is_err());
    let values = format!("[{}0]", "0,".repeat(100_000));
    assert!(limits::check(values.as_bytes()).is_err());
    assert!(limits::check(b"{\"a\":1.5}").is_err());
    assert!(limits::check(b"{}{}").is_err());
}

#[test]
fn catalog_release_tags_and_minimum_versions_follow_bounded_semver() {
    let ordered = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "2.0.0",
    ];
    for pair in ordered.windows(2) {
        assert_eq!(
            version::Version::parse(pair[0])
                .unwrap()
                .compare(&version::Version::parse(pair[1]).unwrap()),
            Ordering::Less
        );
    }
    assert_eq!(
        version::Version::parse("1.2.3+build.1")
            .unwrap()
            .compare(&version::Version::parse("1.2.3+build.2").unwrap()),
        Ordering::Equal
    );
    assert!(FrozenCatalogRelease::new("v1.2.3-rc.1").is_ok());
    for bad in [
        "1.2.3",
        "v01.2.3",
        "v1.2",
        "v1.2.3+build",
        "v1.2.3-01",
        "v1.2.3/extra",
        "v1.2.3\n",
    ] {
        assert!(FrozenCatalogRelease::new(bad).is_err(), "accepted {bad:?}");
    }
    for bad in ["1.2.03", "1.2.3+", "1.2.3-", "1.2.3-a..b", "１.2.3"] {
        assert!(version::Version::parse(bad).is_err());
    }
}

#[test]
fn catalog_digests_are_distinct_from_evidence_and_strictly_lowercase() {
    assert!(CatalogDigest::parse(&"a".repeat(64)).is_ok());
    assert!(CatalogDigest::parse(&"A".repeat(64)).is_err());
    assert!(CatalogProofId::parse("../proof").is_err());
    assert!(CatalogIndexBytes::new(Vec::new(), &[0; 64]).is_err());
}

#[test]
fn catalog_case_store_default_is_unavailable_without_global_fallback() {
    use crate::{AppError, CancellationToken};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct GlobalOnly(AtomicUsize);
    impl CatalogProofStore for GlobalOnly {
        fn publish(
            &self,
            _: &VerifiedCatalogIndex,
            _: &CancellationToken,
        ) -> Result<CatalogProofId, AppError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AppError::Storage("global method called".into()))
        }
        fn read(
            &self,
            _: &CatalogProofId,
            _: &CancellationToken,
        ) -> Result<CatalogIndexBytes, AppError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AppError::Storage("global method called".into()))
        }
    }
    let case = irmind_domain::CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap();
    let id = CatalogProofId::parse(&"a".repeat(64)).unwrap();
    let store = GlobalOnly(AtomicUsize::new(0));
    let result = store.read_for_case(&case, &id, &CancellationToken::new());
    assert!(result.err().unwrap().to_string().contains("unavailable"));
    assert_eq!(store.0.load(Ordering::SeqCst), 0);
}
