use std::fmt::Write as _;
mod bounds;
mod fixtures;
mod layout;
mod lineage;
mod run;
use super::*;
use crate::{COMMON_EVENT_V1, MappingIdentityV1, SourceReferenceV1};

fn source() -> SourceRecordSetV1 {
    SourceRecordSetV1::from_manifest(
        &source_manifest(),
        SourceReferenceV1::file("logs/synthetic.json").unwrap(),
        vec![SourceFormatIdentityV1::try_new("json", "source-json-v1").unwrap()],
        2,
        EvidenceHash::parse(&"b".repeat(64)).unwrap(),
    )
    .unwrap()
}
fn source_manifest() -> crate::SourceManifestV2 {
    crate::SourceManifestV2 {
        source: crate::SourceManifestV1 {
            source: "logs/synthetic.json".into(),
            size: 4200,
            modified_unix_seconds: None,
            version: None,
            provider_checksum: None,
            sha256: EvidenceHash::parse(&"a".repeat(64)).unwrap(),
            copied: false,
        },
        parser_id: "parser-json".into(),
        parser_version: "json-source-v1".into(),
        confidence: 90,
        selection: crate::ParserSelectionMode::Automatic,
        timestamp_context: Some("normalized-utc".into()),
        cluster_context: None,
        rejected_records: 1,
        rejected_sample: vec![],
    }
}

fn snapshot() -> MappingSnapshotV1 {
    MappingSnapshotV1::try_new(
        MappingIdentityV1::try_new(
            "mapping-example",
            "1",
            COMMON_EVENT_V1,
            EvidenceHash::parse(&"c".repeat(64)).unwrap(),
        )
        .unwrap(),
        "{\"contract\":\"synthetic\",\"selectors\":[]}".into(),
    )
    .unwrap()
}

#[test]
fn acyclic_source_set_snapshot_and_profile_bytes_are_frozen_separately() {
    let set = source();
    assert_eq!(
        set.encode().unwrap(),
        include_str!("goldens/source-set-v1.hex").trim()
    );
    assert_eq!(
        SourceRecordSetV1::decode(&set.encode().unwrap()).unwrap(),
        set
    );
    let snapshot = snapshot();
    assert_eq!(
        snapshot.encode().unwrap(),
        include_str!("goldens/snapshot-v1.hex").trim()
    );
    let profile = MappingProfileV1::try_new(
        vec![MappingInputRefV1::from_set(&set).unwrap()],
        vec![snapshot.reference().unwrap()],
    )
    .unwrap();
    assert_eq!(
        profile.encode().unwrap(),
        include_str!("goldens/profile-v1.hex").trim()
    );
    assert_eq!(
        MappingProfileV1::decode(&profile.encode().unwrap()).unwrap(),
        profile
    );
    for payload in [snapshot.encode().unwrap(), profile.encode().unwrap()] {
        assert_eq!(
            MappingProfileRecordV1::decode(&payload)
                .unwrap()
                .encode()
                .unwrap(),
            payload
        );
        assert!(SourceRecordSetV1::decode(&payload).is_err());
    }
}

#[test]
fn profiles_reject_duplicate_sources_catalog_ids_and_noncanonical_payloads() {
    let input = MappingInputRefV1::from_set(&source()).unwrap();
    let snapshot = snapshot().reference().unwrap();
    assert!(MappingProfileV1::try_new(vec![input.clone(), input.clone()], vec![]).is_err());
    assert!(
        MappingProfileV1::try_new(vec![input.clone()], vec![snapshot.clone(), snapshot]).is_err()
    );
    let profile = MappingProfileV1::try_new(vec![input], vec![]).unwrap();
    let encoded = profile.encode().unwrap();
    assert!(MappingProfileV1::decode(&(encoded.clone() + "00")).is_err());
    assert!(MappingProfileV1::decode(&encoded.to_ascii_uppercase()).is_err());
    assert!(
        MappingInputRefV1::try_new(source().source().clone(), source().identity().unwrap(), 0)
            .is_err()
    );
    assert!(SourceDecoderIdentityV1::try_new("parser_bad", "1").is_err());
}

#[test]
fn a_well_formed_unknown_contract_is_rejected_as_an_unsupported_format() {
    let encoded = fixtures::profile().encode().unwrap();
    let mut old = String::new();
    for byte in super::contracts::common_event_contract_digest()
        .as_str()
        .as_bytes()
    {
        write!(&mut old, "{byte:02x}").unwrap();
    }
    let unsupported = encoded.replace(&old, &"30".repeat(64));
    assert_ne!(unsupported, encoded);
    assert_eq!(
        MappingProfileV1::decode(&unsupported),
        Err(DomainError::UnsupportedContract)
    );
}
