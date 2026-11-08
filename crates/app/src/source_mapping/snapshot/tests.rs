use super::*;
use crate::source_mapping::{
    SelectorCondition, SelectorPredicate as P, SelectorScalar as S, SourceDiscriminator,
    SourceNumber, SourcePath, SourceSelector,
};
use std::collections::{BTreeMap, BTreeSet};

fn manifest(provenance: MappingProvenance) -> MappingManifest {
    let content = match &provenance {
        MappingProvenance::NativeBuild { manifest } => manifest,
        MappingProvenance::BundledDefinition { canonical, .. }
        | MappingProvenance::InstalledDefinition { canonical, .. } => canonical,
    };
    let identity = MappingIdentityV1::try_new(
        "mapping-test",
        "1",
        irmind_domain::COMMON_EVENT_V1,
        EvidenceHash::from_bytes(crate::sha256(content)),
    )
    .unwrap();
    let predicates = [
        P::Missing,
        P::Null,
        P::Present,
        P::Exact(S::Boolean(false)),
        P::Exact(S::Number(
            SourceNumber::try_new("9007199254740993").unwrap(),
        )),
        P::Exact(S::Text("failure".into())),
        P::IntegerInterval {
            first: i128::MIN,
            last: i128::MAX,
        },
    ];
    let conditions = predicates
        .into_iter()
        .enumerate()
        .map(|(i, predicate)| SelectorCondition {
            path: SourcePath::keys(&[&format!("field{i}")]).unwrap(),
            predicate,
        })
        .collect();
    let selector = SourceSelector::try_new(
        "parser-json",
        BTreeSet::from(["json-source-v1".into()]),
        Some(("json".into(), "source-json-v1".into())),
        BTreeMap::from([(SourceDiscriminator::Provider, "aws".into())]),
        conditions,
    )
    .unwrap();
    MappingManifest::try_new(identity, vec![selector], provenance, false).unwrap()
}

#[test]
fn snapshots_round_trip_all_closed_selector_types_and_provenances_without_executing_code() {
    for provenance in [
        MappingProvenance::NativeBuild {
            manifest: b"synthetic-native\0manifest".to_vec(),
        },
        MappingProvenance::BundledDefinition {
            canonical: b"synthetic definition".to_vec(),
            interpreter: "irmind-mapping-tables-v1".into(),
        },
        MappingProvenance::InstalledDefinition {
            canonical: b"synthetic definition".to_vec(),
            interpreter: "irmind-mapping-tables-v1".into(),
            operation: EvidenceHash::from_bytes([8; 32]),
        },
    ] {
        let manifest = manifest(provenance);
        let snapshot = manifest.snapshot().unwrap();
        assert_eq!(MappingManifest::from_snapshot(&snapshot).unwrap(), manifest);
        assert_eq!(
            MappingManifest::from_snapshot(&snapshot)
                .unwrap()
                .snapshot()
                .unwrap()
                .content(),
            snapshot.content()
        );
        assert!(snapshot.content().contains("9007199254740993"));
        assert!(snapshot.content().contains(&i128::MIN.to_string()));
    }
}

#[test]
fn snapshots_reject_unknown_fields_noncanonical_order_and_changed_content() {
    let manifest = manifest(MappingProvenance::NativeBuild {
        manifest: b"synthetic native".to_vec(),
    });
    let snapshot = manifest.snapshot().unwrap();
    let check = |text| {
        MappingManifest::from_snapshot(
            &MappingSnapshotV1::try_new(snapshot.mapping().clone(), text).unwrap(),
        )
    };
    assert!(check(format!(" {}", snapshot.content())).is_err());
    assert!(
        check(
            snapshot
                .content()
                .replacen("\"contract\":", "\"unknown\":", 1)
        )
        .is_err()
    );
    assert!(
        check(snapshot.content().replace(
            "73796e746865746963206e6174697665",
            "73796e746865746963206e6174697664"
        ))
        .is_err()
    );
    assert!(check(snapshot.content().replace("9007199254740993", "01")).is_err());
}
