#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{LargeCaseStore, MappedIngestRequest, mapped_ingest::CommittedArtifacts};
use std::collections::{BTreeMap, BTreeSet};

struct Fixture {
    _root: tempfile::TempDir,
    store: ParquetStore,
    case: CaseId,
    artifacts: Vec<ParquetArtifact>,
    names: BTreeMap<String, String>,
    allowed: BTreeSet<String>,
    denied: String,
}
fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let store = crate::parquet_store::fixtures::store(root.path());
    let case = CaseId::parse("00000000-0000-0000-0000-000000000033").unwrap();
    for (name, second, ip) in [
        ("allowed.json", "01", "203.0.113.77"),
        ("denied.json", "02", "203.0.113.99"),
    ] {
        std::fs::write(root.path().join(name), format!(
            "{{\"eventTime\":\"2026-11-01T00:00:{second}Z\",\"eventName\":\"Synthetic {name}\",\"user\":\"alice\",\"sourceIPAddress\":\"{ip}\"}}"
        )).unwrap();
    }
    let paths = ["allowed.json".into(), "denied.json".into()];
    let cancel = CancellationToken::new();
    let prepared = crate::parquet_store::fixtures::successive_sources(
        &store,
        MappedIngestRequest {
            case_id: &case,
            source_root: root.path(),
            relative_paths: &paths,
            copy_original: false,
            parser: &crate::parquet_store::fixtures::parser(),
            committed_artifacts: CommittedArtifacts::Slice(&[]),
            limits: irmind_app::PartitionLimits::default(),
        },
        &cancel,
    )
    .unwrap();
    let names = prepared
        .iter()
        .zip(paths)
        .map(|(p, name)| (p.manifest.sha256.as_str().into(), name))
        .collect();
    let all = prepared
        .iter()
        .flat_map(|p| p.artifacts.clone())
        .collect::<Vec<_>>();
    let mut artifacts = Vec::new();
    for schema in [
        "irmind-events-v4",
        "irmind-entities-v4",
        "irmind-coobservations-v3",
    ] {
        let inputs = all
            .iter()
            .filter(|a| a.schema_version() == schema)
            .cloned()
            .collect::<Vec<_>>();
        let artifact = store.compact_artifacts(&case, &inputs, &cancel).unwrap();
        assert_eq!(artifact.source_hashes().len(), 2);
        artifacts.push(artifact);
    }
    let allowed = BTreeSet::from([prepared[0].manifest.sha256.as_str().into()]);
    let denied = prepared[1].manifest.sha256.as_str().into();
    Fixture {
        _root: root,
        store,
        case,
        artifacts,
        names,
        allowed,
        denied,
    }
}

#[test]
fn subagent_source_view_filters_mixed_files_before_counts_and_top_n() {
    let fixture = fixture();
    let unrestricted = fixture.store.queries(&fixture.names);
    let query = QueryStore {
        store: &fixture.store,
        source_names: &fixture.names,
        source_subset: Some(&fixture.allowed),
    };
    let filter = GraphQueryFilter::default();
    let cancel = CancellationToken::new();
    assert!(
        unrestricted
            .summary_native(&fixture.case, &fixture.artifacts, &cancel)
            .unwrap()
            .contains("records=2;")
    );
    assert!(
        query
            .summary_native(&fixture.case, &fixture.artifacts, &cancel)
            .unwrap()
            .contains("records=1;")
    );
    let timeline = query
        .timeline_native(&fixture.case, &fixture.artifacts, &filter, 1, &cancel)
        .unwrap();
    assert_eq!(timeline.len(), 1);
    assert!(fixture.allowed.contains(&timeline[0].evidence_hash));
    let search = query
        .search_native(
            &fixture.case,
            &fixture.artifacts,
            &filter,
            "Synthetic",
            1,
            &cancel,
        )
        .unwrap();
    assert!(search.contains("allowed.json") && !search.contains("denied.json"));
}

#[test]
fn subagent_source_view_filters_mixed_files_before_entity_graph_operations() {
    let fixture = fixture();
    let query = QueryStore {
        store: &fixture.store,
        source_names: &fixture.names,
        source_subset: Some(&fixture.allowed),
    };
    let filter = GraphQueryFilter::default();
    let cancel = CancellationToken::new();
    let entity = query
        .entity_native(
            &fixture.case,
            &fixture.artifacts,
            &filter,
            "user",
            "alice",
            &cancel,
        )
        .unwrap();
    assert!(entity.contains("observations=1;"), "{entity}");
    let neighbors = query
        .neighbors_native(
            &fixture.case,
            &fixture.artifacts,
            &filter,
            ("user", "alice"),
            20,
            &cancel,
        )
        .unwrap();
    assert!(
        neighbors.contains("203.0.113.77") && !neighbors.contains("203.0.113.99"),
        "{neighbors}"
    );
    let path = query
        .path_native(
            &fixture.case,
            &fixture.artifacts,
            &filter,
            ("ip", "203.0.113.77"),
            ("ip", "203.0.113.99"),
            &cancel,
        )
        .unwrap();
    assert!(path.contains("no co-observation path"), "{path}");
    assert!(
        query
            .raw_native(
                &fixture.case,
                &fixture.artifacts,
                &fixture.denied,
                0,
                &cancel
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn subagent_empty_source_view_has_no_unrestricted_fallback() {
    let fixture = fixture();
    let sources = BTreeSet::new();
    let query = QueryStore {
        store: &fixture.store,
        source_names: &fixture.names,
        source_subset: Some(&sources),
    };
    let filter = GraphQueryFilter::default();
    let cancel = CancellationToken::new();
    assert!(
        query
            .summary_native(&fixture.case, &fixture.artifacts, &cancel)
            .unwrap()
            .contains("records=0;")
    );
    assert!(
        query
            .timeline_native(&fixture.case, &fixture.artifacts, &filter, 20, &cancel)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        query
            .search_native(
                &fixture.case,
                &fixture.artifacts,
                &filter,
                "Synthetic",
                20,
                &cancel
            )
            .unwrap(),
        "no indexed matches"
    );
    assert!(
        query
            .raw_native(
                &fixture.case,
                &fixture.artifacts,
                &fixture.denied,
                0,
                &cancel
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn subagent_mixed_source_file_still_requires_the_signed_file_hash() {
    let fixture = fixture();
    let query = QueryStore {
        store: &fixture.store,
        source_names: &fixture.names,
        source_subset: Some(&fixture.allowed),
    };
    let artifact = fixture
        .artifacts
        .iter()
        .find(|a| a.schema_version() == "irmind-events-v4")
        .unwrap();
    std::fs::write(
        fixture
            .store
            .case_dir(&fixture.case)
            .unwrap()
            .join(artifact.path()),
        b"changed",
    )
    .unwrap();
    assert!(matches!(
        query.timeline_native(
            &fixture.case,
            &fixture.artifacts,
            &GraphQueryFilter::default(),
            1,
            &CancellationToken::new()
        ),
        Err(AppError::EvidenceMismatch(_))
    ));
}
