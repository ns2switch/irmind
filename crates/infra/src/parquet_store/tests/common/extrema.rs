use super::*;

#[test]
fn homogeneous_and_many_scope_batches_keep_exact_counts_and_extrema() {
    let root = tempfile::tempdir().unwrap();
    let store = mapped::store(root.path());
    let id = CaseId::parse("33333333-3333-3333-3333-333333333333").unwrap();
    let records = (0..64)
        .rev()
        .map(|index| {
            format!(
                r#"{{"eventTime":"2026-11-01T00:{:02}:{:02}Z","eventName":"Login","source_ip":"203.0.113.77","pid":42}}"#,
                index / 60,
                index % 60
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(root.path().join("mapped.ndjson"), records).unwrap();
    let paths = ["mapped.ndjson".into()];
    let source = store
        .prepare_local_batch(
            irmind_app::LocalBatchRequest {
                case_id: &id,
                source_root: root.path(),
                relative_paths: &paths,
                copy_original: false,
                parser: &mapped::Mapped,
                committed_artifacts: &[],
                limits: irmind_app::PartitionLimits::default(),
            },
            &CancellationToken::new(),
        )
        .unwrap()
        .pop()
        .unwrap();
    let names = BTreeMap::from([(
        source.manifest.sha256.as_str().to_owned(),
        "mapped.ndjson".into(),
    )]);
    for (kind, value, role) in [
        ("ip", "203.0.113.77", "source"),
        ("process", "42", "subject"),
    ] {
        let result = store
            .queries(&names)
            .entity_native(
                &id,
                &source.artifacts,
                &GraphQueryFilter::default(),
                kind,
                value,
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(result.contains("observations=64;"), "{result}");
        assert!(result.contains(&format!("{role}=64")), "{result}");
        assert!(result.contains("first=2026-11-01T00:00:00"), "{result}");
        assert!(result.contains("last=2026-11-01T00:01:03"), "{result}");
        assert_eq!(result.contains("Partial scope details"), kind == "process");
    }
}
