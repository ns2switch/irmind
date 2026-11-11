#![allow(clippy::unwrap_used)]
use irmind_app::CancellationToken;
use irmind_domain::{CaseId, GraphQueryFilter};

#[test]
fn borrowed_extrema_preserve_exact_mixed_precision_and_unknown_time_counts() {
    let sources = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let old = crate::parquet_store::fixtures::store(data.path());
    let new = crate::parquet_store::fixtures::store(data.path());
    let id = CaseId::parse("00000000-0000-0000-0000-000000000024").unwrap();
    let cancel = CancellationToken::new();
    let mut names = std::collections::BTreeMap::new();
    let mut artifacts = Vec::new();
    for (name, time, store) in [
        ("before.json", "1969-12-31T23:59:59.999999900Z", &new),
        ("after.json", "2026-11-01T00:00:00.123456789Z", &new),
        ("second.json", "2026-11-01T00:00:00.123456789Z", &old),
        ("unknown.json", "", &new),
    ] {
        let mut raw = serde_json::json!({"eventName":"Read","sourceIPAddress":"203.0.113.4"});
        if !time.is_empty() {
            raw["eventTime"] = time.into();
        }
        std::fs::write(sources.path().join(name), raw.to_string()).unwrap();
        let source = crate::parquet_store::fixtures::one_source(
            store,
            &id,
            sources.path(),
            name,
            false,
            &cancel,
        )
        .unwrap();
        names.insert(source.manifest.sha256.as_str().into(), name.into());
        artifacts.extend(source.artifacts);
    }
    let query = new.queries(&names);
    let result = query
        .entity_native(
            &id,
            &artifacts,
            &GraphQueryFilter::default(),
            "ip",
            "203.0.113.4",
            &cancel,
        )
        .unwrap();
    assert_eq!(
        result,
        "ip 203.0.113.4: observations=4; first=1969-12-31T23:59:59.999999900Z; last=2026-11-01T00:00:00.123456789Z; role counts: unspecified=4\nscope=legacy-unspecified: observations=4; first=1969-12-31T23:59:59.999999900Z; last=2026-11-01T00:00:00.123456789Z"
    );
    let summary = query.summary_native(&id, &artifacts, &cancel).unwrap();
    assert_eq!(
        summary,
        "Parquet records=4; first=1969-12-31T23:59:59.999999900Z; last=2026-11-01T00:00:00.123456789Z; common records=4/4; categorized=0/4; known outcomes=0/4; other records remain unclassified"
    );
}
