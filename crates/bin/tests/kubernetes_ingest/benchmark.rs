use super::*;
use std::io::{BufWriter, Write as _};
#[test]
#[ignore = "manual optimized 1 GiB benchmark; writes only synthetic temporary data"]
fn one_gib_release_throughput() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("Run benchmarks in the release profile");
    }
    for format in ["kubernetes", "falco"] {
        benchmark(format);
    }
    Ok(())
}
fn benchmark(format: &str) {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("sources");
    fs::create_dir(&originals).unwrap();
    let fixture = fixture(format);
    let mut value: serde_json::Value = serde_json::from_slice(fixture).unwrap();
    value["synthetic_padding"] = serde_json::json!("x".repeat(1024));
    let mut line = serde_json::to_vec(&value).unwrap();
    line.push(b'\n');
    let mut writer = BufWriter::new(fs::File::create(originals.join("benchmark.ndjson")).unwrap());
    let mut bytes = 0u64;
    let mut count = 0u64;
    while bytes < 1024 * 1024 * 1024 {
        writer.write_all(&line).unwrap();
        bytes += line.len() as u64;
        count += 1;
    }
    writer.flush().unwrap();
    drop(writer);
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic cluster benchmark", "local only")
        .unwrap();
    let started = std::time::Instant::now();
    let context = match format {
        "gcp" | "zeek" | "suricata" => None,
        "gke" => irmind_app::command_cluster_context(Some(
            "gke:projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
        ))
        .unwrap(),
        _ => Some(context()),
    };
    assert_eq!(
        ingest_with_context(
            &engine,
            store.as_ref(),
            &case.id,
            &originals,
            "benchmark.ndjson",
            context.as_ref()
        ),
        count
    );
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "KUBERNETES_BENCH format={format} bytes={bytes} records={count} seconds={seconds:.3} MiB_per_second={:.3}",
        f64::from(u32::try_from(bytes).unwrap()) / 1_048_576.0 / seconds
    );
    verify_selection(store.as_ref(), &case.id, format);
    engine.verify(&case.id).unwrap();
}

#[cfg(feature = "parser-gcp-audit")]
#[test]
#[ignore = "manual optimized 1 GiB Cloud Audit and GKE smoke"]
fn gcp_audit_one_gib_release_throughput() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("Run benchmarks in the release profile");
    }
    for format in ["gcp", "gke"] {
        benchmark(format);
    }
    Ok(())
}

#[cfg(all(
    feature = "parser-zeek",
    feature = "parser-suricata",
    feature = "mapping-network"
))]
#[test]
#[ignore = "manual optimized 1 GiB network semantic mapping smoke"]
fn network_one_gib_release_throughput() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("Run benchmarks in the release profile");
    }
    for format in ["zeek", "suricata"] {
        benchmark(format);
    }
    Ok(())
}

fn fixture(format: &str) -> &'static [u8] {
    [
        (
            "kubernetes",
            include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/event.ndjson")
                .as_slice(),
        ),
        (
            "falco",
            include_bytes!("../../../testkit/fixtures/parser-falco/source/event.ndjson").as_slice(),
        ),
        (
            "zeek",
            include_bytes!("../../../testkit/fixtures/parser-zeek/source/dns.jsonl").as_slice(),
        ),
        (
            "suricata",
            include_bytes!("../../../testkit/fixtures/parser-suricata/source/eve.jsonl")
                .split(|b| *b == b'\n')
                .next()
                .unwrap(),
        ),
        (
            "gcp",
            include_bytes!("../../../testkit/fixtures/parser-gcp-audit/source/event.ndjson")
                .as_slice(),
        ),
        (
            "gke",
            include_bytes!("../../../testkit/fixtures/parser-gcp-audit/source/gke.ndjson")
                .as_slice(),
        ),
    ]
    .into_iter()
    .find(|(name, _)| *name == format)
    .unwrap()
    .1
}

fn verify_selection(store: &LocalStore, id: &irmind_domain::CaseId, format: &str) {
    let entries = store.entries(id).unwrap();
    let manifest = entries
        .iter()
        .rev()
        .find(|e| e.kind == AuditEventKind::SourceManifestV2)
        .map(|e| SourceManifestV2::decode(&e.payload).unwrap())
        .unwrap();
    let expected = [
        ("gcp", "parser-gcp-audit"),
        ("gke", "parser-gcp-audit"),
        ("kubernetes", "parser-kubernetes"),
        ("falco", "parser-falco"),
        ("zeek", "parser-zeek"),
        ("suricata", "parser-suricata"),
    ]
    .into_iter()
    .find(|(name, _)| *name == format)
    .unwrap()
    .1;
    assert_eq!(manifest.parser_id, expected);
    assert!(
        entries
            .iter()
            .any(|e| e.kind == AuditEventKind::MappingRunV1)
    );
}
