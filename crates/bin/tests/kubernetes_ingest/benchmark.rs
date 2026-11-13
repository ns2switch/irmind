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
    let fixture = match format {
        "kubernetes" => {
            include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/event.ndjson")
                .as_slice()
        }
        _ => {
            include_bytes!("../../../testkit/fixtures/parser-falco/source/event.ndjson").as_slice()
        }
    };
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
    assert_eq!(
        ingest(
            &engine,
            store.as_ref(),
            &case.id,
            &originals,
            "benchmark.ndjson"
        ),
        count
    );
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "KUBERNETES_BENCH format={format} bytes={bytes} records={count} seconds={seconds:.3} MiB_per_second={:.3}",
        f64::from(u32::try_from(bytes).unwrap()) / 1_048_576.0 / seconds
    );
    engine.verify(&case.id).unwrap();
}
