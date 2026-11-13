use super::*;
use std::io::{BufWriter, Read as _, Write as _};

#[test]
#[ignore = "manual release-only 1 GiB benchmark for each Linux input format"]
fn linux_one_gib_release_throughput() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("Run benchmarks with cargo test --release; unoptimized results are invalid");
    }
    for format in ["auth", "journal", "http", "audit"] {
        benchmark(format);
    }
    Ok(())
}
fn benchmark(format: &str) {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("sources");
    fs::create_dir(&originals).unwrap();
    let path = originals.join("benchmark.log");
    let mut output = BufWriter::new(fs::File::create(&path).unwrap());
    let mut bytes = 0u64;
    let mut serial = 1u64;
    let padding = "x".repeat(900);
    while bytes < 1024 * 1024 * 1024 {
        let block = generated(format, serial, &padding);
        output.write_all(block.as_bytes()).unwrap();
        bytes += block.len() as u64;
        serial += 1;
    }
    output.flush().unwrap();
    drop(output);
    let store = Arc::new(LocalStore::open(&root.path().join("case")).unwrap());
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic Linux benchmark", "local")
        .unwrap();
    let catalog = catalog();
    let started = std::time::Instant::now();
    let mut sample = vec![];
    std::io::Read::take(fs::File::open(&path).unwrap(), 65_536)
        .read_to_end(&mut sample)
        .unwrap();
    let time_context = (format == "auth")
        .then(|| ParserTimeContext::new(2026, 0, true, ParserTimeBasis::Command).unwrap());
    let selected = catalog
        .select_source(ParserSelectionRequest {
            cluster_context: None,
            source: "benchmark.log",
            sample: &sample,
            parser_override: None,
            forced: false,
            time_context,
        })
        .unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: selected.parser.as_ref(),
    }
    .ingest_local_batch_selected(
        &case.id,
        &originals,
        &["benchmark.log".into()],
        false,
        &BTreeMap::from([("benchmark.log".into(), selected.selection)]),
        &CancellationToken::new(),
    )
    .unwrap();
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "LINUX_BENCH format={format} bytes={bytes} seconds={seconds:.3} MiB_per_second={:.3}",
        f64::from(u32::try_from(bytes).unwrap()) / 1_048_576.0 / seconds
    );
    engine.verify(&case.id).unwrap();
    let entries = store.entries(&case.id).unwrap();
    let manifest = entries
        .iter()
        .find(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        .map(|entry| SourceManifestV2::decode(&entry.payload).unwrap())
        .unwrap();
    assert_eq!(
        manifest.rejected_records, 0,
        "{format}: rejected benchmark rows"
    );
}
fn generated(format: &str, serial: u64, padding: &str) -> String {
    match format {
        "auth" => format!("Nov  1 01:00:00 synthetic-linux sshd[101]: Accepted password for synthetic-user from 203.0.113.77 port 4242 ssh2 Synthetic={padding}\n"),
        "journal" => format!("{{\"__REALTIME_TIMESTAMP\":\"1793494800123456\",\"_HOSTNAME\":\"synthetic-linux\",\"_UID\":\"1000\",\"_PID\":\"101\",\"_EXE\":\"/usr/bin/sh\",\"MESSAGE\":\"Synthetic {padding}\"}}\n"),
        "http" => format!("203.0.113.77 - synthetic-user [01/Nov/2026:01:00:00 +0000] \"GET /synthetic HTTP/1.1\" 200 12 \"-\" \"Synthetic-{padding}\"\n"),
        _ => [
            format!("node=synthetic-linux type=SYSCALL msg=audit(1793494800.123456:{serial}): syscall=59 uid=1000 auid=1000 pid=101 exe=\"/usr/bin/sh\" success=yes padding={padding}\n"),
            format!("node=synthetic-linux type=EXECVE msg=audit(1793494800.123456:{serial}): argc=2 a0=\"sh\" a1=\"synthetic\" padding={padding}\n"),
            format!("node=synthetic-linux type=EOE msg=audit(1793494800.123456:{serial}): padding={padding}\n"),
        ].join(""),
    }
}
