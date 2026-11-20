use super::*;
use irmind_app::SourceMapper;
use irmind_domain::SourceRecordSetV1;
use irmind_mod_mapping_cloud_flow::CloudFlowMapping;
use irmind_mod_parser_azure_flow::AzureFlowSourceDecoder;
use std::io::{BufWriter, Write};

#[test]
#[ignore = "manual release-only comparable Azure flow ingestion profile"]
fn benchmark_azure_flow_release() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        return Err("benchmark requires an optimized release build");
    }
    let mib: u64 =
        std::env::var("IRMIND_AZURE_BENCH_MIB").map_or(1024, |value| value.parse().unwrap());
    assert!((1..=1024).contains(&mib));
    let format = std::env::var("IRMIND_AZURE_BENCH_FORMAT").unwrap_or_else(|_| "vnet".into());
    let ordered = match std::env::var("IRMIND_AZURE_BENCH_ORDER").as_deref() {
        Ok("ordered") => true,
        Ok("disordered") => false,
        _ => return Err("select ordered or disordered"),
    };
    let root = tempfile::Builder::new()
        .prefix("azure-flow-profile-")
        .tempdir()
        .unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let name = "flows.ndjson";
    let (bytes, rows) = write_flows(&sources.join(name), &format, mib << 20, ordered);
    profile_ingest(root.path(), &sources, name, &format, ordered, bytes, rows);
    Ok(())
}

fn write_flows(path: &Path, format: &str, target: u64, ordered: bool) -> (u64, u64) {
    let (fixture, tuples) = match format {
        "vnet" => (
            include_str!("../../../../../../testkit/fixtures/parser-azure-flow/source/vnet.ndjson"),
            "/flowRecords/flows/0/flowGroups/0/flowTuples",
        ),
        "nsg" => (
            include_str!("../../../../../../testkit/fixtures/parser-azure-flow/source/nsg.ndjson"),
            "/properties/flows/0/flows/0/flowTuples",
        ),
        _ => unreachable!("select vnet or nsg"),
    };
    let mut container: serde_json::Value =
        serde_json::from_str(fixture.lines().next().unwrap()).unwrap();
    let original = container
        .pointer(tuples)
        .unwrap()
        .as_array()
        .unwrap()
        .clone();
    let lines = [0, 1].map(|index| {
        *container.pointer_mut(tuples).unwrap() =
            serde_json::Value::Array(vec![original[index].clone(); 2]);
        let mut line = serde_json::to_vec(&container).unwrap();
        line.push(b'\n');
        line
    });
    let pair_bytes = (lines[0].len() + lines[1].len()) as u64;
    let pairs = target.div_ceil(pair_bytes);
    let mut writer = BufWriter::new(fs::File::create(path).unwrap());
    for index in 0..pairs * 2 {
        let group = if ordered { index / pairs } else { index % 2 };
        writer
            .write_all(&lines[usize::try_from(group).unwrap()])
            .unwrap();
    }
    writer.flush().unwrap();
    (pairs * pair_bytes, pairs * 4)
}

fn profile_ingest(
    root: &Path,
    sources: &Path,
    name: &str,
    format: &str,
    ordered: bool,
    bytes: u64,
    rows: u64,
) {
    let mappings = CloudFlowMapping::azure()
        .unwrap()
        .into_iter()
        .map(|mapping| Arc::new(mapping) as Arc<dyn SourceMapper>)
        .collect();
    let catalog =
        Arc::new(MappingCatalog::freeze(vec![Arc::new(AzureFlowSourceDecoder)], mappings).unwrap());
    let ProfiledFixture {
        store,
        engine,
        catalog,
        profile,
        custody,
    } = profiled_fixture_with_catalog(&root.join("case"), catalog);
    store.set_parallel_worker_limit(NonZeroU16::new(4));
    let case = engine
        .create_case("Synthetic Azure flow profile", "local only")
        .unwrap();
    let identity = AzureFlowSourceDecoder.identity();
    let parser = catalog
        .decoder_selection(identity.name, identity.version)
        .unwrap();
    let ingest = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let cancel = CancellationToken::new();
    custody.reset();
    let start = Instant::now();
    assert_eq!(
        ingest
            .ingest_local_batch(&case.id, sources, &[name.into()], false, &cancel)
            .unwrap()
            .len(),
        1
    );
    let wall = start.elapsed().as_secs_f64();
    let [stage, sort, replay, recheck, publish] =
        profile.partition_snapshot().map(|v| v.as_secs_f64());
    let temporary_peak = profile.temporary_disk_peak();
    println!(
        "AZURE_PROFILE format={format} ordered={ordered} bytes={bytes} rows={rows} wall={wall:.3} MiB_per_second={:.3} stage={stage:.3} sort={sort:.3} replay={replay:.3} recheck={recheck:.3} publish={publish:.3} normalized_peak_bytes={temporary_peak}",
        f64::from(u32::try_from(bytes).unwrap()) / 1_048_576.0 / wall
    );
    report_phases(&profile);
    custody.report();
    let entries = store.entries(&case.id).unwrap();
    let actual = entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SourceRecordSetV1)
        .map(|entry| SourceRecordSetV1::decode(&entry.payload).unwrap().records())
        .sum::<u64>();
    assert_eq!(actual, rows);
    assert_eq!(sort > 0.0, !ordered);
    engine.verify(&case.id).unwrap();
    assert!(ingest.verify_parquet(&case.id, &cancel).unwrap() > 0);
}
