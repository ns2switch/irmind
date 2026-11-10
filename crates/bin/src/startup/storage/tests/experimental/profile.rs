//! Development-only counters for the shared decode/map boundary; no output changes.
use irmind_app::{
    CancellationToken,
    source_mapping::{
        MappingCatalog, MappingError, MappingManifest, MappingOutput, SourceFileInput,
        SourceMapper, SourceMetadata, SourceRecordAccumulator, SourceRecordV1,
    },
};
use irmind_domain::{EvidenceHash, MappingIdentityV1, SourceReferenceV1};
use std::{
    fs::File,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

struct MeasuredMapper {
    manifest: MappingManifest,
    original: MappingCatalog,
    identity: MappingIdentityV1,
    nanos: Arc<AtomicU64>,
}
impl SourceMapper for MeasuredMapper {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let mapper = self.original.exact_mapper(&self.identity)?;
        let started = Instant::now();
        let result = mapper.map(source);
        self.nanos.fetch_add(
            u64::try_from(started.elapsed().as_nanos()).unwrap(),
            Ordering::Relaxed,
        );
        result
    }
}
fn measured(original: &MappingCatalog, nanos: &Arc<AtomicU64>) -> MappingCatalog {
    let mut catalog = original.clone();
    for snapshot in original.snapshots().unwrap() {
        let mapper = original.exact_mapper(snapshot.mapping()).unwrap();
        let wrapper = MeasuredMapper {
            manifest: mapper.manifest().clone(),
            original: original.clone(),
            identity: snapshot.mapping().clone(),
            nanos: Arc::clone(nanos),
        };
        catalog = catalog
            .changed(snapshot.mapping().id(), Some(Arc::new(wrapper)))
            .unwrap();
    }
    catalog
}
pub(super) fn run(
    original: &MappingCatalog,
    path: &Path,
    hash: &EvidenceHash,
    decoder: (&str, &str),
    label: &str,
    repetition: u32,
    root: &Path,
) {
    let mapper_nanos = Arc::new(AtomicU64::new(0));
    let catalog = measured(original, &mapper_nanos);
    let decoder = catalog.decoder(decoder.0, decoder.1).unwrap();
    let reference = SourceReferenceV1::file(path.file_name().unwrap().to_str().unwrap()).unwrap();
    let cancel = CancellationToken::new();
    let metadata = SourceMetadata {
        source: &reference,
        evidence_hash: std::array::from_fn(|i| {
            u8::from_str_radix(&hash.as_str()[2 * i..2 * i + 2], 16).unwrap()
        }),
        time_context: None,
        cancel: &cancel,
    };
    let mut file = File::open(path).unwrap();
    let mut spool = tempfile::tempfile_in(root).unwrap();
    let mut accumulator = SourceRecordAccumulator::new(
        metadata,
        decoder.identity(),
        file.metadata().unwrap().len(),
        &catalog,
    )
    .unwrap();
    let (mut callback, mut observations, mut first) = (0.0, 0usize, None);
    let started = Instant::now();
    let report = decoder
        .decode_local_file(
            SourceFileInput {
                metadata,
                file: &mut file,
            },
            &mut |record| {
                let start = Instant::now();
                let mapped = accumulator.accept(&record, &mut spool)?;
                callback += start.elapsed().as_secs_f64();
                mapped.output.inspect(|out| {
                    observations += out.record().common.observations().values().len();
                });
                if first.is_none() {
                    record.inspect(|source| first = Some(source.clone()));
                }
                Ok(())
            },
        )
        .unwrap();
    let decoding = started.elapsed().as_secs_f64() - callback;
    let finalize = Instant::now();
    accumulator.finish(&mut spool, &report).unwrap();
    let finalize = finalize.elapsed().as_secs_f64();
    let mapping =
        std::time::Duration::from_nanos(mapper_nanos.load(Ordering::Relaxed)).as_secs_f64();
    assert_eq!(report.rejected, 0);
    println!(
        "COMMON_PIPELINE_PROFILE source={label} repetition={repetition} records={} decode_ipc_seconds={decoding:.6} mapping_seconds={mapping:.6} shared_boundary_seconds={:.6} finalize_seconds={finalize:.6} observations={observations} source_sha256={}",
        report.accepted,
        callback - mapping,
        hash.as_str()
    );
    micro(first.as_ref().unwrap(), label, repetition);
}
fn micro(source: &SourceRecordV1, label: &str, repetition: u32) {
    use std::hint::black_box;
    let iterations = 20_000;
    let clone_start = Instant::now();
    for _ in 0..iterations {
        black_box(source.clone());
    }
    let cloning = clone_start.elapsed().as_secs_f64();
    let validate_start = Instant::now();
    for _ in 0..iterations {
        black_box(source.fields().validate().unwrap());
    }
    let validation = validate_start.elapsed().as_secs_f64();
    let render_start = Instant::now();
    for _ in 0..iterations {
        black_box(irmind_app::source_mapping::json::render_source_fields(source.fields()).unwrap());
    }
    let rendering = render_start.elapsed().as_secs_f64();
    println!(
        "COMMON_PIPELINE_MICRO source={label} repetition={repetition} iterations={iterations} clone_seconds={cloning:.6} validation_seconds={validation:.6} rendering_seconds={rendering:.6} source_estimated_bytes={}",
        source.fields().validate().unwrap()
    );
}

#[cfg(feature = "mapping-ecs")]
#[test]
fn shared_profiler_keeps_decoder_output_and_source_commitment_valid() {
    let root = tempfile::tempdir().unwrap();
    let bytes = br#"{"@timestamp":"2026-11-01T00:00:00.123456Z","ecs":{"version":"9.5.0"},"event":{"category":["authentication"],"type":["start"],"outcome":"failure"},"host":{"name":"synthetic-host"},"user":{"name":"alice","domain":"LAB"}}
"#;
    let path = root.path().join("events.ndjson");
    std::fs::write(&path, bytes).unwrap();
    let catalog = super::registry().mapping_catalog().unwrap();
    let mapper = catalog.select(&decode_ecs(bytes)).unwrap().unwrap();
    let wrapped = MeasuredMapper {
        manifest: mapper.manifest().clone(),
        original: catalog.clone(),
        identity: mapper.manifest().identity().clone(),
        nanos: Arc::new(AtomicU64::new(0)),
    };
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_ecs::EcsSourceDecoder),
        Arc::new(wrapped),
        "events.ndjson",
        bytes,
        1,
    )
    .unwrap();
    run(
        &catalog,
        &path,
        &EvidenceHash::from_bytes(irmind_app::sha256(bytes)),
        ("parser-ecs", "ecs-source-v1"),
        "ecs",
        0,
        root.path(),
    );
}
#[cfg(feature = "mapping-ecs")]
fn decode_ecs(bytes: &[u8]) -> SourceRecordV1 {
    use irmind_app::{SourceDecoder, source_mapping::SourceInput};
    let mut source = None;
    let cancel = CancellationToken::new();
    let reference = SourceReferenceV1::file("events.ndjson").unwrap();
    irmind_mod_parser_ecs::EcsSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut &bytes[..],
            },
            &mut |record| {
                record.inspect(|record| source = Some(record.clone()));
                Ok(())
            },
        )
        .unwrap();
    source.unwrap()
}
