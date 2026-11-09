//! Benchmark-only clocks surround the production decoder and pure mapper.
use super::*;
use irmind_app::source_mapping::{
    MappingCatalog, MappingError, MappingManifest, MappingOutput, SourceFileInput, SourceInput,
    SourceRecordV1,
};
use irmind_app::{ParseReport, ParserIdentity, SourceDecoder, SourceMapper};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Default)]
pub(super) struct Timings {
    decoder: AtomicU64,
    mapping: AtomicU64,
}
impl Timings {
    fn add(counter: &AtomicU64, duration: Duration) {
        counter.fetch_add(
            u64::try_from(duration.as_nanos()).unwrap(),
            Ordering::Relaxed,
        );
    }
    pub(super) fn report(&self) {
        println!(
            "MAPPING_PHASE decoder_seconds={:.6} mapper_seconds={:.6}",
            Duration::from_nanos(self.decoder.load(Ordering::Relaxed)).as_secs_f64(),
            Duration::from_nanos(self.mapping.load(Ordering::Relaxed)).as_secs_f64()
        );
    }
}
struct Decoder {
    inner: Arc<dyn SourceDecoder>,
    timings: Arc<Timings>,
}
impl SourceDecoder for Decoder {
    fn identity(&self) -> ParserIdentity<'_> {
        self.inner.identity()
    }
    fn source_parallelism(&self) -> irmind_app::SourceParallelism {
        self.inner.source_parallelism()
    }
    fn needs_random_access(&self, source: &str, sample: &[u8]) -> bool {
        self.inner.needs_random_access(source, sample)
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let started = Instant::now();
        let mut callback = Duration::ZERO;
        let result = self.inner.decode_reader(input, &mut |record| {
            let started = Instant::now();
            let result = emit(record);
            callback += started.elapsed();
            result
        });
        Timings::add(
            &self.timings.decoder,
            started.elapsed().saturating_sub(callback),
        );
        result
    }
    fn decode_local_file(
        &self,
        input: SourceFileInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let started = Instant::now();
        let mut callback = Duration::ZERO;
        let result = self.inner.decode_local_file(input, &mut |record| {
            let started = Instant::now();
            let result = emit(record);
            callback += started.elapsed();
            result
        });
        Timings::add(
            &self.timings.decoder,
            started.elapsed().saturating_sub(callback),
        );
        result
    }
}
struct Mapper {
    inner: Arc<dyn SourceMapper>,
    timings: Arc<Timings>,
}
impl SourceMapper for Mapper {
    fn manifest(&self) -> &MappingManifest {
        self.inner.manifest()
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let started = Instant::now();
        let result = self.inner.map(source);
        Timings::add(&self.timings.mapping, started.elapsed());
        result
    }
}
pub(super) fn catalog() -> (Arc<MappingCatalog>, Arc<Timings>) {
    let timings = Arc::new(Timings::default());
    let decoders: Vec<Arc<dyn SourceDecoder>> = vec![
        Arc::new(irmind_mod_parser_json::JsonSourceDecoder),
        Arc::new(irmind_mod_parser_linux::LinuxSourceDecoder),
    ];
    let mappers: Vec<Arc<dyn SourceMapper>> = vec![
        Arc::new(irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap()),
        Arc::new(irmind_mod_mapping_journald_compat::JournaldCompatibilityMapping::new().unwrap()),
    ];
    let decoders = decoders
        .into_iter()
        .map(|inner| {
            Arc::new(Decoder {
                inner,
                timings: timings.clone(),
            }) as Arc<dyn SourceDecoder>
        })
        .collect();
    let mappers = mappers
        .into_iter()
        .map(|inner| {
            Arc::new(Mapper {
                inner,
                timings: timings.clone(),
            }) as Arc<dyn SourceMapper>
        })
        .collect();
    (
        Arc::new(MappingCatalog::freeze(decoders, mappers).unwrap()),
        timings,
    )
}
