use super::*;

#[test]
fn disorder_stops_speculative_parsing_without_cancelling_the_complete_fallback() {
    let inputs = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let text = format!(
        "{{\"eventTime\":\"2026-11-01T00:00:02Z\"}}\n{{\"eventTime\":\"2026-11-01T00:00:01Z\"}}\n{}",
        input_rows(false)
    );
    std::fs::write(inputs.path().join("events.json"), text).unwrap();
    let store = ParquetStore::open_precise(data.path()).unwrap();
    let parser = CountSpeculation::default();
    let token = CancellationToken::new();
    let id = case();
    let paths = ["events.json".into()];
    let mut req = request(inputs.path(), &id, &paths);
    req.parser = &parser;
    let prepared = store.prepare_local_batch(req, &token).unwrap();
    assert_eq!(prepared[0].records, 12_002);
    assert_eq!(parser.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(parser.speculative.load(std::sync::atomic::Ordering::SeqCst) < 12_002);
    assert!(!token.is_cancelled());
    assert_eq!(
        std::fs::read_dir(store.spool_dir(&id).unwrap())
            .unwrap()
            .count(),
        0
    );
    assert_no_temporary_files(&store.case_dir(&id).unwrap());
}

#[test]
fn disordered_sources_keep_parallel_authenticated_fallback_parsing() {
    let inputs = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let text =
        b"{\"eventTime\":\"2026-11-01T00:00:02Z\"}\n{\"eventTime\":\"2026-11-01T00:00:01Z\"}\n";
    for name in ["a.json", "b.json"] {
        std::fs::write(inputs.path().join(name), text).unwrap();
    }
    let store = ParquetStore::open_precise(data.path()).unwrap();
    let parser = CountSpeculation {
        parallel: Some(ParallelFallback::default()),
        ..Default::default()
    };
    let token = CancellationToken::new();
    let id = case();
    let paths = ["a.json".into(), "b.json".into()];
    let mut req = request(inputs.path(), &id, &paths);
    req.parser = &parser;
    let prepared = store.prepare_local_batch(req, &token).unwrap();
    assert_eq!(prepared.len(), 2);
    assert!(prepared.iter().all(|source| source.records == 2));
    assert_eq!(parser.calls.load(std::sync::atomic::Ordering::SeqCst), 4);
    assert!(!token.is_cancelled());
    assert_eq!(
        std::fs::read_dir(store.spool_dir(&id).unwrap())
            .unwrap()
            .count(),
        0
    );
}

#[derive(Default)]
struct ParallelFallback {
    entered: std::sync::Mutex<usize>,
    ready: std::sync::Condvar,
}
impl ParallelFallback {
    fn wait_for_both(&self) -> Result<(), AppError> {
        let mut entered = self.entered.lock().unwrap();
        *entered += 1;
        self.ready.notify_all();
        let (entered, _) = self
            .ready
            .wait_timeout_while(entered, std::time::Duration::from_secs(5), |n| *n < 2)
            .unwrap();
        if *entered < 2 {
            return Err(AppError::Cancelled);
        }
        Ok(())
    }
}

#[derive(Default)]
struct CountSpeculation {
    calls: std::sync::atomic::AtomicUsize,
    speculative: std::sync::atomic::AtomicUsize,
    per_source: std::sync::Mutex<std::collections::BTreeMap<String, usize>>,
    parallel: Option<ParallelFallback>,
}
impl StreamingEventParser for CountSpeculation {
    fn streaming_version(&self) -> &'static str {
        JsonParser.streaming_version()
    }
    fn parser_name(&self) -> &'static str {
        JsonParser.parser_name()
    }
    fn partition_profile(&self, record: &irmind_app::GraphRecord) -> irmind_app::PartitionProfile {
        JsonParser.partition_profile(record)
    }
    fn parse_reader(
        &self,
        name: &str,
        reader: &mut dyn std::io::Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(
            irmind_domain::Tainted<irmind_app::GraphRecord>,
        ) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        JsonParser.parse_reader(name, reader, hash, cancel, emit)
    }
    fn parse_indexed_reader_report(
        &self,
        name: &str,
        reader: &mut dyn std::io::Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(
            irmind_domain::Tainted<irmind_app::IndexedGraphRecord>,
        ) -> Result<(), AppError>,
    ) -> Result<irmind_app::ParseReport, AppError> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let source_call = {
            let mut counts = self.per_source.lock().unwrap();
            let count = counts.entry(name.into()).or_default();
            *count += 1;
            *count
        };
        if source_call == 2
            && let Some(parallel) = &self.parallel
        {
            parallel.wait_for_both()?;
        }
        let mut count = 0;
        let result =
            JsonParser.parse_indexed_reader_report(name, reader, hash, cancel, &mut |row| {
                count += 1;
                emit(row)
            });
        if call == 0 {
            self.speculative
                .store(count, std::sync::atomic::Ordering::SeqCst);
        }
        result
    }
}
