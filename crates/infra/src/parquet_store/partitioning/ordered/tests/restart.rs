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
    let parser = Arc::new(CountSpeculation::default());
    let store = store(data.path(), parser.clone());
    let token = CancellationToken::new();
    let id = case();
    let paths = ["events.json".into()];
    let req = request(inputs.path(), &id, &paths);
    let prepared = store.prepare_mapped_ingest(req, &token).unwrap().unwrap();
    assert_eq!(prepared.metadata().sources[0].report.accepted, 12_002);
    assert_eq!(parser.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(parser.speculative.load(std::sync::atomic::Ordering::SeqCst) < 12_002);
    assert!(!token.is_cancelled());
    assert_eq!(
        std::fs::read_dir(store.spool_dir(&id).unwrap())
            .unwrap()
            .count(),
        0
    );
    drop(prepared);
    assert_no_temporary_files(&store.case_dir(&id).unwrap());
}

#[test]
fn disordered_sources_keep_parallel_authenticated_fallback_parsing() {
    let inputs = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let text =
        b"{\"eventTime\":\"2026-11-01T00:00:02Z\"}\n{\"eventTime\":\"2026-11-01T00:00:01Z\"}\n";
    for name in ["a.json", "b.json"] {
        let content = std::str::from_utf8(text).unwrap().replace(
            "\"eventTime\":",
            &format!("\"source_shard\":\"{name}\",\"eventTime\":"),
        );
        std::fs::write(inputs.path().join(name), content).unwrap();
    }
    let parser = Arc::new(CountSpeculation {
        parallel: Some(ParallelFallback::default()),
        ..Default::default()
    });
    let store = store(data.path(), parser.clone());
    // This rendezvous exercises two concurrent producers, even on two-core
    // runners where the normal leave-one-core-free default is sequential.
    store.workers.set_limit(std::num::NonZeroU16::new(2));
    let token = CancellationToken::new();
    let id = case();
    let paths = ["a.json".into(), "b.json".into()];
    let req = request(inputs.path(), &id, &paths);
    let prepared = store.prepare_mapped_ingest(req, &token).unwrap().unwrap();
    assert_eq!(prepared.metadata().sources.len(), 2);
    assert!(
        prepared
            .metadata()
            .sources
            .iter()
            .all(|source| source.report.accepted == 2)
    );
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
impl SourceDecoder for CountSpeculation {
    fn identity(&self) -> irmind_app::ParserIdentity<'_> {
        JsonSourceDecoder.identity()
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(irmind_domain::Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<irmind_app::ParseReport, AppError> {
        let name = input.metadata.source.reference();
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
        let result = JsonSourceDecoder.decode_reader(input, &mut |row| {
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
