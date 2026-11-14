use super::*;
use irmind_app::{ParseReport, ParserIdentity, source_mapping::SourceInput};
struct BlockingDecoder {
    enabled: Arc<AtomicBool>,
    entered: Arc<AtomicBool>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}
impl SourceDecoder for BlockingDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        irmind_mod_parser_json::JsonSourceDecoder.identity()
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        if self.enabled.load(Ordering::Acquire) {
            self.entered.store(true, Ordering::Release);
            self.release.lock().unwrap().recv().unwrap();
        }
        irmind_mod_parser_json::JsonSourceDecoder.decode_reader(input, emit)
    }
}
#[test]
fn a_blocked_decoder_cannot_stop_the_deadline_or_spawn_unbounded_read_workers() {
    let enabled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicBool::new(false));
    let (release, receive) = std::sync::mpsc::channel();
    let f = Fixture::with_decoder(
        false,
        RAW,
        Arc::new(BlockingDecoder {
            enabled: enabled.clone(),
            entered: entered.clone(),
            release: Mutex::new(receive),
        }),
    );
    enabled.store(true, Ordering::Release);
    let started = Instant::now();
    let result = f.reader.read_with_deadline(
        &f.case,
        &f.hash,
        0,
        &CancellationToken::new(),
        Duration::from_secs(2),
    );
    assert!(result.is_err());
    assert!(entered.load(Ordering::Acquire));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(f.reader.busy.load(Ordering::Acquire));
    assert!(f.read(0).is_err());
    release.send(()).unwrap();
    await_cleanup(&f.reader);
}
#[test]
fn cancellation_returns_while_the_decoder_callback_is_blocked() {
    let enabled = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicBool::new(false));
    let (release, receive) = std::sync::mpsc::channel();
    let f = Fixture::with_decoder(
        false,
        RAW,
        Arc::new(BlockingDecoder {
            enabled: enabled.clone(),
            entered: entered.clone(),
            release: Mutex::new(receive),
        }),
    );
    enabled.store(true, Ordering::Release);
    let token = CancellationToken::new();
    let worker_cancel = token.clone();
    let reader = Arc::clone(&f.reader);
    let case = f.case.clone();
    let hash = f.hash.clone();
    let worker =
        std::thread::spawn(move || reader.read_verified_record(&case, &hash, 0, &worker_cancel));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !entered.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(entered.load(Ordering::Acquire));
    token.cancel();
    assert!(matches!(worker.join().unwrap(), Err(AppError::Cancelled)));
    release.send(()).unwrap();
    await_cleanup(&f.reader);
}

fn await_cleanup(reader: &OriginalReader) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while reader.busy.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!reader.busy.load(Ordering::Acquire));
}
