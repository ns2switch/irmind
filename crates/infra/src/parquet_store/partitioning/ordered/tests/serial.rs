//! Serial parser contracts exercise bounded producers through the actual writer.
use super::*;
use std::fmt::Write as _;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

struct Exclusive {
    leased: AtomicBool,
    fail_last: bool,
    first_finished: AtomicBool,
}
struct Lease<'a>(&'a AtomicBool);
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl SourceDecoder for Exclusive {
    fn identity(&self) -> irmind_app::ParserIdentity<'_> {
        JsonSourceDecoder.identity()
    }
    fn source_parallelism(&self) -> irmind_app::SourceParallelism {
        irmind_app::SourceParallelism::Serial
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(irmind_domain::Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<irmind_app::ParseReport, AppError> {
        let name = input.metadata.source.reference();
        let cancel = input.metadata.cancel;
        if name == "source-0.json" {
            std::thread::sleep(Duration::from_millis(150));
        }
        while self
            .leased
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let _lease = Lease(&self.leased);
        if name == "source-1.json" {
            assert!(self.first_finished.load(Ordering::Acquire));
        }
        if self.fail_last && name == "source-1.json" {
            return Err(AppError::Policy(
                "synthetic exclusive parser failure".into(),
            ));
        }
        let result = JsonSourceDecoder.decode_reader(input, emit);
        if name == "source-0.json" && result.is_ok() {
            self.first_finished.store(true, Ordering::Release);
        }
        result
    }
}

fn sources() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let mut text = String::new();
    // Queue saturation is tested separately with the actual bounded start permits.
    // This integration test covers canonical starts, signed bytes and rollback.
    for i in 0..32 {
        writeln!(
            text,
            "{{\"eventTime\":\"2026-11-01T00:00:00Z\",\"eventName\":\"Read\",\"id\":{i}}}"
        )
        .unwrap();
    }
    for i in 0..2 {
        let content = text.replace("\"id\":", &format!("\"source_shard\":{i},\"id\":"));
        std::fs::write(root.path().join(format!("source-{i}.json")), content).unwrap();
    }
    root
}
#[test]
fn canonical_starts_keep_an_exclusive_later_producer_from_blocking_the_first() {
    for fail_last in [false, true] {
        let inputs = sources();
        let data = tempfile::tempdir().unwrap();
        let cancel = CancellationToken::new();
        let operation = cancel.clone();
        let data_path = data.path().to_owned();
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let parser = Arc::new(Exclusive {
                leased: AtomicBool::new(false),
                fail_last,
                first_finished: AtomicBool::new(false),
            });
            let store = store(&data_path, parser.clone());
            let paths = ["source-0.json".into(), "source-1.json".into()];
            let id = case();
            let req = request(inputs.path(), &id, &paths);
            let result = store.prepare_mapped_ingest(req, &operation);
            if fail_last {
                assert_eq!(regular_files(&store.case_dir(&id).unwrap()), 0);
            }
            send.send(result.map(|rows| rows.unwrap().metadata().sources.len()))
                .unwrap();
        });
        let result = receive.recv_timeout(Duration::from_secs(10));
        if result.is_err() {
            cancel.cancel();
        }
        worker.join().unwrap();
        assert!(
            result.is_ok(),
            "serial producer pipeline stopped making progress"
        );
        let result = result.unwrap();
        if fail_last {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("synthetic exclusive")
            );
        } else {
            assert_eq!(result.unwrap(), 2);
        }
        assert!(
            !cancel.is_cancelled(),
            "internal batch completion must not cancel the caller"
        );
    }
}
#[test]
fn cancelling_a_waiting_serial_batch_releases_every_producer() {
    let inputs = sources();
    let data = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();
    let operation = cancel.clone();
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let parser = Arc::new(Exclusive {
            leased: AtomicBool::new(false),
            fail_last: false,
            first_finished: AtomicBool::new(false),
        });
        let store = store(data.path(), parser.clone());
        let paths = ["source-0.json".into(), "source-1.json".into()];
        let id = case();
        let req = request(inputs.path(), &id, &paths);
        let result = store.prepare_mapped_ingest(req, &operation);
        assert_eq!(regular_files(&store.case_dir(&id).unwrap()), 0);
        send.send(matches!(result, Err(AppError::Cancelled)))
            .unwrap();
    });
    std::thread::sleep(Duration::from_millis(30));
    cancel.cancel();
    assert!(receive.recv_timeout(Duration::from_secs(3)).unwrap());
    worker.join().unwrap();
}

#[test]
fn serial_scheduling_preserves_the_concurrent_artifact_bytes() {
    let inputs = sources();
    let serial_root = tempfile::tempdir().unwrap();
    let concurrent_root = tempfile::tempdir().unwrap();
    let parser = Arc::new(Exclusive {
        leased: AtomicBool::new(false),
        fail_last: false,
        first_finished: AtomicBool::new(false),
    });
    let serial = store(serial_root.path(), parser);
    let concurrent = store(concurrent_root.path(), Arc::new(JsonSourceDecoder));
    let paths = ["source-0.json".into(), "source-1.json".into()];
    let id = case();
    let cancel = CancellationToken::new();
    let mut actual = serial
        .prepare_mapped_ingest(request(inputs.path(), &id, &paths), &cancel)
        .unwrap()
        .unwrap();
    let mut expected = concurrent
        .prepare_mapped_ingest(request(inputs.path(), &id, &paths), &cancel)
        .unwrap()
        .unwrap();
    assert_eq!(actual.metadata().sources.len(), 2);
    assert_eq!(
        actual.metadata().projections.len(),
        expected.metadata().projections.len()
    );
    actual.publish(&cancel).unwrap();
    expected.publish(&cancel).unwrap();
    for (a, b) in actual
        .metadata()
        .sources
        .iter()
        .zip(&expected.metadata().sources)
    {
        assert_eq!(a.manifest, b.manifest);
    }
    for (a, b) in actual
        .metadata()
        .projections
        .iter()
        .zip(&expected.metadata().projections)
    {
        assert_eq!(a.physical(), b.physical());
        assert_eq!(
            std::fs::read(serial.case_dir(&id).unwrap().join(&a.physical().path)).unwrap(),
            std::fs::read(concurrent.case_dir(&id).unwrap().join(&b.physical().path)).unwrap()
        );
    }
}
