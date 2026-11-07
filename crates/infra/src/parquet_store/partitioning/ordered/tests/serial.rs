//! Serial parser contracts exercise bounded producers through the actual writer.
use super::*;
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
}
struct Lease<'a>(&'a AtomicBool);
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl StreamingEventParser for Exclusive {
    fn source_parallelism(&self, _: &str) -> Result<irmind_app::SourceParallelism, AppError> {
        Ok(irmind_app::SourceParallelism::Serial)
    }
    fn streaming_version(&self) -> &'static str {
        JsonParser.streaming_version()
    }
    fn parser_name(&self) -> &'static str {
        JsonParser.parser_name()
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
        // Without canonical start permits, the later source can take the lease
        // first and fill its bounded queue before the first source is consumed.
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
        if self.fail_last && name == "source-1.json" {
            return Err(AppError::Policy(
                "synthetic exclusive parser failure".into(),
            ));
        }
        JsonParser.parse_reader(name, reader, hash, cancel, emit)
    }
}
fn sources() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let mut text = String::new();
    for i in 0..20_000 {
        writeln!(
            text,
            "{{\"eventTime\":\"2026-11-01T00:00:00Z\",\"eventName\":\"Read\",\"id\":{i}}}"
        )
        .unwrap();
    }
    for i in 0..2 {
        std::fs::write(root.path().join(format!("source-{i}.json")), &text).unwrap();
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
            let store = ParquetStore::open_precise(&data_path).unwrap();
            let parser = Exclusive {
                leased: AtomicBool::new(false),
                fail_last,
            };
            let paths = ["source-0.json".into(), "source-1.json".into()];
            let id = case();
            let mut req = request(inputs.path(), &id, &paths);
            req.parser = &parser;
            let result = store.prepare_local_batch(req, &operation);
            if fail_last {
                assert_eq!(regular_files(&store.case_dir(&id).unwrap()), 0);
            }
            send.send(result.map(|rows| rows.len())).unwrap();
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
        let store = ParquetStore::open_precise(data.path()).unwrap();
        let parser = Exclusive {
            leased: AtomicBool::new(false),
            fail_last: false,
        };
        let paths = ["source-0.json".into(), "source-1.json".into()];
        let id = case();
        let mut req = request(inputs.path(), &id, &paths);
        req.parser = &parser;
        let result = store.prepare_local_batch(req, &operation);
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
    let serial = ParquetStore::open_precise(serial_root.path()).unwrap();
    let concurrent = ParquetStore::open_precise(concurrent_root.path()).unwrap();
    let parser = Exclusive {
        leased: AtomicBool::new(false),
        fail_last: false,
    };
    let paths = ["source-0.json".into(), "source-1.json".into()];
    let id = case();
    let mut req = request(inputs.path(), &id, &paths);
    req.parser = &parser;
    let actual = serial
        .prepare_local_batch(req, &CancellationToken::new())
        .unwrap();
    let expected = concurrent
        .prepare_local_batch(
            request(inputs.path(), &id, &paths),
            &CancellationToken::new(),
        )
        .unwrap();
    for (actual, expected) in actual.iter().zip(&expected) {
        assert_eq!(actual.manifest, expected.manifest);
        assert_eq!(actual.artifacts, expected.artifacts);
        for artifact in &actual.artifacts {
            assert_eq!(
                std::fs::read(serial.case_dir(&id).unwrap().join(artifact.path())).unwrap(),
                std::fs::read(concurrent.case_dir(&id).unwrap().join(artifact.path())).unwrap()
            );
        }
    }
}
