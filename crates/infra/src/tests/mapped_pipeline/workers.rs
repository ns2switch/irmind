use super::*;
use irmind_testkit::FixedClock;
use std::num::NonZeroU16;

#[test]
fn worker_caps_preserve_parquet_and_the_complete_signed_chain() {
    let root = tempfile::tempdir().unwrap();
    let inputs = root.path().join("sources");
    fs::create_dir(&inputs).unwrap();
    let paths = write_sources(&inputs);
    compare_worker_counts(root.path(), &inputs, &paths);
}

#[test]
fn one_ndjson_source_preserves_signed_bytes_with_parallel_record_decoding() {
    use std::io::Write as _;
    let root = tempfile::tempdir().unwrap();
    let inputs = root.path().join("sources");
    fs::create_dir(&inputs).unwrap();
    let name = "synthetic.ndjson";
    let mut out = std::io::BufWriter::new(fs::File::create(inputs.join(name)).unwrap());
    for index in 0..800 {
        if index == 223 {
            // A valid JSON frame that fails the existing timestamp contract.
            out.write_all(b"{\"eventTime\":\"invalid\"}\r\n").unwrap();
        }
        writeln!(out, r#"{{"eventTime":"2026-11-01T00:00:01.123456789Z","eventName":"Synthetic{index}","sourceIPAddress":"203.0.113.77"}}"#).unwrap();
    }
    out.flush().unwrap();
    drop(out);
    compare_worker_counts(root.path(), &inputs, &[name.into()]);
}

fn compare_worker_counts(root: &Path, inputs: &Path, paths: &[String]) {
    let seed = root.join("seed");
    let (_, engine, catalog) = fixture(&seed);
    let case = engine
        .create_case("Synthetic concurrency", "local only")
        .unwrap();
    drop(engine);
    let clock = Arc::new(FixedClock::new(1_793_491_200));
    let mut expected = None;
    for cap in [1, 2, 4, 256] {
        let run = root.join(format!("workers-{cap}"));
        fs::create_dir(&run).unwrap();
        fs::copy(seed.join("irmind.db"), run.join("irmind.db")).unwrap();
        let (store, engine, catalog) = fixture_with_clock(&run, catalog.clone(), clock.clone());
        store.set_parallel_worker_limit(NonZeroU16::new(cap));
        let parser = catalog
            .decoder_selection("parser-json", "json-source-v1")
            .unwrap();
        let ingest = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: &parser,
        };
        let cancel = CancellationToken::new();
        assert_eq!(
            ingest
                .ingest_local_batch(&case.id, inputs, paths, false, &cancel)
                .unwrap()
                .len(),
            paths.len()
        );
        engine.verify(&case.id).unwrap();
        assert_eq!(
            ingest
                .verify_parquet_rebuild(&case.id, inputs, &cancel)
                .unwrap(),
            paths.len()
        );
        let entries = store.entries(&case.id).unwrap();
        let hashes = entries.iter().map(|entry| entry.hash).collect::<Vec<_>>();
        let inventory = irmind_app::artifact_catalog(&entries).unwrap().active;
        assert!(!inventory.is_empty());
        assert!(
            inventory
                .iter()
                .all(|artifact| matches!(artifact, ParquetArtifact::V3(_)))
        );
        if let Some(expected) = &expected {
            assert_eq!(&(hashes, inventory), expected);
        } else {
            expected = Some((hashes, inventory));
        }
    }
}

fn write_sources(root: &Path) -> Vec<String> {
    (0..12).map(|source| {
        let path = format!("source-{source:02}.json");
        // Include a disorder fallback as well as different partitions and ties.
        let first = if source == 5 { "02" } else { "00" };
        let event = |time| format!(r#"{{"eventTime":"2026-11-01T00:00:{time}.123456789Z","eventName":"Synthetic{source}","recipientAccountId":"1234567890{source:02}","awsRegion":"eu-west-1","sourceIPAddress":"203.0.113.77"}}"#);
        let raw = format!(r#"{{"Records":[{},{}]}}"#, event(first), event("01"));
        fs::write(root.join(&path), raw).unwrap();
        path
    }).collect()
}

mod benchmark;
