#![cfg(windows)]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
mod support;
use irmind_process_containment::Program;
use std::{
    fs::File,
    io::Read as _,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
fn probe(program: &Program) {
    let mut child = program.probe().unwrap();
    let stdout = child.take_stdout().unwrap();
    let stderr = child.take_stderr().unwrap();
    let (send, receive) = mpsc::sync_channel(1);
    let output = thread::spawn(move || {
        let mut bytes = String::new();
        stdout.take(4096).read_to_string(&mut bytes).unwrap();
        send.send(bytes).unwrap();
    });
    let errors = thread::spawn(move || {
        let mut bytes = String::new();
        stderr.take(65536).read_to_string(&mut bytes).unwrap();
        bytes
    });
    let start = Instant::now();
    let success = loop {
        if let Some(success) = child.try_wait().unwrap() {
            break success;
        }
        assert!(start.elapsed() < Duration::from_secs(15));
        thread::sleep(Duration::from_millis(10));
    };
    let bytes = receive.recv_timeout(Duration::from_secs(5)).unwrap();
    output.join().unwrap();
    assert!(success, "{}", errors.join().unwrap());
    assert!(bytes.contains("\"isolated\":true"));
}
#[test]
fn full_witness_is_cached_only_in_memory_and_repeated_after_invalidation() {
    let root = tempfile::tempdir().unwrap();
    let program = Program::new(&support::helper_path(), root.path()).unwrap();
    assert_eq!(program.witness_stats().attempts, 0);
    probe(&program);
    probe(&program);
    assert_eq!(program.witness_stats().attempts, 1);
    program.invalidate();
    probe(&program);
    assert_eq!(program.witness_stats().attempts, 2);
    drop(program);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    let fresh = Program::new(&support::helper_path(), root.path()).unwrap();
    assert_eq!(fresh.witness_stats().attempts, 0);
}
#[test]
fn a_cancelled_launch_does_not_read_evidence_or_start_the_witness() {
    let root = tempfile::tempdir().unwrap();
    let program = Program::new(&support::helper_path(), root.path()).unwrap();
    let source = File::open(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/testkit/fixtures/parser-evtx/source/Security.evtx"),
    )
    .unwrap();
    assert_eq!(
        program
            .spawn_cancelable(&source, irmind_process_containment::Mode::Decode, &|| true)
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::Interrupted
    );
    assert_eq!(program.witness_stats().attempts, 0);
}

#[test]
fn parser_reader_cleanup_retains_the_successful_session_witness() {
    use irmind_app::{
        CancellationToken, SourceDecoder as _,
        source_mapping::{SourceFileInput, SourceMetadata},
    };
    let root = tempfile::tempdir().unwrap();
    let parser = irmind_mod_parser_evtx::EvtxParser::new(&support::helper_path(), root.path());
    assert!(
        parser.unavailable_reason().is_none(),
        "{:?}",
        parser.unavailable_reason()
    );
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/testkit/fixtures/parser-evtx/source/Security.evtx");
    for _ in 0..2 {
        let mut file = File::open(&source).unwrap();
        let reference = irmind_domain::SourceReferenceV1::file("Security.evtx").unwrap();
        let cancel = CancellationToken::new();
        let report = parser
            .decode_local_file(
                SourceFileInput {
                    file: &mut file,
                    metadata: SourceMetadata {
                        source: &reference,
                        evidence_hash: [1; 32],
                        time_context: None,
                        cluster_context: None,
                        cancel: &cancel,
                    },
                },
                &mut |_| Ok(()),
            )
            .unwrap();
        assert_eq!(report.accepted, 14);
        assert_eq!(parser.witness_stats().attempts, 1);
    }
}
