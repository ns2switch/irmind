#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
use irmind_process_containment::{Mode, Program};
use std::{
    fs::File,
    io::Read as _,
    path::Path,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn execute(mode: Mode) -> (bool, String, String) {
    let root = tempfile::tempdir().unwrap();
    let program = Program::new(Path::new(env!("CARGO_BIN_EXE_irmind-evtx")), root.path()).unwrap();
    let source = File::open(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/testkit/fixtures/parser-evtx/source/Security.evtx"),
    )
    .unwrap();
    let mut child = program.spawn(&source, mode).unwrap();
    let stdout = child.take_stdout().unwrap();
    let stderr = child.take_stderr().unwrap();
    let (send, receive) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut text = String::new();
        stdout.take(1024 * 1024).read_to_string(&mut text).unwrap();
        send.send(text).unwrap();
    });
    let err = thread::spawn(move || {
        let mut text = String::new();
        stderr.take(65536).read_to_string(&mut text).unwrap();
        text
    });
    let start = Instant::now();
    let success = loop {
        if let Some(success) = child.try_wait().unwrap() {
            break success;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "contained helper did not exit"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let out = receive.recv_timeout(Duration::from_secs(5)).unwrap();
    reader.join().unwrap();
    let mut errors = err.join().unwrap();
    if !success {
        errors.push_str(&child.exit_description().unwrap().unwrap_or_default());
    }
    drop(child);
    drop(program);
    assert_eq!(
        std::fs::read_dir(root.path()).unwrap().count(),
        0,
        "runtime files leaked"
    );
    (success, out, errors)
}

#[test]
fn native_containment_denies_file_and_network_access_before_decoding() {
    let (success, out, err) = execute(Mode::Probe);
    assert!(success, "probe failed: {err}");
    let result: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(result["isolated"], true);
}
#[test]
fn native_contained_decoder_reads_inherited_input_without_filesystem_access() {
    let (success, out, err) = execute(Mode::Decode);
    assert!(success, "decode failed: {err}");
    let last = out.lines().last().unwrap();
    let frame: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(frame["accepted"], 14);
    assert_eq!(frame["rejected"], 0);
}

#[test]
fn parser_module_passes_seekable_contract_and_preserves_100ns_provenance() {
    let root = tempfile::tempdir().unwrap();
    let parser = irmind_mod_parser_evtx::EvtxParser::new(
        Path::new(env!("CARGO_BIN_EXE_irmind-evtx")),
        root.path(),
    );
    assert!(
        parser.unavailable_reason().is_none(),
        "{:?}",
        parser.unavailable_reason()
    );
    for (name, count) in [
        ("Security", 14),
        ("System", 1),
        ("Microsoft-Windows-PowerShell", 2),
        ("Microsoft-Windows-Sysmon", 10),
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../crates/testkit/fixtures/parser-evtx/source/{name}.evtx"
        ));
        let mut file = File::open(path).unwrap();
        irmind_testkit::run_seekable_log_parser_contract(
            &parser,
            &format!("{name}.evtx"),
            &mut file,
            count,
        )
        .unwrap();
    }
    drop(parser);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn termination_reaps_a_decoder_blocked_on_its_output_and_removes_runtime() {
    let root = tempfile::tempdir().unwrap();
    let program = Program::new(Path::new(env!("CARGO_BIN_EXE_irmind-evtx")), root.path()).unwrap();
    let fixture =
        include_bytes!("../../../crates/testkit/fixtures/parser-evtx/source/Security.evtx");
    let mut bytes = fixture[..4096].to_vec();
    bytes[16..24].copy_from_slice(&7u64.to_le_bytes());
    bytes[42..44].copy_from_slice(&8u16.to_le_bytes());
    let crc = evtx::checksum_ieee(&bytes[..120]);
    bytes[124..128].copy_from_slice(&crc.to_le_bytes());
    for _ in 0..8 {
        bytes.extend_from_slice(&fixture[4096..]);
    }
    let path = root.path().join("synthetic-blocked-output.evtx");
    std::fs::write(&path, bytes).unwrap();
    let source = File::open(&path).unwrap();
    let mut child = program.spawn(&source, Mode::Decode).unwrap();
    thread::sleep(Duration::from_millis(100));
    assert!(
        child.try_wait().unwrap().is_none(),
        "the fixture must block on its undrained output pipe"
    );
    child.terminate().unwrap();
    assert_eq!(child.try_wait().unwrap(), Some(false));
    drop(child);
    drop(program);
    drop(source);
    std::fs::remove_file(path).unwrap();
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn parent_cancellation_aborts_without_a_complete_report_and_cleans_up() {
    use irmind_app::CancellationToken;
    use irmind_app::StreamingEventParser as _;
    let root = tempfile::tempdir().unwrap();
    let parser = irmind_mod_parser_evtx::EvtxParser::new(
        Path::new(env!("CARGO_BIN_EXE_irmind-evtx")),
        root.path(),
    );
    let mut source = File::open(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/testkit/fixtures/parser-evtx/source/Security.evtx"),
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let mut count = 0;
    let result = parser.parse_local_file_report(
        "synthetic.evtx",
        &mut source,
        [0; 32],
        &cancel,
        &mut |_| {
            count += 1;
            cancel.cancel();
            Ok(())
        },
    );
    assert!(matches!(result, Err(irmind_app::AppError::Cancelled)));
    assert_eq!(count, 1);
    drop(parser);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn normalized_eventdata_fields_are_entities_not_just_preserved_attributes() {
    use irmind_app::{CancellationToken, StreamingEventParser as _};
    let root = tempfile::tempdir().unwrap();
    let parser = irmind_mod_parser_evtx::EvtxParser::new(
        Path::new(env!("CARGO_BIN_EXE_irmind-evtx")),
        root.path(),
    );
    let mut file = File::open(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/testkit/fixtures/parser-evtx/source/Security.evtx"),
    )
    .unwrap();
    let mut count = 0;
    parser
        .parse_indexed_local_file_report(
            "Security.evtx",
            &mut file,
            [1; 32],
            &CancellationToken::new(),
            &mut |row| {
                row.inspect(|row| {
                    assert!(
                        row.record
                            .entities
                            .contains(&("user".into(), "synthetic-user".into())),
                        "{}",
                        row.record.text
                    );
                    assert!(
                        row.record
                            .entities
                            .contains(&("ip".into(), "203.0.113.77".into()))
                    );
                    assert_eq!(row.time.unwrap().instant().submicro_nanos(), 700);
                });
                count += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(count, 14);
}
