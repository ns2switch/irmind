#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
use std::io::Cursor;

#[test]
fn synthetic_records_keep_real_offsets_counts_and_100ns_timestamps() {
    for (name, count) in [
        ("Security", 14),
        ("System", 1),
        ("Microsoft-Windows-PowerShell", 2),
        ("Microsoft-Windows-Sysmon", 10),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../crates/testkit/fixtures/parser-evtx/source/{name}.evtx"
        ));
        let bytes = std::fs::read(path).unwrap();
        let mut out = Vec::new();
        irmind_evtx::decode(Cursor::new(&bytes), &mut out).unwrap();
        let lines = out
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice::<serde_json::Value>(l).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), count + 2, "{name}: {lines:?}");
        assert_eq!(lines.last().unwrap()["accepted"], count);
        assert_eq!(lines.last().unwrap()["rejected"], 0);
        for row in &lines[1..lines.len() - 1] {
            let offset = usize::try_from(row["offset"].as_u64().unwrap()).unwrap();
            assert_eq!(&bytes[offset..offset + 4], b"\x2a\x2a\0\0");
            assert_eq!(
                u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap()),
                row["record_id"].as_u64().unwrap()
            );
            assert!(row["timestamp"].as_str().unwrap().ends_with("7Z"));
        }
    }
}

#[test]
fn invalid_headers_chunks_and_partial_files_are_rejected() {
    for bytes in [vec![], vec![0; 4096], vec![0; 8192]] {
        assert!(irmind_evtx::decode(Cursor::new(bytes), &mut Vec::new()).is_err());
    }
    let mut bytes =
        include_bytes!("../../../crates/testkit/fixtures/parser-evtx/source/Security.evtx")
            .to_vec();
    bytes[6000] ^= 1;
    assert!(irmind_evtx::decode(Cursor::new(bytes), &mut Vec::new()).is_err());
}

fn many_chunks() -> Vec<u8> {
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
    bytes
}
#[test]
fn chunk_parallelism_keeps_every_protocol_byte_and_physical_offset_identical() {
    let bytes = many_chunks();
    let mut expected = Vec::new();
    irmind_evtx::decode(Cursor::new(&bytes), &mut expected).unwrap();
    for workers in [1, 2, 4, 8] {
        let mut output = Vec::new();
        irmind_evtx::decode_with_workers(Cursor::new(&bytes), &mut output, workers).unwrap();
        assert_eq!(output, expected, "worker count {workers}");
    }
}
#[test]
fn sink_failure_disconnects_all_bounded_producers_before_joining() {
    use std::{
        io::{self, Write},
        sync::mpsc,
        time::Duration,
    };
    struct Broken {
        remaining: usize,
    }
    impl Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.remaining {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.remaining -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = irmind_evtx::decode_with_workers(
            Cursor::new(many_chunks()),
            &mut Broken { remaining: 1024 },
            4,
        );
        send.send(result.map_err(|e| e.kind())).unwrap();
    });
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(5)).unwrap(),
        Err(io::ErrorKind::BrokenPipe)
    );
}
