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

#[test]
fn owned_chunks_match_every_frame_with_one_two_four_and_seven_workers() {
    let fixture =
        include_bytes!("../../../crates/testkit/fixtures/parser-evtx/source/Security.evtx");
    let mut bytes = fixture[..4096].to_vec();
    bytes[16..24].copy_from_slice(&7u64.to_le_bytes());
    bytes[42..44].copy_from_slice(&8u16.to_le_bytes());
    let checksum = evtx::checksum_ieee(&bytes[..120]);
    bytes[124..128].copy_from_slice(&checksum.to_le_bytes());
    for _ in 0..8 {
        bytes.extend_from_slice(&fixture[4096..]);
    }
    let mut reference = Vec::new();
    irmind_evtx::decode(Cursor::new(&bytes), &mut reference).unwrap();
    for workers in [2, 4, 7] {
        let mut result = Vec::new();
        irmind_evtx::decode_with_workers(Cursor::new(&bytes), &mut result, workers).unwrap();
        assert_eq!(result, reference);
    }
}
