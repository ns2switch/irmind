#![allow(clippy::unwrap_used)]
use super::*;
use arrow::{
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use parquet::arrow::ArrowWriter;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io::Write, sync::Arc};

#[test]
fn frame_reader_cannot_read_adjacent_frames_or_overflow_offsets() {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"beforepayloadafter").unwrap();
    let source = FrameReader {
        file,
        start: 6,
        size: 7,
    };
    assert_eq!(source.get_bytes(0, 7).unwrap().as_ref(), b"payload");
    assert!(source.get_bytes(0, 8).is_err());
    assert!(source.get_bytes(u64::MAX, 1).is_err());
    assert!(source.get_read(8).is_err());
    let mut remaining = Vec::new();
    source
        .get_read(3)
        .unwrap()
        .read_to_end(&mut remaining)
        .unwrap();
    assert_eq!(remaining, b"load");
}

#[test]
fn signed_hash_does_not_replace_validation_of_common_physical_columns() {
    for metadata in [
        HashMap::new(),
        HashMap::from([(
            "irmind.common.schema".into(),
            irmind_domain::COMMON_EVENT_V1.into(),
        )]),
    ] {
        let schema = Arc::new(
            Schema::new(vec![Field::new("unexpected", DataType::Utf8, false)])
                .with_metadata(metadata),
        );
        let mut bytes = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut bytes, schema.clone(), None).unwrap();
        writer.write(&RecordBatch::new_empty(schema)).unwrap();
        writer.close().unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"prefix").unwrap();
        file.write_all(&bytes).unwrap();
        file.write_all(b"next frame").unwrap();
        file.seek(SeekFrom::Start(6)).unwrap();
        assert!(
            verify_common(
                &mut file,
                bytes.len() as u64,
                &hash,
                ArtifactSchemaV2::CommonEvents
            )
            .is_err()
        );
        assert_eq!(file.stream_position().unwrap(), 6 + bytes.len() as u64);
    }
}
