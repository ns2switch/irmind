use irmind_app::{
    AppError, CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMapper, SourceMetadata},
    source_queries::{QueryCaptureWriter, SourceQueryPageDecoder},
};
use irmind_domain::{EvidenceHash, SourceDecoderIdentityV1, SourceKind, SourceReferenceV1};
use serde_json::Value;
use std::io::Cursor;

/// Compare the exact `CommonEvent` fields from a synthetic local file and its
/// equivalent provider page. Only the source provenance may differ.
///
/// # Panics
/// Panics if the fixture is rejected or the two common events differ.
#[allow(clippy::unwrap_used)]
pub fn assert_capture_mapping_equivalent(
    file: &[u8],
    page: &[u8],
    file_decoder: &dyn SourceDecoder,
    capture_decoder: &dyn SourceQueryPageDecoder,
    file_mapper: &dyn SourceMapper,
    capture_mapper: &dyn SourceMapper,
) {
    let cancel = CancellationToken::new();
    let file_ref = SourceReferenceV1::file("synthetic.json").unwrap();
    let capture_ref = SourceReferenceV1::try_new(
        "queries/0000000000000000000000000000000000000000000000000000000000000000.sqc",
        SourceKind::ToolResult,
        Some(EvidenceHash::from_bytes([2; 32])),
    )
    .unwrap();
    let identity = capture_decoder.identity();
    let mut writer = QueryCaptureWriter::new(
        Cursor::new(Vec::new()),
        EvidenceHash::from_bytes([1; 32]),
        SourceDecoderIdentityV1::try_new(identity.name, identity.version).unwrap(),
        128 * 1024,
        10,
    )
    .unwrap();
    writer
        .stage_inspected_page(&mut Cursor::new(page), capture_decoder, None, 10, &cancel)
        .unwrap();
    let mut capture = Vec::new();
    writer.finish(&mut capture, &cancel).unwrap();
    let local = common_events(file, &file_ref, file_decoder, file_mapper, &cancel).unwrap();
    let remote = common_events(
        &capture,
        &capture_ref,
        capture_decoder,
        capture_mapper,
        &cancel,
    )
    .unwrap();
    assert_eq!(local.len(), 1);
    assert_eq!(remote.len(), 1);
    assert_ne!(local[0]["origin"], remote[0]["origin"]);
    assert_eq!(without_origin(local), without_origin(remote));
}

fn common_events(
    bytes: &[u8],
    source: &SourceReferenceV1,
    decoder: &dyn SourceDecoder,
    mapper: &dyn SourceMapper,
    cancel: &CancellationToken,
) -> Result<Vec<Value>, AppError> {
    let mut events = Vec::new();
    let report = decoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source,
                evidence_hash: irmind_app::sha256(bytes),
                time_context: None,
                cluster_context: None,
                cancel,
            },
            reader: &mut &*bytes,
        },
        &mut |entry| {
            let mut result = Ok(());
            entry.inspect(|row| {
                if source.kind() == SourceKind::ToolResult {
                    assert_eq!(
                        entry.provenance().record_index(),
                        Some(row.origin().record())
                    );
                }
                result = mapper
                    .map(row)
                    .map_err(irmind_app::source_mapping::MappingError::into_app)
                    .and_then(|mapped| {
                        let encoded = irmind_app::encode_common_event(&mapped.record().common)?;
                        let event = serde_json::from_str(&encoded).map_err(|_| {
                            AppError::Policy("synthetic event encoding failed".into())
                        })?;
                        events.push(event);
                        Ok(())
                    });
            });
            result
        },
    )?;
    assert_eq!((report.accepted, report.rejected), (1, 0));
    Ok(events)
}

fn without_origin(mut events: Vec<Value>) -> Vec<Value> {
    for event in &mut events {
        let source = event["origin"]["source"].as_str().map(str::to_owned);
        if let Some(object) = event.as_object_mut() {
            object.remove("origin");
        }
        if let Some(observations) = event["observations"].as_array_mut() {
            for observation in observations {
                let scope = &mut observation["scope"];
                if scope["kind"] == "source_record" {
                    assert_eq!(scope["source"].as_str(), source.as_deref());
                    if let Some(scope) = scope.as_object_mut() {
                        scope.remove("source");
                    }
                }
            }
        }
    }
    events
}
