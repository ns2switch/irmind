use irmind_app::{
    CancellationToken, SourceDecoder, SourceMapper, hex, sha256,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};

pub(super) fn digest(
    decoder: &dyn SourceDecoder,
    mapper: &dyn SourceMapper,
    bytes: &[u8],
    records: usize,
) -> String {
    let source = SourceReferenceV1::file("synthetic.log").unwrap();
    let cancel = CancellationToken::new();
    let mut canonical = Vec::new();
    let report = decoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: sha256(bytes),
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |tainted| {
                tainted.inspect(|record| {
                    let mut input = Vec::new();
                    record.feed_canonical(&mut |bytes| input.extend_from_slice(bytes));
                    append(&mut canonical, &input);
                    let output = mapper.map(record).unwrap();
                    let graph = &output.record().indexed.record;
                    let relations = graph
                        .relations
                        .iter()
                        .map(|r| {
                            (
                                &r.from_kind,
                                &r.from_value,
                                &r.relation,
                                &r.to_kind,
                                &r.to_value,
                            )
                        })
                        .collect::<Vec<_>>();
                    let projection = serde_json::to_vec(&(
                        graph.at.as_str(),
                        graph.event.as_str(),
                        graph.text.as_str(),
                        &graph.entities,
                        relations,
                    ))
                    .unwrap();
                    append(&mut canonical, &projection);
                    append(
                        &mut canonical,
                        irmind_app::encode_common_event(&output.record().common)
                            .unwrap()
                            .as_bytes(),
                    );
                });
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected), (records, 0));
    hex(&sha256(&canonical))
}
fn append(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}
