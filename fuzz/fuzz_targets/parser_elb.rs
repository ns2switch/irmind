#![no_main]
use irmind_app::source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1};
use irmind_app::{CancellationToken, LogParser as _, SourceDecoder as _, sha256};
use irmind_mod_parser_elb::{ElbParser, ElbSourceDecoder};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4_194_304 {
        return;
    }
    let source = SourceReferenceV1::file("elb.log").expect("fixed name");
    let cancel = CancellationToken::new();
    let _ = ElbParser.detect("elb.log", bytes);
    let _ = ElbSourceDecoder.decode_reader(
        SourceInput {
            metadata: SourceMetadata {
                source: &source,
                evidence_hash: sha256(bytes),
                time_context: None,
                cluster_context: None,
                cancel: &cancel,
            },
            reader: &mut std::io::Cursor::new(bytes),
        },
        &mut |_| Ok(()),
    );
});
