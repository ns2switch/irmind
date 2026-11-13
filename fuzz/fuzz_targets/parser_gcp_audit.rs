#![no_main]
use irmind_app::{CancellationToken, LogParser as _, SourceDecoder as _, sha256};
use irmind_domain::{
    ClusterContextBasis, ClusterIdentity, ClusterProvider, SourceClusterBinding,
    SourceClusterContext,
};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    let source =
        irmind_app::source_mapping::SourceReferenceV1::file("fuzz.ndjson").expect("fixed source");
    let cancel = CancellationToken::new();
    let cluster = ClusterIdentity::try_new(
        ClusterProvider::Gke,
        "projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
    )
    .expect("fixed identity");
    let context = SourceClusterContext::try_new(vec![
        SourceClusterBinding::try_new(cluster, ClusterContextBasis::Analyst, None)
            .expect("fixed binding"),
    ])
    .expect("fixed context");
    for context in [None, Some(&context)] {
        let _ = irmind_mod_parser_gcp_audit::GcpAuditSourceDecoder.decode_reader(
            irmind_app::source_mapping::SourceInput {
                metadata: irmind_app::source_mapping::SourceMetadata {
                    source: &source,
                    evidence_hash: sha256(bytes),
                    time_context: None,
                    cluster_context: context,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |_| Ok(()),
        );
    }
    let parser = irmind_mod_parser_gcp_audit::GcpAuditParser::default();
    let _ = parser.detect("fuzz.ndjson", bytes);
    let _ = parser.cluster_context_requirement("fuzz.ndjson", bytes);
});
