#![no_main]
use irmind_app::{
    CancellationToken, LogParser as _, SourceDecoder as _, SourceMapper as _, sha256,
};
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
    static MAPPERS: std::sync::OnceLock<Vec<irmind_mod_mapping_kubernetes::KubernetesMapping>> =
        std::sync::OnceLock::new();
    let mappers = MAPPERS.get_or_init(|| {
        irmind_mod_mapping_kubernetes::KubernetesMapping::all().expect("included mappings")
    });
    for (provider, id) in [
        (ClusterProvider::Kubernetes, "urn:k8s:fuzz"),
        (
            ClusterProvider::Eks,
            "arn:aws:eks:us-east-1:111122223333:cluster/synthetic-cluster",
        ),
        (
            ClusterProvider::Aks,
            "/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/synthetic/providers/Microsoft.ContainerService/managedClusters/synthetic-cluster",
        ),
    ] {
        let cluster = ClusterIdentity::try_new(provider, id).expect("fixed identity");
        let context = SourceClusterContext::try_new(vec![
            SourceClusterBinding::try_new(cluster, ClusterContextBasis::Analyst, None)
                .expect("fixed binding"),
        ])
        .expect("fixed context");
        for context in [None, Some(&context)] {
            let _ = irmind_mod_parser_kubernetes::KubernetesSourceDecoder.decode_reader(
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
                &mut |row| {
                    row.inspect(|source| {
                        for mapper in mappers {
                            if mapper
                                .manifest()
                                .selectors()
                                .iter()
                                .any(|s| s.matches(source))
                            {
                                let _ = mapper.map(source);
                            }
                        }
                    });
                    Ok(())
                },
            );
        }
    }
    let parser = irmind_mod_parser_kubernetes::KubernetesParser::default();
    let _ = parser.detect("fuzz.ndjson", bytes);
    let _ = parser.cluster_context_requirement("fuzz.ndjson", bytes);
});
