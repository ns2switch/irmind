use super::*;
use crate::{ParseReport, source_mapping::SourceInput};
use irmind_domain::Tainted;
struct Decoder;
impl SourceDecoder for Decoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-synthetic",
            version: "source-v1",
        }
    }
    fn decode_reader(
        &self,
        _: SourceInput<'_>,
        _: &mut dyn FnMut(Tainted<super::super::SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        Err(AppError::Cancelled)
    }
}
fn time(source: &str, sample: &[u8]) -> Result<Option<crate::ParserTimeRequirement>, AppError> {
    if source.is_empty() {
        return Err(AppError::Cancelled);
    }
    assert_eq!(sample.len(), 65536);
    Ok(Some(crate::ParserTimeRequirement {
        required: true,
        observed: None,
        hosts: vec![],
    }))
}
#[test]
fn time_detection_is_optional_bounded_and_survives_context_selection() {
    let sample = vec![b'x'; 100_000];
    let plain = SourceDecoderSelection::new(Arc::new(Decoder));
    assert!(
        plain
            .time_context_requirement("synthetic", &sample)
            .unwrap()
            .is_none()
    );
    let timed = plain.with_time_detector(time);
    assert!(
        timed
            .time_context_requirement("synthetic", &sample)
            .unwrap()
            .unwrap()
            .required
    );
    let context =
        crate::ParserTimeContext::new(2026, 0, true, crate::ParserTimeBasis::Analyst).unwrap();
    let configured = timed.with_time_context(&context).unwrap();
    assert_eq!(configured.identity().version, "source-v1");
    assert!(configured.timestamp_context().is_some());
    assert!(
        configured
            .time_context_requirement("synthetic", &sample)
            .unwrap()
            .unwrap()
            .required
    );
}

#[test]
fn immutable_cluster_and_time_selection_survive_private_spool_provenance() {
    use crate::{
        ClusterContextBasis, ClusterIdentity, ClusterProvider, SourceClusterBinding,
        SourceClusterContext,
    };
    let plain = SourceDecoderSelection::new(Arc::new(Decoder));
    assert!(plain.cluster_context().is_none());
    assert!(
        plain
            .cluster_context_requirement("source", &[])
            .unwrap()
            .is_none()
    );
    let identity =
        ClusterIdentity::try_new(ClusterProvider::Kubernetes, "urn:k8s:synthetic").unwrap();
    let context = SourceClusterContext::try_new(vec![
        SourceClusterBinding::try_new(identity, ClusterContextBasis::Analyst, None).unwrap(),
    ])
    .unwrap();
    let selected = plain.with_cluster_context(&context).unwrap();
    let time =
        crate::ParserTimeContext::new(2026, 0, true, crate::ParserTimeBasis::Analyst).unwrap();
    let configured = selected.with_time_context(&time).unwrap();
    let logical = crate::SourceParser::new(configured.as_ref(), "s3://synthetic/audit.json");
    assert_eq!(logical.cluster_context(), Some(&context));
    assert_eq!(logical.timestamp_context(), configured.timestamp_context());
    assert_eq!(
        logical.logical_source("private-spool"),
        "s3://synthetic/audit.json"
    );
    assert_eq!(logical.identity(), plain.identity());
    assert!(plain.cluster_context().is_none());
}
