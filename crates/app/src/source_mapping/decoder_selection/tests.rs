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
