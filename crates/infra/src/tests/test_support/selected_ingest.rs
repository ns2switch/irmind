use super::*;
use irmind_app::LargeCaseUseCases;

/// The benchmark makes an explicit parser choice, just like --parser, for both
/// wire versions. V2 must retain the same signed parser-selection requirement.
pub(in crate::tests) fn ingest_selected(
    ingest: &LargeCaseUseCases<'_, '_>,
    id: &CaseId,
    root: &Path,
    names: &[String],
) -> usize {
    use std::io::Read as _;
    let selections = names
        .iter()
        .map(|name| {
            let mut sample = Vec::new();
            fs::File::open(root.join(name))
                .unwrap()
                .take(65536)
                .read_to_end(&mut sample)
                .unwrap();
            let identity = ingest.parser.identity_for_source(name).unwrap();
            (
                name.clone(),
                irmind_app::ParserSelection {
                    parser_id: identity.name.into(),
                    parser_version: identity.version.into(),
                    confidence: 100,
                    mode: irmind_domain::ParserSelectionMode::Forced,
                    timestamp_context: None,
                    format_sample_sha256: irmind_app::sha256(&sample),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    ingest
        .ingest_local_batch_selected(
            id,
            root,
            names,
            false,
            &selections,
            &CancellationToken::new(),
        )
        .unwrap()
        .len()
}
