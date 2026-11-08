use super::*;
use crate::source_mapping::{
    DecodeAnnotationsV1, MappingManifest, MappingProvenance, SelectorCondition, SelectorPredicate,
    SelectorScalar, SourceFormatV1, SourceInput, SourceNumber, SourcePath, SourceSelector,
    SourceValue,
};
use crate::{AppError, ParseReport, ParserIdentity};
use irmind_domain::{COMMON_EVENT_V1, EventOrigin, EvidenceHash, Tainted};
use std::collections::{BTreeMap, BTreeSet};

struct Decoder;
impl SourceDecoder for Decoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-json",
            version: "json-stream-v3",
        }
    }
    fn decode_reader(
        &self,
        _: SourceInput<'_>,
        _: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        Err(AppError::Policy(
            "test decoder is not an acquisition path".into(),
        ))
    }
}
struct Mapper(MappingManifest);
impl SourceMapper for Mapper {
    fn manifest(&self) -> &MappingManifest {
        &self.0
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        crate::source_mapping::output::unmapped(source)
    }
}
fn selector(conditions: Vec<(&[&str], SelectorPredicate)>) -> SourceSelector {
    SourceSelector::try_new(
        "parser-json",
        BTreeSet::from(["json-stream-v3".into()]),
        None,
        BTreeMap::new(),
        conditions
            .into_iter()
            .map(|(path, predicate)| SelectorCondition {
                path: SourcePath::keys(path).unwrap(),
                predicate,
            })
            .collect(),
    )
    .unwrap()
}
fn mapper(id: &str, selector: SourceSelector) -> Arc<dyn SourceMapper> {
    let content = b"synthetic-native-manifest-v1".to_vec();
    Arc::new(Mapper(
        MappingManifest::try_new(
            MappingIdentityV1::try_new(
                id,
                "1",
                COMMON_EVENT_V1,
                EvidenceHash::from_bytes(crate::sha256(&content)),
            )
            .unwrap(),
            vec![selector],
            MappingProvenance::NativeBuild { manifest: content },
            false,
        )
        .unwrap(),
    ))
}
fn source() -> SourceRecordV1 {
    SourceRecordV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([4; 32]),
            0,
            None,
            "parser-json",
            "json-stream-v3",
        )
        .unwrap(),
        "fixture.json",
        None,
        SourceFormatV1::try_new("json", "1", BTreeMap::new()).unwrap(),
        SourceValue::object(vec![("result".into(), SourceValue::Text("failed".into()))]).unwrap(),
        DecodeAnnotationsV1::default(),
    )
    .unwrap()
}

#[test]
fn frozen_selection_and_atomic_replacement_preserve_the_previous_catalog() {
    let first = mapper("mapping-one", selector(vec![]));
    let frozen = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![first]).unwrap();
    let replacement = mapper(
        "mapping-one",
        selector(vec![(
            &["result"],
            SelectorPredicate::Exact(SelectorScalar::Text("success".into())),
        )]),
    );
    let changed = frozen.changed("mapping-one", Some(replacement)).unwrap();
    assert!(frozen.select(&source()).unwrap().is_some());
    assert!(changed.select(&source()).unwrap().is_none());
    let overlap = mapper("mapping-two", selector(vec![]));
    let failure = frozen.changed("mapping-two", Some(overlap)).err().unwrap();
    assert!(matches!(failure, MappingError::Overlap { .. }));
    if let MappingError::Overlap {
        first,
        second,
        selector,
    } = failure
    {
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("mapping-one", "mapping-two")
        );
        assert!(selector.contains("parser-json@json-stream-v3"));
    }
    assert!(frozen.select(&source()).unwrap().is_some());
}

#[test]
fn finite_selector_intersections_respect_types_presence_ranges_and_nested_paths() {
    use SelectorPredicate::{Exact, IntegerInterval, Missing, Null, Present};
    let scalar = |v: &str| Exact(SelectorScalar::Text(v.into()));
    assert!(
        selector(vec![(&["status"], scalar("0"))])
            .overlap_witness(&selector(vec![(
                &["status"],
                Exact(SelectorScalar::Number(SourceNumber::try_new("0").unwrap()))
            )]))
            .is_none()
    );
    assert!(
        selector(vec![(&["status"], Null)])
            .overlap_witness(&selector(vec![(&["status"], Missing)]))
            .is_none()
    );
    assert!(
        selector(vec![(&["status"], Present)])
            .overlap_witness(&selector(vec![(&["status"], scalar("ok"))]))
            .is_some()
    );
    assert!(
        selector(vec![(
            &["status"],
            IntegerInterval {
                first: 200,
                last: 299
            }
        )])
        .overlap_witness(&selector(vec![(
            &["status"],
            IntegerInterval {
                first: 300,
                last: 399
            }
        )]))
        .is_none()
    );
    assert!(
        selector(vec![(
            &["status"],
            IntegerInterval {
                first: 200,
                last: 299
            }
        )])
        .overlap_witness(&selector(vec![(
            &["status"],
            IntegerInterval {
                first: 299,
                last: 400
            }
        )]))
        .is_some()
    );
    assert!(
        selector(vec![(&["user"], scalar("alice"))])
            .overlap_witness(&selector(vec![(&["user", "name"], Present)]))
            .is_none()
    );
    assert!(
        selector(vec![(&["user"], scalar("alice"))])
            .overlap_witness(&selector(vec![(&["user.name"], Present)]))
            .is_some()
    );
}

#[test]
fn unregistered_versions_and_duplicate_mapping_ids_are_rejected() {
    let mut unknown = selector(vec![]);
    unknown = SourceSelector::try_new(
        unknown.parser(),
        BTreeSet::from(["unknown-version".into()]),
        None,
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        MappingCatalog::freeze(
            vec![Arc::new(Decoder)],
            vec![mapper("mapping-one", unknown)]
        ),
        Err(MappingError::UnsupportedVersion)
    ));
    let first = mapper("mapping-one", selector(vec![]));
    assert!(matches!(
        MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![first.clone(), first]),
        Err(MappingError::DuplicateIdentity)
    ));
}

#[test]
fn no_mapping_retains_time_and_search_text_without_inventing_entities_or_roles() {
    let frozen = MappingCatalog::freeze(vec![Arc::new(Decoder)], Vec::new()).unwrap();
    let (identity, mapped) = frozen.map(&source()).unwrap();
    assert!(identity.is_none());
    assert!(mapped.record().indexed.record.entities.is_empty());
    assert!(mapped.record().indexed.record.relations.is_empty());
    assert_eq!(
        mapped.record().common,
        MappingOutput::unclassified_common(&source()).unwrap()
    );
    assert!(mapped.record().indexed.record.text.contains("failed"));
}
