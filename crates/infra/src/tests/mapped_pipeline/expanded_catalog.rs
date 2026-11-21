use super::*;
use irmind_app::source_mapping::{
    MappingError, MappingManifest, MappingOutput, MappingProvenance, SourceInput, SourceSelector,
};
use irmind_app::{ParserIdentity, SourceMapper};
use irmind_domain::{
    COMMON_EVENT_V1, EvidenceHash, MappingIdentityV1, MappingProfileRecordV1, SourceRecordV1,
    Tainted,
};
use irmind_testkit::FixedClock;
use std::collections::BTreeSet;
use std::num::NonZeroU16;

struct OtherDecoder;

impl SourceDecoder for OtherDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-synthetic-other",
            version: "decoder-v1",
        }
    }

    fn decode_reader(
        &self,
        _: SourceInput<'_>,
        _: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<irmind_app::ParseReport, AppError> {
        Err(AppError::Policy("unrelated test decoder".into()))
    }
}

struct OtherMapper(MappingManifest);

impl SourceMapper for OtherMapper {
    fn manifest(&self) -> &MappingManifest {
        &self.0
    }

    fn map(&self, _: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        Err(MappingError::InvalidOutput)
    }
}

fn expanded_catalog(other_count: usize) -> Arc<MappingCatalog> {
    let mut mappings: Vec<Arc<dyn SourceMapper>> =
        vec![Arc::new(JsonCompatibilityMapping::new().unwrap())];
    let identity = OtherDecoder.identity();
    for index in 0..other_count {
        let id = format!("mapping-other-{index:02}");
        let selector = SourceSelector::try_new(
            identity.name,
            BTreeSet::from([identity.version.to_owned()]),
            Some((format!("fixture-{index:02}"), "1".into())),
            BTreeMap::new(),
            vec![],
        )
        .unwrap();
        let mapping = MappingIdentityV1::try_new(
            &id,
            "1",
            COMMON_EVENT_V1,
            EvidenceHash::from_bytes(sha256(id.as_bytes())),
        )
        .unwrap();
        mappings.push(Arc::new(OtherMapper(
            MappingManifest::try_new(
                mapping,
                vec![selector],
                MappingProvenance::NativeBuild {
                    manifest: id.into_bytes(),
                },
                false,
            )
            .unwrap(),
        )));
    }
    Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(JsonSourceDecoder), Arc::new(OtherDecoder)],
            mappings,
        )
        .unwrap(),
    )
}

#[test]
fn expanded_catalog_groups_and_artifacts_are_identical_with_one_or_many_workers() {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("originals");
    fs::create_dir(&originals).unwrap();
    let paths = write_disordered_sources(&originals);
    let catalog = expanded_catalog(64);
    assert_eq!(catalog.manifests().len(), 65);
    assert_eq!(
        catalog
            .for_decoder(OtherDecoder.identity())
            .manifests()
            .len(),
        64
    );
    let seed = root.path().join("seed");
    let (_, engine, _) = fixture_catalog(&seed, catalog.clone());
    let case = engine
        .create_case("Expanded registry", "local only")
        .unwrap();
    drop(engine);

    let reversed = paths.iter().rev().cloned().collect::<Vec<_>>();
    let run = |cap, input: &[String]| {
        let dir = root.path().join(format!("run-{cap}"));
        fs::create_dir(&dir).unwrap();
        fs::copy(seed.join("irmind.db"), dir.join("irmind.db")).unwrap();
        let (store, engine, _) = fixture_with_clock(
            &dir,
            catalog.clone(),
            Arc::new(FixedClock::new(1_793_491_200)),
        );
        store.set_parallel_worker_limit(NonZeroU16::new(cap));
        let parser = catalog
            .decoder_selection("parser-json", "json-source-v1")
            .unwrap();
        let cancel = CancellationToken::new();
        let large = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: &parser,
        };
        assert_eq!(
            large
                .ingest_local_batch(&case.id, &originals, input, false, &cancel)
                .unwrap()
                .len(),
            paths.len()
        );
        assert_eq!(
            large
                .verify_parquet_rebuild(&case.id, &originals, &cancel)
                .unwrap(),
            paths.len()
        );
        let entries = store.entries(&case.id).unwrap();
        let profiles = verify_profile_groups(&entries);
        let files = irmind_app::artifact_catalog(&entries)
            .unwrap()
            .active
            .into_iter()
            .map(|artifact| {
                fs::read(
                    store
                        .parquet
                        .owned_case_path(&case.id)
                        .join(artifact.path()),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(!files.is_empty());
        engine.seal(&case.id).unwrap();
        let export = dir.join("case.irmind");
        let key =
            irmind_app::export_case(&engine, store.as_ref(), &case.id, &export, &cancel).unwrap();
        LocalExportVerifier
            .verify_export_details(&export, Some(&key))
            .unwrap();
        (profiles, files, fs::read(export).unwrap())
    };
    assert_eq!(run(1, &paths), run(256, &reversed));
}

fn write_disordered_sources(originals: &Path) -> Vec<String> {
    (0..=irmind_app::mapped_ingest::MAPPED_GROUP_SOURCES)
        .map(|index| {
            let path = format!("fixture-{index:03}.ndjson");
            let row = |second| format!(
                r#"{{"eventTime":"2026-11-01T00:00:{second:02}Z","eventName":"Synthetic{index}","sourceIPAddress":"203.0.113.77"}}"#
            );
            // Two decreasing timestamps force the external merge path.
            fs::write(originals.join(&path), format!("{}\n{}\n", row(2), row(1))).unwrap();
            path
        })
        .collect::<Vec<_>>()
}

fn verify_profile_groups(
    entries: &[irmind_app::SignedEntry],
) -> Vec<irmind_domain::MappingProfileV1> {
    let profiles = read_profiles(entries);
    assert_eq!(
        profiles
            .iter()
            .map(|p| p.inputs().len())
            .collect::<Vec<_>>(),
        [128, 1]
    );
    assert!(profiles.iter().all(|p| p.catalog().len() == 1));
    profiles
}

#[test]
fn signed_historical_profile_reconstructs_and_exports_identically_after_registry_growth() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("originals");
    fs::create_dir(&input).unwrap();
    fs::write(
        input.join("historical.json"),
        br#"{"eventTime":"2026-11-01T00:00:01Z","eventName":"Read","sourceIPAddress":"203.0.113.77"}"#,
    ).unwrap();
    let storage = root.path().join("case-data");
    let clock = Arc::new(FixedClock::new(1_793_491_200));
    let cancel = CancellationToken::new();
    let (store, engine, catalog) =
        fixture_with_clock(&storage, expanded_catalog(63), clock.clone());
    let case = engine
        .create_case("Synthetic historical group", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    assert_eq!(
        large
            .ingest_local_batch(
                &case.id,
                &input,
                &["historical.json".into()],
                false,
                &cancel
            )
            .unwrap()
            .len(),
        1
    );
    let entries = store.entries(&case.id).unwrap();
    let profiles = read_profiles(&entries);
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].catalog().len(), 64);
    engine.seal(&case.id).unwrap();
    let signed_before = root.path().join("before.irmind");
    let key = irmind_app::export_case(&engine, store.as_ref(), &case.id, &signed_before, &cancel)
        .unwrap();
    drop(engine);
    drop(store);

    let (store, engine, catalog) = fixture_with_clock(&storage, expanded_catalog(64), clock);
    assert_eq!(catalog.manifests().len(), 65);
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    engine.verify(&case.id).unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    assert_eq!(
        large
            .verify_parquet_rebuild(&case.id, &input, &cancel)
            .unwrap(),
        1
    );
    let signed_after = root.path().join("after.irmind");
    assert_eq!(
        irmind_app::export_case(&engine, store.as_ref(), &case.id, &signed_after, &cancel).unwrap(),
        key
    );
    LocalExportVerifier
        .verify_export_details(&signed_after, Some(&key))
        .unwrap();
    assert_eq!(
        fs::read(signed_before).unwrap(),
        fs::read(signed_after).unwrap()
    );
}

fn read_profiles(entries: &[irmind_app::SignedEntry]) -> Vec<irmind_domain::MappingProfileV1> {
    entries
        .iter()
        .filter(|e| e.kind == AuditEventKind::MappingProfileV1)
        .filter_map(
            |entry| match MappingProfileRecordV1::decode(&entry.payload).unwrap() {
                MappingProfileRecordV1::Profile(p) => Some(p),
                MappingProfileRecordV1::Snapshot(_) => None,
            },
        )
        .collect::<Vec<_>>()
}
