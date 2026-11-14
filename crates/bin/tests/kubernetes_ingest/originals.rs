use super::*;
use irmind_domain::{EvidenceHash, SourceRecordV1, Tainted};

#[test]
fn native_eks_aks_and_gke_original_reads_replay_the_frozen_acquisition_context() {
    for (name, raw, identity, expected) in fixtures() {
        let root = tempfile::tempdir().unwrap();
        let inputs = root.path().join("input");
        fs::create_dir(&inputs).unwrap();
        let store = Arc::new(current_sources::open(&root.path().join("data")));
        let engine = engine(&store);
        let case = engine
            .create_case("Synthetic transport original", "local only")
            .unwrap();
        fs::write(inputs.join(name), raw).unwrap();
        let cluster = irmind_app::command_cluster_context(Some(identity)).unwrap();
        assert_eq!(
            ingest_with_context(
                &engine,
                store.as_ref(),
                &case.id,
                &inputs,
                name,
                cluster.as_ref()
            ),
            1
        );
        let hash = EvidenceHash::from_bytes(irmind_app::sha256(raw));
        let reader = store.source_evidence_reader();
        reader
            .authorize_local_root(&case.id, &inputs, std::slice::from_ref(&hash))
            .unwrap();
        let record = read_trials(reader.as_ref(), &case.id, &hash, name, raw.len());
        record.inspect(|r| assert_eq!(r.cluster_identity().unwrap().qualified(), identity));
        assert!(fields(&record).contains(expected));
        assert_eq!(record.provenance().record_index(), Some(0));
    }
}
fn read_trials(
    reader: &dyn irmind_app::SourceEvidenceReader,
    case: &irmind_domain::CaseId,
    hash: &EvidenceHash,
    name: &str,
    bytes: usize,
) -> Tainted<SourceRecordV1> {
    let mut selected = None;
    for trial in 0..3 {
        let started = std::time::Instant::now();
        let record = reader
            .read_verified_record(case, hash, 0, &CancellationToken::new())
            .unwrap();
        let seconds = started.elapsed().as_secs_f64();
        if let Some(previous) = &selected {
            assert_eq!(previous, &record);
        }
        if !cfg!(debug_assertions) {
            println!(
                "ORIGINAL_READ_BENCH source={name} bytes={bytes} trial={trial} seconds={seconds:.6}"
            );
        }
        selected = Some(record);
    }
    selected.unwrap()
}
fn fields(record: &Tainted<SourceRecordV1>) -> String {
    let mut value = String::new();
    record.inspect(|r| {
        value = irmind_app::source_mapping::json::render_source_fields(r.fields()).unwrap();
    });
    value
}
fn fixtures() -> Vec<(&'static str, &'static [u8], &'static str, &'static str)> {
    let values = vec![
        (
            "native.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/event.ndjson")
                .as_slice(),
            "kubernetes:urn:k8s:synthetic",
            "auditID",
        ),
        (
            "eks.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/eks-row.ndjson")
                .as_slice(),
            "eks:arn:aws:eks:us-east-1:111122223333:cluster/synthetic-cluster",
            "audit_event",
        ),
        (
            "aks.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-kubernetes/source/aks-row.ndjson")
                .as_slice(),
            "aks:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/synthetic/providers/Microsoft.ContainerService/managedClusters/synthetic-cluster",
            "audit_event",
        ),
    ];
    #[cfg(feature = "parser-gcp-audit")]
    let values = {
        let mut values = values;
        values.push((
            "gke.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-gcp-audit/source/gke.ndjson")
                .as_slice(),
            "gke:projects/synthetic-project/locations/us-central1/clusters/synthetic-cluster",
            "protoPayload",
        ));
        values
    };
    values
}
#[test]
fn rejected_members_do_not_shift_the_accepted_pointer_or_original_offset() {
    let root = tempfile::tempdir().unwrap();
    let inputs = root.path().join("input");
    fs::create_dir(&inputs).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("data")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic rejected member", "local only")
        .unwrap();
    let prefix = b"{\"not_an_event\":true}\n";
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(include_bytes!(
        "../../../testkit/fixtures/parser-kubernetes/source/event.ndjson"
    ));
    fs::write(inputs.join("events.ndjson"), &bytes).unwrap();
    let cluster = context();
    let catalog = current_sources::catalog();
    let selected = catalog
        .select_source(ParserSelectionRequest {
            source: "events.ndjson",
            sample: &bytes,
            parser_override: Some("parser-kubernetes"),
            forced: true,
            time_context: None,
            cluster_context: Some(&cluster),
        })
        .unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: selected.parser.as_ref(),
    }
    .ingest_local_batch_selected(
        &case.id,
        &inputs,
        &["events.ndjson".into()],
        false,
        &BTreeMap::from([("events.ndjson".into(), selected.selection)]),
        &CancellationToken::new(),
    )
    .unwrap();
    let hash = EvidenceHash::from_bytes(irmind_app::sha256(&bytes));
    let reader = store.source_evidence_reader();
    reader
        .authorize_local_root(&case.id, &inputs, std::slice::from_ref(&hash))
        .unwrap();
    let row = reader
        .read_verified_record(&case.id, &hash, 0, &CancellationToken::new())
        .unwrap();
    row.inspect(|r| {
        assert_eq!(r.origin().record(), 0);
        assert_eq!(r.annotations().members()[0].ordinal, 1);
        assert_eq!(r.origin().offset(), Some(prefix.len() as u64));
    });
}
