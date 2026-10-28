use super::*;
use crate::graph_duckdb::GraphInsertProfile;
use irmind_app::IngestProfile;
use irmind_mod_parser_json::{ParserProfile, ParserTiming, ProfiledJsonParser};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Corpus {
    Representative,
    LargeRecord,
}

impl Corpus {
    fn label(self) -> &'static str {
        match self {
            Self::Representative => "representative",
            Self::LargeRecord => "large_record",
        }
    }

    fn file_count(self) -> usize {
        match self {
            Self::Representative => 1_000,
            Self::LargeRecord => 25,
        }
    }
}

#[test]
#[ignore = "manual and weekly CI benchmark: 1 GB of 1-2 KB synthetic CloudTrail records"]
fn graph_benchmark_representative_1gb() {
    run_benchmark(Corpus::Representative, 1_000);
}

#[test]
#[ignore = "manual and weekly CI benchmark: 1 GB of unusually large JSON records"]
fn graph_benchmark_large_record_1gb() {
    run_benchmark(Corpus::LargeRecord, 25);
}

#[test]
#[ignore = "local diagnostic profile: 50 MB of representative CloudTrail records"]
fn graph_profile_representative_50mb() {
    run_benchmark(Corpus::Representative, 50);
}

fn run_benchmark(corpus: Corpus, file_count: usize) {
    let root = tempfile::tempdir().unwrap();
    let source_dir = root.path().join("sources");
    fs::create_dir(&source_dir).unwrap();
    let input_bytes = generate_corpus(&source_dir, corpus, file_count);
    if file_count == corpus.file_count() {
        assert!(input_bytes >= 1_000_000_000);
    }
    let graph_profile = Arc::new(GraphInsertProfile::default());
    let parser_profile = Arc::new(ParserProfile::default());
    let (store, guard, engine, id) =
        benchmark_engine(root.path(), graph_profile.clone(), parser_profile.clone());
    let mut ingest_profile = IngestProfile::default();
    let (ingest_time, read_time) = ingest_corpus(
        &engine,
        &id,
        &source_dir,
        corpus,
        file_count,
        &mut ingest_profile,
    );
    println!(
        "GRAPH_INGEST corpus={} bytes={input_bytes} files={file_count} seconds={:.3}",
        corpus.label(),
        ingest_time.as_secs_f64()
    );
    let query_started = Instant::now();
    let query = match corpus {
        Corpus::Representative => "000001",
        Corpus::LargeRecord => "SyntheticBenchmark",
    };
    let result = store.text_search(&id, query, 20).unwrap();
    let query_time = query_started.elapsed();
    assert!(result.contains("source="));
    let guard_started = Instant::now();
    let screened = irmind_app::ContentGuard::screen(guard.as_ref(), &result).unwrap();
    let guard_time = guard_started.elapsed();
    let output_tokens = screened.text.len().div_ceil(4);
    print_profile(
        corpus,
        file_count,
        input_bytes,
        output_tokens,
        ingest_time,
        read_time,
        query_time,
        guard_time,
        ingest_profile,
        parser_profile.snapshot(),
    );
    for (phase, duration) in graph_profile.snapshot() {
        println!(
            "GRAPH_INSERT corpus={} phase={phase} seconds={:.3}",
            corpus.label(),
            duration.as_secs_f64()
        );
    }
}

fn benchmark_engine(
    root: &Path,
    graph_profile: Arc<GraphInsertProfile>,
    parser_profile: Arc<ParserProfile>,
) -> (
    Arc<LocalStore>,
    Arc<MandatoryGuard>,
    Engine<'static>,
    CaseId,
) {
    let mut local_store = LocalStore::open(&root.join("case")).unwrap();
    local_store.graph.attach_profile(graph_profile);
    let store = Arc::new(local_store);
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[73u8; 32]),
        actor: Actor::Analyst,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            guard.clone(),
            Arc::new(ProfiledJsonParser::new(parser_profile)),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine
        .create_case("Synthetic graph benchmark", "local evidence only")
        .unwrap();
    (store, guard, engine, case.id)
}

fn generate_corpus(root: &Path, corpus: Corpus, file_count: usize) -> usize {
    let padding = matches!(corpus, Corpus::LargeRecord).then(|| "x".repeat(40 * 1024 * 1024));
    let mut total = 0;
    for index in 0..file_count {
        let bytes = match corpus {
            Corpus::Representative => format!(
                "{{\"fileMarker\":\"{index:04}\",\"Records\":[{}]}}",
                representative_records(index)
            ),
            Corpus::LargeRecord => format!(
                "{{\"Records\":[{{\"eventTime\":\"2026-10-27T12:00:00Z\",\"eventName\":\"SyntheticBenchmark\",\"sequence\":{index},\"message\":\"{}\"}}]}}",
                padding.as_deref().unwrap_or_default()
            ),
        };
        total += bytes.len();
        fs::write(root.join(format!("cloudtrail-{index:04}.json")), bytes).unwrap();
    }
    total
}

fn representative_records(file_index: usize) -> String {
    let mut records = String::new();
    let mut index = 0usize;
    while records.len() < 1_045_000 {
        if !records.is_empty() {
            records.push(',');
        }
        let sequence = file_index * 1_000 + index;
        let session = format!("synthetic-{sequence:06}");
        let record = serde_json::json!({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": format!("AROASYNTHETIC:{session}"),
                "arn": format!("arn:aws:sts::111122223333:assumed-role/SyntheticAnalyst/{session}"),
                "accountId": "111122223333",
                "accessKeyId": "SYNTHETIC-DO-NOT-USE",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AROASYNTHETIC",
                        "arn": "arn:aws:iam::111122223333:role/SyntheticAnalyst",
                        "accountId": "111122223333",
                        "userName": "SyntheticAnalyst"
                    },
                    "attributes": {
                        "creationDate": "2026-10-27T11:59:00Z",
                        "mfaAuthenticated": "true"
                    }
                }
            },
            "eventTime": "2026-10-27T12:00:00Z",
            "eventSource": "sts.amazonaws.com",
            "eventName": "SyntheticBenchmark",
            "awsRegion": "eu-west-1",
            "sourceIPAddress": "198.51.100.42",
            "userAgent": "aws-cli/2.15.22 Python/3.11.7 Linux/6.8.0 botocore/2.4.5",
            "requestParameters": {
                "roleArn": "arn:aws:iam::111122223333:role/SyntheticTarget",
                "roleSessionName": session,
                "durationSeconds": 3600,
                "tags": [
                    {"key": "incident", "value": "synthetic-benchmark"},
                    {"key": "team", "value": "security-lab"}
                ]
            },
            "responseElements": {
                "assumedRoleUser": {
                    "arn": format!("arn:aws:sts::111122223333:assumed-role/SyntheticTarget/{session}"),
                    "assumedRoleId": format!("AROATARGET:{session}")
                }
            },
            "requestID": session,
            "eventID": format!("00000000-0000-0000-0000-{sequence:012}"),
            "readOnly": false,
            "eventType": "AwsApiCall",
            "managementEvent": true,
            "recipientAccountId": "111122223333",
            "eventCategory": "Management",
            "tlsDetails": {
                "tlsVersion": "TLSv1.3",
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
                "clientProvidedHostHeader": "sts.amazonaws.com"
            }
        });
        records.push_str(&record.to_string());
        index += 1;
    }
    records
}

fn ingest_corpus(
    engine: &Engine<'_>,
    id: &CaseId,
    root: &Path,
    corpus: Corpus,
    file_count: usize,
    profile: &mut IngestProfile,
) -> (Duration, Duration) {
    let started = Instant::now();
    let mut read_time = Duration::ZERO;
    for index in 0..file_count {
        if index.is_multiple_of(100) {
            eprintln!("GRAPH_PROGRESS corpus={} files={index}", corpus.label());
        }
        let name = format!("cloudtrail-{index:04}.json");
        let read_started = Instant::now();
        let bytes = fs::read(root.join(&name)).unwrap();
        read_time += read_started.elapsed();
        engine
            .ingest_profiled(
                id,
                &bytes,
                &format!("synthetic/{name}"),
                &CancellationToken::new(),
                profile,
            )
            .unwrap();
    }
    (started.elapsed(), read_time)
}

#[allow(clippy::too_many_arguments)]
fn print_profile(
    corpus: Corpus,
    file_count: usize,
    bytes: usize,
    indexed_tokens: usize,
    ingest: Duration,
    read: Duration,
    query: Duration,
    guard: Duration,
    profile: IngestProfile,
    parser: ParserTiming,
) {
    let parsing = parser
        .total
        .saturating_sub(parser.extraction + parser.emit + parser.hash);
    let inserting = profile.graph.saturating_sub(parser.total) + parser.emit;
    let read_hash = read + profile.hash + parser.hash;
    let accounted = read_hash
        + profile.custody
        + profile.evidence_write
        + profile.audit
        + parsing
        + parser.extraction
        + inserting;
    let other = ingest.saturating_sub(accounted);
    let total = ingest + query + guard;
    println!(
        "GRAPH_BENCHMARK corpus={} bytes={bytes} files={} ingest_seconds={:.3} query_seconds={:.3} raw_tokens_est={} indexed_tokens_est={indexed_tokens}",
        corpus.label(),
        file_count,
        ingest.as_secs_f64(),
        query.as_secs_f64(),
        bytes.div_ceil(4)
    );
    for (phase, elapsed) in [
        ("read_hash", read_hash),
        ("custody", profile.custody),
        ("guard", guard),
        ("parse", parsing),
        ("entity_extraction", parser.extraction),
        ("duckdb_insert", inserting),
        ("evidence_write", profile.evidence_write),
        ("audit_write", profile.audit),
        ("query", query),
        ("other", other),
    ] {
        println!(
            "GRAPH_PHASE corpus={} phase={phase} seconds={:.3} percent={:.1}",
            corpus.label(),
            elapsed.as_secs_f64(),
            100.0 * elapsed.as_secs_f64() / total.as_secs_f64()
        );
    }
}
