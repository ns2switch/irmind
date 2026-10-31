use super::hunteval_eval;
use super::*;
use crate::parquet_store::ParquetProfile;
use irmind_app::LargeCaseUseCases;
use std::time::Instant;

#[test]
#[ignore = "manual and weekly benchmark: synthetic 1 GB CloudTrail corpus"]
fn parquet_benchmark_1gb() {
    benchmark(1_000, 1, "1gb");
}

#[test]
#[ignore = "manual and weekly benchmark: synthetic 15 GB CloudTrail corpus"]
fn parquet_benchmark_15gb() {
    benchmark(1_000, 15, "15gb");
}

#[test]
#[ignore = "local diagnostic: 50 MB synthetic CloudTrail corpus"]
fn parquet_benchmark_50mb() {
    benchmark(50, 1, "50mb");
}

#[allow(clippy::too_many_lines)]
fn benchmark(files: usize, multiplier: usize, label: &str) {
    let root = tempfile::tempdir().unwrap();
    let source_root = root.path().join("sources");
    fs::create_dir(&source_root).unwrap();
    let mut store = LocalStore::open(&root.path().join("case")).unwrap();
    let profile = Arc::new(ParquetProfile::default());
    store.parquet.attach_profile(profile.clone());
    let store = Arc::new(store);
    let signer = Arc::new(LocalSigner {
        key: SigningKey::from_bytes(&[74u8; 32]),
        actor: Actor::Analyst,
    });
    let parser = Arc::new(JsonParser);
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
            Arc::new(MandatoryGuard::new().unwrap()),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine
        .create_case("Synthetic Parquet benchmark", "local synthetic sources")
        .unwrap();
    let ingest = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    };
    let mut total_bytes = 0u64;
    let started = Instant::now();
    for start in (0..files).step_by(4) {
        let names = (start..(start + 4).min(files))
            .map(|index| {
                let records = representative_records(index);
                let body = std::iter::repeat_n(records.as_str(), multiplier)
                    .collect::<Vec<_>>()
                    .join(",");
                let data = format!("{{\"Records\":[{body}]}}");
                total_bytes += data.len() as u64;
                let name = format!("cloudtrail-{index:04}.json");
                fs::write(source_root.join(&name), data).unwrap();
                name
            })
            .collect::<Vec<_>>();
        ingest
            .ingest_local_batch(
                &case.id,
                &source_root,
                &names,
                false,
                &CancellationToken::new(),
            )
            .unwrap();
        for name in names {
            fs::remove_file(source_root.join(name)).unwrap();
        }
        if start.is_multiple_of(100) {
            eprintln!("PARQUET_PROGRESS files={} of {files}", start + 4);
        }
    }
    if label == "15gb" {
        total_bytes += stage_worst_case_path(&source_root, &case.id, &ingest);
    }
    let episodes = hunteval_eval::root_from_environment().map(|root| {
        let episodes = hunteval_eval::load_episodes(&root);
        let names = hunteval_eval::stage_sources(&source_root, &episodes);
        total_bytes += names
            .iter()
            .map(|name| fs::metadata(source_root.join(name)).unwrap().len())
            .sum::<u64>();
        for batch in names.chunks(4) {
            ingest
                .ingest_local_batch(
                    &case.id,
                    &source_root,
                    batch,
                    false,
                    &CancellationToken::new(),
                )
                .unwrap();
        }
        episodes
    });
    let bundles = ingest
        .compact_case(&case.id, &CancellationToken::new())
        .unwrap();
    println!("PARQUET_COMPACTION bundles={bundles}");
    let ingest_time = started.elapsed();
    let [hash_time, conversion_time, row_time, parquet_time, _, _] = profile.snapshot();
    let disk_bytes = directory_bytes(&root.path().join("case/parquet"));
    let coobservation_bytes = store
        .entries(&case.id)
        .unwrap()
        .iter()
        .filter(|entry| entry.kind == irmind_domain::AuditEventKind::ParquetArtifactV1)
        .map(|entry| irmind_domain::ParquetArtifactV1::decode(&entry.payload).unwrap())
        .filter(|artifact| artifact.schema_version == "irmind-coobservations-v1")
        .map(|artifact| artifact.size)
        .sum::<u64>();
    println!(
        "PARQUET_INGEST bytes={total_bytes} files={files} hash_seconds={:.3} conversion_seconds={:.3} row_seconds={:.3} parquet_seconds={:.3} wall_seconds={:.3} parquet_bytes={disk_bytes} coobservation_bytes={coobservation_bytes}",
        hash_time.as_secs_f64(),
        conversion_time.as_secs_f64(),
        row_time.as_secs_f64(),
        parquet_time.as_secs_f64(),
        ingest_time.as_secs_f64()
    );
    assert!(
        ingest_time < std::time::Duration::from_mins(15),
        "Parquet ingestion exceeded the 15-minute benchmark target"
    );
    let cold_started = Instant::now();
    let cold = store.graph_summary(&case.id);
    println!(
        "PARQUET_COLD_QUERY seconds={:.3} error={}",
        cold_started.elapsed().as_secs_f64(),
        cold.is_err()
    );
    cold.unwrap();
    let labels = ["term", "entity", "neighbors", "timeline", "path"];
    for (index, label) in labels.iter().enumerate() {
        let mut timings = Vec::new();
        let mut errors = 0usize;
        for _ in 0..5 {
            let started = Instant::now();
            let result = match index {
                0 => store
                    .text_search(&case.id, "synthetic-000001", 10)
                    .map(|_| ()),
                1 => store
                    .entity_lookup(&case.id, "ip", "198.18.254.42")
                    .map(|_| ()),
                2 => store
                    .neighbors(&case.id, "ip", "198.18.254.42", 10)
                    .map(|_| ()),
                3 => store.timeline(&case.id, 10).map(|_| ()),
                _ => store
                    .graph_path(
                        &case.id,
                        ("ip", "198.18.254.42"),
                        ("account", "999900001111"),
                    )
                    .map(|_| ()),
            };
            timings.push(started.elapsed());
            if result.is_err() {
                errors += 1;
            }
        }
        timings.sort();
        println!(
            "PARQUET_QUERY name={label} p50_seconds={:.3} p95_seconds={:.3} errors={errors}",
            timings[2].as_secs_f64(),
            timings[4].as_secs_f64()
        );
        assert_eq!(errors, 0, "{label} query failed");
        assert!(
            timings[4] < std::time::Duration::from_secs(10),
            "{label} query exceeded the 10-second benchmark target"
        );
    }
    let [_, _, _, _, verify_time, scan_time] = profile.snapshot();
    println!(
        "PARQUET_QUERY_PHASE verify_seconds={:.3} scan_seconds={:.3}",
        verify_time.as_secs_f64(),
        scan_time.as_secs_f64()
    );
    if let Some(episodes) = episodes {
        let mut metrics = std::collections::BTreeMap::new();
        hunteval_eval::evaluate_case(store.as_ref(), &case.id, &episodes, &mut metrics);
        hunteval_eval::report_metrics(label, &metrics);
    }
    if label == "15gb" {
        let started = Instant::now();
        let path = store
            .graph_path(&case.id, ("account", "887700000000"), ("ip", "192.0.2.250"))
            .unwrap();
        println!(
            "PARQUET_WORST_PATH seconds={:.3} truncated={} time_budget={}",
            started.elapsed().as_secs_f64(),
            path.contains("truncated"),
            path.contains("10-second time budget")
        );
        assert!(path.contains("truncated"));
    }
}

fn stage_worst_case_path(
    source_root: &Path,
    id: &CaseId,
    ingest: &LargeCaseUseCases<'_, '_>,
) -> u64 {
    let mut records = Vec::new();
    for ip in 1..=50 {
        records.push(format!("{{\"eventTime\":\"2026-10-28T12:00:00Z\",\"eventName\":\"Branch\",\"recipientAccountId\":\"887700000000\",\"sourceIPAddress\":\"203.0.113.{ip}\"}}"));
        for peer in 0..5 {
            records.push(format!("{{\"eventTime\":\"2026-10-28T12:00:00Z\",\"eventName\":\"Branch\",\"recipientAccountId\":\"8877{ip:04}{peer:04}\",\"sourceIPAddress\":\"203.0.113.{ip}\"}}"));
        }
    }
    let mut bytes = 0;
    for (part, batch) in records.chunks(50).enumerate() {
        let name = format!("worst-path-{part:02}.json");
        let data = format!("{{\"Records\":[{}]}}", batch.join(","));
        bytes += data.len() as u64;
        fs::write(source_root.join(&name), data).unwrap();
        ingest
            .ingest_local(id, source_root, &name, false, &CancellationToken::new())
            .unwrap();
        fs::remove_file(source_root.join(name)).unwrap();
    }
    bytes
}

fn directory_bytes(root: &Path) -> u64 {
    let mut total = 0;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                total += metadata.len();
            }
        }
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
                "arn": format!("arn:aws:sts::999900001111:assumed-role/SyntheticAnalyst/{session}"),
                "accountId": "999900001111",
                "accessKeyId": "SYNTHETIC-DO-NOT-USE",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AROASYNTHETIC",
                        "arn": "arn:aws:iam::999900001111:role/SyntheticAnalyst",
                        "accountId": "999900001111",
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
            "sourceIPAddress": "198.18.254.42",
            "userAgent": "aws-cli/2.15.22 Python/3.11.7 Linux/6.8.0 botocore/2.4.5",
            "requestParameters": {
                "roleArn": "arn:aws:iam::999900001111:role/SyntheticTarget",
                "roleSessionName": session,
                "durationSeconds": 3600,
                "tags": [
                    {"key": "incident", "value": "synthetic-benchmark"},
                    {"key": "team", "value": "security-lab"}
                ]
            },
            "responseElements": {
                "assumedRoleUser": {
                    "arn": format!("arn:aws:sts::999900001111:assumed-role/SyntheticTarget/{session}"),
                    "assumedRoleId": format!("AROATARGET:{session}")
                }
            },
            "requestID": session,
            "eventID": format!("00000000-0000-0000-0000-{sequence:012}"),
            "readOnly": false,
            "eventType": "AwsApiCall",
            "managementEvent": true,
            "recipientAccountId": "999900001111",
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
