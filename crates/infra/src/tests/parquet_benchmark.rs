use super::*;
use crate::parquet_store::ParquetProfile;
use irmind_app::LargeCaseUseCases;
use std::time::Instant;

#[test]
#[ignore = "manual and weekly benchmark: synthetic 1 GB CloudTrail corpus"]
fn parquet_benchmark_1gb() {
    benchmark(1_000, 1);
}

#[test]
#[ignore = "manual and weekly benchmark: synthetic 15 GB CloudTrail corpus"]
fn parquet_benchmark_15gb() {
    benchmark(1_000, 15);
}

#[test]
#[ignore = "local diagnostic: 50 MB synthetic CloudTrail corpus"]
fn parquet_benchmark_50mb() {
    benchmark(50, 1);
}

#[allow(clippy::too_many_lines)]
fn benchmark(files: usize, multiplier: usize) {
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
        .create_case("Synthetic Parquet benchmark", "account 111122223333")
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
    let bundles = ingest
        .compact_case(&case.id, &CancellationToken::new())
        .unwrap();
    println!("PARQUET_COMPACTION bundles={bundles}");
    let ingest_time = started.elapsed();
    let [hash_time, conversion_time, row_time, parquet_time, _, _] = profile.snapshot();
    let disk_bytes = directory_bytes(&root.path().join("case/parquet"));
    println!(
        "PARQUET_INGEST bytes={total_bytes} files={files} hash_seconds={:.3} conversion_seconds={:.3} row_seconds={:.3} parquet_seconds={:.3} wall_seconds={:.3} parquet_bytes={disk_bytes}",
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
                    .entity_lookup(&case.id, "ip", "198.51.100.42")
                    .map(|_| ()),
                2 => store
                    .neighbors(&case.id, "ip", "198.51.100.42", 10)
                    .map(|_| ()),
                3 => store.timeline(&case.id, 10).map(|_| ()),
                _ => store
                    .graph_path(
                        &case.id,
                        ("ip", "198.51.100.42"),
                        ("account", "111122223333"),
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
