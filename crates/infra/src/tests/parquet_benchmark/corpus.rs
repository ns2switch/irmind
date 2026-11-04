use super::*;

pub(super) fn stage_worst_case_path(
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
        ingest_selected(ingest, id, source_root, std::slice::from_ref(&name));
        fs::remove_file(source_root.join(name)).unwrap();
    }
    bytes
}

pub(super) fn directory_bytes(root: &Path) -> u64 {
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
pub(super) fn representative_records(file_index: usize) -> String {
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

/// The benchmark makes an explicit parser choice, just like --parser, for both
/// wire versions. V2 must retain the same signed parser-selection requirement.
pub(super) fn ingest_selected(
    ingest: &LargeCaseUseCases<'_, '_>,
    id: &CaseId,
    root: &Path,
    names: &[String],
) {
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
        .unwrap();
}
