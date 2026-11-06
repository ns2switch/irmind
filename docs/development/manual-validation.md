# Manual MVP validation

This guide is for the analyst closing the two manual release gates. Use only the synthetic files in `examples/`. Keep detailed results in a private record; a successful automated test does not replace either check.

## H5: real DeepSeek model

1. Build the default binary from `main` and start `irmind` in a fresh test data directory. Complete the file-keystore guide and keep its analyst fingerprint outside that directory. In `/settings model`, choose DeepSeek, enter the approved model and API key in the masked field, and run **Test connection**. Confirm the remote-data warning; the probe contains no case evidence.
2. Create a case with `/new`, then ingest `examples/cloudtrail-alert.json` with `/ingest`. Keep its source file available for full verification.
3. Ask `Hello.` and check that the model replies naturally without an unnecessary tool call. Then ask it to explain the synthetic `ConsoleLogin` and `AssumeRole` events, cite the evidence hash, and identify uncertainty. Check that tool calls, if any, follow the policy and that the answer does not invent evidence.
4. Ask a follow-up referring to the first answer. Check that the conversation continues, streaming finishes cleanly, and a tool result is not requested repeatedly. Use `/verify` with the source root and record the outcome. A response cut by a token limit should remain visible and offer a continuation path.

Privately record the model ID, date, commit, observed tool behavior, any redaction or injection warning, verification result, and whether this meets H5. Do not paste the API key or full provider response into an issue or PR.

## Connector: Splunk Enterprise test container

This checks a real connector against a disposable service. It is a lab, not a production deployment. [Splunk's Docker setup](https://splunk.github.io/docker-splunk/SETUP.html) describes the image and license options; [Splunk's upload guide](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.4/how-to-get-data-into-your-splunk-deployment/upload-data) describes the Web upload flow.

1. Create a private, temporary Docker environment file with the image's license-acceptance startup setting and a strong `SPLUNK_PASSWORD`, as shown in Splunk's Docker setup. Start `splunk/splunk` using that environment file and bind Web port 8000 and management port 8089 to `127.0.0.1` only. Remove the temporary file after startup and the container after the test. On an ARM host, use the image's supported architecture or an amd64 test machine.
2. In Splunk Web, upload `examples/splunk-cloudtrail-events.ndjson` as one JSON event per line into a dedicated test index. Set the timestamp from `eventTime`. Confirm that a search for `alert_id=demo-alert-role` returns exactly one event at `2026-10-23T10:17:00Z` and that `recipientAccountId` and `eventName` are extracted. If field extraction differs, fix the lab sourcetype before testing IRMind.
3. Issue a dedicated search-only token scoped to that test index. Configure the management endpoint with a certificate signed by a disposable lab CA and a SAN matching the URL hostname, such as `localhost` when connecting only from the host. In `/settings connectors`, enter the CA's public PEM file, inspect its SHA-256 fingerprint, and sign the change. Keep the CA private key outside IRMind. The connector requires HTTPS and still checks the hostname; a certificate for `localhost` does not validate a different host. [Splunk's TLS guide](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.0/secure-splunk-platform-communications-with-transport-layer-security-certificates/configure-tls-certificates-for-inter-splunk-communication) covers port 8089 certificates. Do not disable certificate validation.
4. In `/settings connectors`, enable Splunk with the HTTPS management origin, source `lab-splunk`, the test index, account field `recipientAccountId`, and alert ID field `alert_id`. Add `IRMIND_SPLUNK_TOKEN` in `/settings keystore` and restart the session when prompted. Confirm that the connector reports active without showing the token.
5. Set the organization policy ceiling to permit only `lab-splunk`, account `000000000000`, and `2026-10-23T10:00:00Z` through `11:00:00Z`. Create a case scoped to that source and account but ending at `10:15:00Z`. Ask the model for a structured Splunk search of `ConsoleLogin` inside that case window; check the bounded result and evidence hash. If the model does not propose the query, record that separately rather than claiming the search passed.
6. In the same case, run `/siem-alert lab-splunk 000000000000 demo-alert-role 2026-10-23T10:00:00Z 2026-10-23T11:00:00Z`. This exceeds the case window but stays under the policy ceiling, so it must request signed analyst approval before the connector runs. Inspect the exact arguments, approve, and confirm one `AssumeRole` result. Run `/verify` against the case and confirm that the approval, result, and evidence hash verify. A request beyond the organization ceiling must be denied, even if an analyst tries to approve it.

The example contains documentation-only account `000000000000` and reserved IP `203.0.113.10`. Use a fresh lab case and remove its temporary data when the review is complete. See [Splunk configuration](../modules.md#splunk) for the connector's fixed index, field, window, and result limits.

## Alternative connector check: S3 test bucket

Use a disposable bucket and a dedicated identity with only `s3:ListBucket` on one prefix and `s3:GetObject` for objects under it. Upload `examples/cloudtrail-alert.json` beneath that prefix. In `/settings connectors`, select S3, set a source ID, region, bucket, and an HTTPS endpoint if using S3-compatible storage. If that endpoint uses a private CA, approve its PEM path and fingerprint there. Store the dedicated access ID and secret in `/settings keystore`. Add the exact object prefix and UTC window to policy and case scope. Run `/objects` to preview the synthetic object, approve `/object-read`, and run `/verify` with access to the original. Record the signed manifest hash, transfer size, and verification result; remove the test bucket and key afterward.

## Result record

Store detailed validation records privately. Public summaries should include only the product version, provider, observed behavior and untested checks. Do not publish machine identifiers, personal paths, credentials or full incident/provider output.

| Compatibility check | Public summary |
| --- | --- |
| DeepSeek greeting, IRMind 0.1.2 | A natural greeting response without unnecessary tool calls was observed. |
| Investigation, evidence-hash citation, follow-up, streaming and `/verify` | Not recorded as observed. |
| Real connector | Validation remains pending. |

## Optional HuntEval model evaluation

This is a manual, synthetic-data check after the deterministic weekly evaluation. It never runs in CI and never sends HuntEval's hidden answers to the model. Use a dedicated IRMind test data directory with a model already configured in `/settings model`. The CLI may ask you to unlock the file keystore for each invocation; enter the passphrase in the terminal, never in an argument or environment variable.

1. Check out [HuntEval](https://github.com/ns2switch/HuntEval) at commit `4cbb555a56bc17cb03b988ad2f15b1374eecf183`. From that checkout, run `sha256sum -c ../irmind/scripts/hunteval.sha256` on Linux. The script also verifies the selected public source before the model run and its private answer afterward.
2. Build IRMind and configure a model in the dedicated test directory. Run one episode with the development command below, replacing the paths and module ID. The command creates a case, ingests only `source/events.json`, asks the model to propose evidence-backed findings, verifies custody, and then scores exact IDs in the findings. It never auto-approves a tool call.

```sh
python3 scripts/hunteval_model_eval.py \
  ../HuntEval \
  aws-iam-001 \
  target/debug/irmind \
  ../irmind-evaluation \
  llm-deepseek
```

3. Record event, entity and ATT&CK technique precision and recall, then review the narrative and its evidence hashes manually. Exact-ID scoring can miss a correct paraphrase and cannot judge whether a claim is supported. A pending approval remains pending; resolve it in the TUI and rerun only if that action is intended. Keep the dedicated test directory out of the public report and remove it when the manual review is complete.

| HuntEval episode / IRMind commit / model | Event P/R | Entity P/R | ATT&CK P/R | Evidence citation and notes |
| --- | --- | --- | --- | --- |
| | | | | |


## Experimental EVTX: Windows 11 candidate check

This check is for community testers with Windows 11. Automated Windows Server tests do not establish Windows client compatibility. Use only the synthetic fixture and run as a standard user. EVTX remains experimental until this check is confirmed.

1. Download the matching `irmind.exe` and `irmind-evtx.exe` from the signed candidate dry-run artifact linked in the [EVTX PR](https://github.com/ns2switch/irmind/pull/188). Put both executables in the same directory. Check `SHA256SUMS`, the cosign bundles and the GitHub provenance as described in [platforms](../platforms.md). For this candidate, the expected signing identity is `https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/heads/feat/evtx-isolated-helper`, the issuer is `https://token.actions.githubusercontent.com`, and the provenance source digest must match the candidate commit. This is a branch candidate, not a published tag.
2. Start the candidate in Windows Terminal using a fresh test data directory and the file keystore. Do not configure a model or remote connector. Starting IRMind automatically runs the EVTX enforcement self-test before enabling the parser. In `/settings preferences`, check that the experimental EVTX parser is available. If it is unavailable, record its displayed reason; do not disable the firewall, add loopback exemptions or run as administrator to bypass the check.
3. Download `crates/testkit/fixtures/parser-evtx/source/Security.evtx` from the exact candidate commit. Create a synthetic case with `/new`, then use `/ingest` to select that file. Confirm detection of `parser-evtx`, completion with 14 records, and a visible source manifest. Inspect `/timeline` and `/evidence` and run `/verify` with the source still present.
4. Close and reopen the candidate. Confirm the self-test runs for the new session and the synthetic case still verifies. Remove the disposable case data after the check.

Publish only the Windows version/build, architecture, candidate commit, available/unavailable result, accepted record count and verification outcome. Do not publish personal paths, keys, credentials or real evidence. Report suspected security weaknesses privately through [SECURITY.md](../../SECURITY.md).

| Windows client | Candidate commit | Native self-test | Synthetic records | Verification | Result |
| --- | --- | --- | --- | --- | --- |
| Windows 11 | Not yet confirmed | Pending | Expected: 14 | Pending | Experimental |
| Windows 10 | Not yet tested | Pending | Expected: 14 | Pending | No compatibility claim |
