# Manual MVP validation

This guide is for the analyst closing the two manual release gates. Use only the synthetic files in `examples/`. Record the result below; a successful automated test does not replace either check.

## H5: real DeepSeek model

1. Build the default binary from a reviewed `main` commit and start `irmind` in a fresh test data directory. Complete the file-keystore guide and keep its analyst fingerprint outside that directory. In `/settings model`, choose DeepSeek, enter the approved model and API key in the masked field, and run **Test connection**. Confirm the remote-data warning; the probe contains no case evidence.
2. Create a case with `/new`, then ingest `examples/cloudtrail-alert.json` with `/ingest`. Keep its source file available for full verification.
3. Ask `Hello.` and check that the model replies naturally without an unnecessary tool call. Then ask it to explain the synthetic `ConsoleLogin` and `AssumeRole` events, cite the evidence hash, and identify uncertainty. Check that tool calls, if any, follow the policy and that the answer does not invent evidence.
4. Ask a follow-up referring to the first answer. Check that the conversation continues, streaming finishes cleanly, and a tool result is not requested repeatedly. Use `/verify` with the source root and record the outcome. A response cut by a token limit should remain visible and offer a continuation path.

Record the model ID, date, commit, observed tool behavior, any redaction or injection warning, verification result, and whether this meets H5. Do not paste the API key or full provider response into an issue or PR.

## Connector: Splunk Enterprise test container

This checks a real connector against a disposable service. It is a lab, not a production deployment. [Splunk's Docker setup](https://splunk.github.io/docker-splunk/SETUP.html) describes the image and license options; [Splunk's upload guide](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.4/how-to-get-data-into-your-splunk-deployment/upload-data) describes the Web upload flow.

1. Create a private, temporary Docker environment file with the image's license-acceptance startup setting and a strong `SPLUNK_PASSWORD`, as shown in Splunk's Docker setup. Start `splunk/splunk` using that environment file and bind Web port 8000 and management port 8089 to `127.0.0.1` only. Remove the temporary file after startup and the container after the test. On an ARM host, use the image's supported architecture or an amd64 test machine.
2. In Splunk Web, upload `examples/splunk-cloudtrail-events.ndjson` as one JSON event per line into a dedicated test index. Set the timestamp from `eventTime`. Confirm that a search for `alert_id=demo-alert-role` returns exactly one event at `2026-10-23T10:17:00Z` and that `recipientAccountId` and `eventName` are extracted. If field extraction differs, fix the lab sourcetype before testing IRMind.
3. Issue a dedicated search-only token scoped to that test index. Configure a management endpoint with a certificate whose hostname matches the URL and whose issuing CA is in the client's system trust store. The connector requires HTTPS and verifies TLS; the image's default self-signed certificate may require replacing with a trusted lab certificate. [Splunk's TLS guide](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.0/secure-splunk-platform-communications-with-transport-layer-security-certificates/configure-tls-certificates-for-inter-splunk-communication) covers port 8089 certificates. Do not disable certificate validation.
4. In `/settings connectors`, enable Splunk with the HTTPS management origin, source `lab-splunk`, the test index, account field `recipientAccountId`, and alert ID field `alert_id`. Add `IRMIND_SPLUNK_TOKEN` in `/settings keystore` and restart the session when prompted. Confirm that the connector reports active without showing the token.
5. Set the organization policy ceiling to permit only `lab-splunk`, account `000000000000`, and `2026-10-23T10:00:00Z` through `11:00:00Z`. Create a case scoped to that source and account but ending at `10:15:00Z`. Ask the model for a structured Splunk search of `ConsoleLogin` inside that case window; check the bounded result and evidence hash. If the model does not propose the query, record that separately rather than claiming the search passed.
6. In the same case, run `/siem-alert lab-splunk 000000000000 demo-alert-role 2026-10-23T10:00:00Z 2026-10-23T11:00:00Z`. This exceeds the case window but stays under the policy ceiling, so it must request signed analyst approval before the connector runs. Inspect the exact arguments, approve, and confirm one `AssumeRole` result. Run `/verify` against the case and confirm that the approval, result, and evidence hash verify. A request beyond the organization ceiling must be denied, even if an analyst tries to approve it.

The example contains documentation-only account `000000000000` and reserved IP `203.0.113.10`. Use a fresh lab case and remove its temporary data when the review is complete. See [Splunk configuration](../modules.md#splunk) for the connector's fixed index, field, window, and result limits.

## Result record

| Check | Record |
| --- | --- |
| Date, operator, OS, IRMind commit | |
| H5 provider and model; connection probe | |
| H5 greeting, investigation, follow-up, streaming | |
| H5 tool policy, citations, verification | |
| Splunk image digest/version, test index, TLS setup | |
| Structured search: expected / observed count and evidence hash | |
| Alert approval: exact scope, decision, expected / observed result | |
| Custody verification and any failure | |
| Verdict: H5 pass/fail; connector pass/fail; follow-up issue | |

Keep secrets, complete provider output, personal paths, and real incident data out of the record.
