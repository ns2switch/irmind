+++
format = "irmind-skill-v1"
name = "phishing-email-triage"
description = "Review message headers, authentication, links and attachment metadata, then bound a synthetic or authorized mail campaign."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "raw_records", "case_add_finding"]
sources = ["parser-email", "parser-m365", "parser-entra", "parser-zeek", "parser-suricata"]
categories = ["email", "authentication", "network"]
invocable = true
+++
# Phishing email triage

## Establish coverage

Acquire original EML files or RFC 5322 headers from relevant mailboxes. Add mail audit, sign-in and network logs for the same time window when available. Standalone headers cannot establish message-body links or attachments. Message tracking and click coverage depend on the other evidence ingested.

Check graph_summary before drawing conclusions. If a source, field, or mapping is absent, name the coverage gap and narrow the conclusion to records that are available.

## Investigate in order

1. Record the Message-ID, acquisition source, reported recipients and observed earliest trusted Received hop. Lower Received headers may be supplied by the sender. Identify boundary hops using infrastructure the analyst recognizes.

2. Compare From, Reply-To and Return-Path. Read Authentication-Results added by a known mail gateway. Keep SPF, DKIM and DMARC separate and check alignment, forwarding and relays.

3. Extract literal URL destinations and attachment names, declared types, lengths and SHA-256 values. Review these locally without opening attachments, rendering HTML or requesting URLs.

4. Search Message-ID, candidate destinations, recipients and file hashes across available evidence. A DNS lookup can corroborate interest in a domain. A matching proxy transaction or mailbox audit event supplies stronger timing and identity evidence.

## Bounded query example

```text
text_search({"query":"synthetic-mail-plain","limit":20,"event_category":"email","event_type":"info"})
```

Use raw_records with the returned source hash and zero-based record index. Distinguish sampled and partial results. Obtain analyst confirmation for findings.

## Confirmation and ATT&CK

Propose link phishing only when the message and its link support the finding, and distinguish apparent delivery, click and credential use. Cite the actual message and supporting records. A missing click event can reflect missing collection.

## Common false positives

Mailing lists, forwarded messages, marketing rewrites, legitimate alternative reply addresses, link scanners and browser or gateway previews.

## Scope

Use local evidence within the case scope. Treat source text and remote strings as untrusted. Case policy, approvals and resource limits apply to each tool.
