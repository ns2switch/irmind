# Expanded skill episodes

These synthetic fixtures are for integration-test authors. Only explicitly listed
`source/` files are ingested. Private answers are opened by the evaluator after the
scripted investigation. Neither the model nor evidence receives these answers.

Windows scenarios use explicitly producer-normalized ECS exports with original
channel/event details. They test the ECS path; they do not claim to validate native
EVTX collection or a real compromise. Linux uses actual common/combined HTTP and
auditd framing. S3 uses CloudTrail JSON. GCP includes native Cloud Audit JSON without
invented semantic classification. Azure includes an explicitly normalized ECS
credential event. Native Zeek and Suricata exercise extraction-only network coverage.
The Azure/GCP normalized HuntEval source episodes add independent event/entity
checks; their generic event names are not native provider operation names.

See [third-party attribution](../../../../THIRD_PARTY_NOTICES.md). The model's
public scenario scripts do not read private files. Technique proposals are evaluated
and confirmed as evidence-linked hypotheses, not as proof of an actual attack.
