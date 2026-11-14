# Synthetic Windows collection

Owned synthetic exports for the bundled `windows-triage` integration episode:
Hayabusa, PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd, LECmd, RECmd batch,
SrumECmd and EvtxECmd. Nine files contain ten observations from one fictional
host. They are exported tables, not a binary KAPE archive, real collection or
telemetry from an incident. IRMind launches no collector or export tool.

The episode uses actual detection, identified decoders/mappings, signed source
sets, local queries, explicit verified-original excerpts, analyst-confirmed
findings, reconstruction, sealing and independently verified export with the
originals. Cache presence is distinguished from execution and missing semantic
classification is retained. These checks evaluate pipeline behavior, not the
quality of an autonomous model or the accuracy of third-party tools.

`source/` alone is ingested. `private/ground-truth.json` is opened only by the
evaluator after the scripted response; its marker must be absent from every
model request and case entry. No real credentials, users or hosts are present.
All fixture text is original and covered by the repository licenses.
