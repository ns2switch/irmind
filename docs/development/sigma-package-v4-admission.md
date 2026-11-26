# Sigma V4 case admission for installed packages

**Status** Approved by the analyst, including the independent vectors.

The approved package contract gives V3 runs that require case admission
the distinct identity `irmind-sigma-evaluator-v3-case-admission-v1`. The
approved decimal projection gives its field table `irmind-sigma-evaluator-v4`
semantics. To combine them, use the explicit identity
`irmind-sigma-evaluator-v4-case-admission-v1` for a package run with the
decimal table. The marker is committed in both the case admission and the
following run. Direct imports and historical runs keep their approved
interpretation.

A verifier of the new identity first authenticates the complete case and
locates the immediately preceding Analyst case admission. That record
commits to the preceding checkpoint, optional exact installation operation,
global pack admission, manifest, inventory, scope, time, table, compiled
rules and reserved work. The following run must bind the admission entry as
its checkpoint and match those commitments. Then the verifier applies the
V4 field-table and projection checks and the existing V3 result layout. A
missing admission, a V3 table under the new marker, an ungated marker in
either of the two records or a changed checkpoint fails verification.

There are no new statuses, frame fields, archive kinds or limits in this
proposal. The [generator](sigma-package-vectors/generate-v4-gate.py) and
[vectors](sigma-package-vectors/v4-gate.json) specify the new string in the
pair of receipt bodies, the exact signature challenge of the synthetic
admission and the rejected downgrade. They use synthetic material.
