# Bundled forensic methods

These data-only packages are for contributors reviewing the included catalog.
Each contains a bounded SKILL.md and reference data. See the [analyst catalog](../docs/skills.md)
for purpose, required sources and honest coverage limits, and the [skills design](../docs/development/skills-design.md)
for the existing admission and case-use contracts.

All 13 methods declare local reads and finding-proposal tools only. They do not
run collectors or scripts, enable providers, grant permissions or confirm
findings. Missing mappings remain coverage gaps. Methodology is untrusted after
compilation and signing; its hash is not an evidence citation.

[Package commitments](package-identities.json) pin the inventories;
[SHA256SUMS](SHA256SUMS) covers individual resources. Run
`python3 scripts/skills_inventory.py` from the repository root to check both,
or add `--write` after deliberately editing a package. The shared Rust compiler
contract independently checks canonical package hashes, bounded metadata and guard
screening. Existing published package hashes remain unchanged when adding methods.

The scripted integration suite runs each included method through ingestion,
progressive loading, local queries, analyst-confirmed findings, verification,
sealing and independent V7 export verification. Separate hostile-evidence tests
use an obedient fake model to attempt undeclared tools and out-of-scope reads.
These checks validate integration and controls, not the accuracy of a real model.
Expected answers live in evaluator-only fixtures, outside evidence and model context.
The methods contain original project-licensed prose and link to public primary sources.
