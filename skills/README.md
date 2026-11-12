# Initial forensic methods

These data-only packages are for contributors reviewing IRMind's initial skills.
Each contains a bounded SKILL.md and reference data. The packages compile into
methodology candidates; runtime activation and case-use receipts are separate.
See the [skills design](../docs/development/skills-design.md).

| Method | Coverage | Evidence needed |
| --- | --- | --- |
| [Windows triage](windows-triage/SKILL.md) | Sign-ins, execution, persistence and lateral activity | EVTX, or collected Hayabusa, EZTools, Velociraptor and plaso exports. |
| [Linux triage](linux-triage/SKILL.md) | Authentication, privilege changes, execution and persistence | auth.log/secure, auditd, journald and available network/web logs. |
| [AWS credential compromise](aws-credential-compromise/SKILL.md) | Credentials, privilege changes and follow-on cloud activity | CloudTrail within the authorized accounts, regions and interval. |

The initial methods declare local read and finding-proposal tools only. They do
not run collectors or scripts, enable providers, grant permissions or confirm
findings. Missing mappings remain coverage gaps. All methodology text remains
untrusted after compilation and signing; its hash is not an evidence citation.

The [package commitments](package-identities.json) pin the initial inventories;
[SHA256SUMS](SHA256SUMS) also covers individual resources. The shared compiler
contract checks exact bytes and metadata. A guard test screens
every resource and the packages carry MIT OR Apache-2.0 metadata. Synthetic episode
execution will exercise the methods through the bounded agent-loading path when
its case receipt and export contract is integrated. These files contain no
benchmark ground truth or episode answers.
