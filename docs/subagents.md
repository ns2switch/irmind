# Parallel investigations

[Español](es/subagents.md)

Subagents split a larger investigation into bounded tasks. They use the model
already selected by the analyst. No provider is enabled automatically. A greeting
or a simple question does not require delegation.

## Review a plan

Ask the agent to investigate the case or to divide a specific investigation
across the relevant sources. Before work starts, IRMind shows the tasks, their
included types, signed source names with short hashes and reserved tokens and
tool calls. Large source sets show their count and the first sixteen labels.

A plan reserving **more than 25%** of either the remaining case tokens or tool
calls requires **Start** with an Analyst signature. Select Start or Cancel with
the arrows and Enter, or type its number and Enter. Esc cancels the plan. A plan
at or below the threshold starts after its preview is displayed. In
`/settings preferences`, turn on **Confirm all subagent plans** to require Start
for every plan. This preference is signed and only the analyst can change it.

The six included types are triage, cloud, endpoint, network, Kubernetes and
threat intelligence. Each has a fixed tool and skill catalog. Community-defined
types and monetary budget limits are outside this version.

## Follow and cancel tasks

Use `/subagents` to see task state, activity, consumption and coverage. Arrows
select a task; Enter shows its details; Esc returns to the conversation. Use
`/subagents cancel <task>` with a unique identifier from the panel, at least
eight characters, to cancel one task. `/pause` cancels the investigation and its
children. Cancellation preserves completed results and incurred consumption.

The normal interactive engine runs up to two child model requests concurrently.
A child waiting for Analyst approval leaves siblings free to continue. Resolve
its card or use `/approve`, `/deny` or `/edit`; the decision goes back to that
live task. A request from an ended task can be denied, but cannot execute in the
parent. Children cannot approve requests, change settings, increase budgets or
create more subagents. Only the analyst confirms findings.

## Sources, budgets and partial results

Tasks receive a frozen subset of signed sources and, when explicitly assigned,
a narrower remote scope. A child cannot read a sibling's sources or fall back to
an unrestricted query. A newly acquired source becomes available to its owning
task only after its decoder, mapping, artifacts and attributed receipt are signed.
Object downloads require the task's own prior listing, a pinned version or ETag,
a byte reservation and any transfer approval required by policy. They use the
case's private, automatically removed spool. Instance-scoped SIEM queries are
not available to children in this version.

Type, parent skill, child skill, case scope and organization policy all restrict
the effective tools. External intelligence requires an observed indicator from
an assigned verified original and the existing signed disclosure approval.
Skill text and results remain guarded UNTRUSTED data, including when signed.

Use `/budget` for the shared case allocation. Child tokens, tool calls and cloud
bytes consume that allocation and their task limits; rounds also consume the
parent turn allowance. Unknown provider usage remains reserved. Cost is an
estimate when usage and prices are available, otherwise unavailable.

Sampling, expansion, deadlines, result limits and incomplete source coverage
produce explicit partial results. Remote adapters that do not attest response
completeness also remain partial. Tool failure never triggers a broader read.
The main agent receives the guarded summary and coverage gaps, not authority to
clear a partial marker.

## Verification and export

Each child signs a separate branch with the Agent key. The case commits bounded
checkpoints and merges results in deterministic task order. `/verify`, `/seal`
and `/export` authenticate the branch material, approvals, reservations and
terminal results. Export V8 includes the committed branches and catalog proofs
needed for offline verification. Interrupted plans retain their signed work;
reopening closes interrupted work without retrying remote effects.

Version 0.5 uses case marker 4 and export V8. Keep the creating executable for
older cases or re-ingest verified originals into a new case; opening a case does
not migrate it. See [configuration](configuration.md), the
[format contract](development/subagents-format-contract.md) and
[case version policy](development/case-migration.md).
