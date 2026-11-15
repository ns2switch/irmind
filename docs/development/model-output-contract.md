# Complete model output and request-boundary budgets

Proposed contract amendment. This document changes no running code or signed
bytes. It separates the analyst's generation policy from the capability and
accounting contracts needed to implement it safely.

## Generation policy

For root turns, child turns, summaries and conversation compaction, IRMind must
not impose a smaller output-token ceiling than the selected model supports.
When its maximum is known, send that maximum in the provider's supported field.
When it is unknown and the field is optional, omit the field. If it is required,
show an actionable `/settings model` error before dispatch. A context window is
not an output ceiling. Never assume one model family's limit applies to an
unknown model or a custom endpoint.

The case budget is an admission check between requests. A request admitted with
positive available tokens may complete even if its reported usage exhausts or
exceeds that balance. Persist the entire guarded answer and reported usage;
compute debt from positive cumulative usage and the signed allocation without
unsigned underflow. Block the next request and explain `/budget`. Existing
organization authority still governs allocation changes. This does not let a
model raise an allocation or approve anything.

## Current implementation points

| Path | Existing behavior | Required result |
| --- | --- | --- |
| [Root investigation](../../crates/app/src/engine/investigation.rs) | 2,048 output tokens; a further 512-token summary reserve is subtracted. | Native model maximum / omitted optional parameter, with a pre-request budget check. |
| [Summary](../../crates/app/src/engine/investigation/limits.rs) and [compaction](../../crates/app/src/engine/investigation/compaction.rs) | 512-token ceiling. | Same generation policy as a normal request. |
| [Child request](../../crates/app/src/subagents/broker/runner/model.rs) | Output is capped at the smaller of 2,048 and the remaining child slice after estimated input. | Reserve input upper bound plus the model's actual output maximum; do not dispatch if this does not fit the child slice. |
| [Chat adapter](../../crates/llm-chat-completions/src/lib.rs) and [Anthropic](../../crates/modules/llm-anthropic/src/lib.rs) | Wire maximum is clamped to remaining case tokens. | No case-budget clamp on provider output. |
| [Child outcome](../../crates/app/src/subagents/broker/runner/outcome.rs) | A report above its reservation discards the reply; visible child text is reduced to 16 KiB. | Preserve the complete guarded answer and account for the provider's report, with a separately bounded summary. |
| [Settlement ledger](../../crates/app/src/subagents/journal/ledger.rs) and [branch verifier](../../crates/app/src/subagents/journal/material/task.rs) | Actual usage must fit both the request reservation and the child allocation. | The exceptional overrun policy below requires an explicit contract amendment. |

## 1. Typed model output capabilities

Propose an additive `LlmPort::output_profile()` method with a default unknown
profile, and a validated application type:

```rust
pub struct ModelOutputProfile {
    pub maximum_output_tokens: Option<NonZeroU32>,
    pub parameter_requirement: OutputParameterRequirement,
}
pub enum OutputParameterRequirement { Optional, Required }
```

The module owns the wire parameter name and provider dialect. The profile is
resolved from an exact, documented model identity or an analyst-confirmed
`/settings model` value. It is frozen for the request. Discovery is an explicit
settings action; no new network call is added before every inference. Metadata
from discovery is untrusted, validated and displayed through the guard before
signed admission. No credentials or new production dependency are needed.

`CompletionRequest` stops carrying `remaining_case_tokens` to adapters. Replace
its numeric per-call cap with an explicit provider-maximum/omission decision;
ordinary callers cannot request a lower application ceiling. This is a change
to the existing application/adapter contract and must not be hidden behind a
magic value such as zero or an arbitrarily large integer.

An unknown optional maximum permits a root request without that parameter. It
cannot support a bounded child reservation: that child waits for a known or
analyst-declared maximum. The TUI names the missing setting; it does not invent
a 2,048-token reservation or silently enlarge the child's allocation. A declared
maximum is labelled as such, not represented as verified provider metadata.
A discovered/signed change invalidates an incompatible pending plan preview.

### Provider profile sources

| Adapter | Rule and primary reference |
| --- | --- |
| OpenAI | `max_completion_tokens` is optional and includes reasoning output; use the exact model's documented maximum when known. [API reference](https://developers.openai.com/api/reference/go/resources/chat/subresources/completions/methods/create). |
| DeepSeek | `max_tokens` is optional; provider defaults can be below the supported maximum. Resolve the actual model using documented limits or confirmed settings. [Chat API](https://api-docs.deepseek.com/api/create-chat-completion/) and [model metadata](https://api-docs.deepseek.com/api/list-models/). |
| OpenRouter | Resolve per-model/provider capabilities; absence of a parameter passes through to the provider. Never treat a context length as an output maximum. [Parameters](https://openrouter.ai/docs/api_reference/parameters) and [models](https://openrouter.ai/docs/api/api-reference/models/list-all-models-and-their-properties). |
| Anthropic | Ordinary generation requires `max_tokens`; an unknown model maximum must be configured before sending. [Messages API](https://platform.claude.com/docs/en/api/messages/create) and [model specifications](https://platform.claude.com/docs/en/models/overview). |
| Compatible / local | An optional signed setting records the analyst-declared model maximum and supported dialect. Unknown optional values are omitted for root calls; unknown mandatory values block dispatch with a settings action. |

Do not add stale numeric defaults for whole families, use a provider's default
as its advertised maximum, enable server-side tools, or change the existing
reasoning non-replay rule. Report reasoning usage when provided; it is not
visible answer text and is never appended to a continuation prompt.

## 2. Child reservations and exceptional token settlement

Normal admission retains the approved broker rules: input upper bound plus model
maximum must fit the existing child allocation, all current holds and case
admission checks. The aggregate plan still uses the signed 25% rule, the same
six types and the same tool/source intersection. No child request starts with an
unknown output bound or an insufficient slice. In-flight requests are not
cancelled merely because another request finishes and consumes the balance.

There is one explicit contract decision: the current verifier rejects a provider
report above a request reservation or child token allocation. A larger provider
maximum removes the ordinary 2,048-token cause, but it does not prove a custom
provider's report or a hidden prompt overhead can never exceed the bound.

Proposed amendment: an already admitted model request may settle **reported
tokens** above its reservation. Its signed usage event, committed reply prefix
and unique settlement must agree exactly. Persist the excess and enter a debt
state; do not turn it into unused capacity, silently clamp it, discard the answer
or restart a call. An outstanding plan cannot authorize another request against
an exhausted case or child. Unknown usage retains the conservative hold as today;
invalid or unrepresentable reports are explicitly unresolved and cannot become
zero usage or permission to dispatch again.

This exception applies only to model-token accounting of already authorized
requests. Calls, rounds, cloud bytes, tool approvals, sources, deadlines and
policy permissions retain their existing rules. Cancellation remains effective.
Counter arithmetic remains checked. The verifier must reject a repeated
settlement, a fabricated overrun without its committed provider report, a
mismatched request/actor/checkpoint, a refund of spent tokens, and any new request
admitted while that case/child has no admissible balance.

The existing signed record byte layouts need not change for this numeric
settlement rule. Its interpretation and verifier invariants do change, so this
amendment is separate from merely replacing an output-token constant. New and
changed accounting vectors must be reviewed; no historical golden is edited to
make an unrelated change pass.

## 3. Complete answers within existing security limits

Keep the 1 MiB signed-frame ceiling, the 1,000,000-byte guard input limit and
the 2,000,000-byte stream limit. Raise the 200,000-byte preview limit so that it
does not truncate an answer that fits these existing limits. No segmented answer
storage, new spool or new export representation is introduced.

Retain and sign the entire guarded answer that fits its enclosing frame, allowing
for record metadata and encoding overhead. If an answer exceeds that capacity,
retain the largest UTF-8-safe prefix that fits and mark it explicitly as
“Truncated by IRMind's security limit”. Never label that prefix complete or
confuse this condition with the provider's output maximum. Preserve guard
validation of all displayed or retained text; do not weaken it to admit a larger
answer. Test a representative synthetic 128,000-token-size answer through
retention, signing and export, and test the explicit frame-overflow case. Tokens
are not bytes: an unusually byte-heavy answer can still reach the security limit.

The bounded 16 KiB child summary returned to the parent remains unchanged. The
complete child answer is retained in its branch within the same frame limit.
Resource failure, explicit cancellation and deadlines remain visible interruptions.

## 4. One automatic provider continuation

A native output/context stop (`length` / `max_tokens`, not a transport error)
shows “The model reached its maximum output”. If the next request passes case,
child reservation and round checks, make **one** automatic continuation with no
tools, preserving the same logical answer card. The continuation is an ordinary
billed request; it cannot reuse an exhausted reservation, bypass the round
limit, replay reasoning or execute incomplete tool-call arguments. Persist the
original parts and both usage reports even when the second part stops too.

Use structured assistant history with the guarded partial answer and a fixed
trusted continuation instruction. Reuse one structured history without appending a second copy of the evidence
prompt. The provider may bill that history again; record it. Never mix evidence
into `system` or join wire fragments by silently deleting text.
`/continue` remains the analyst action for round/budget exhaustion. A second
native stop is labelled explicitly; it cannot trigger an unbounded retry loop.

## 5. Implementation gates and tests

1. Review the model-capability port and exceptional token-settlement amendment.
2. Keep existing stream, guard and frame limits; review new accounting vectors
   and explicit security-truncation tests.
3. Implement profiles/settings and request-boundary accounting, then complete in-frame text
   retention and the single logical-answer continuation. Do not ship a state that
   merely removes `2048` while silently losing longer content later.
4. Test full long output, positive balance followed by a completed overrun and a
   blocked next call, known-max child admission and insufficient/unknown slices,
   valid exceptional settlement and forged/duplicate receipts, one provider
   continuation and a second stop, unknown mandatory model maxima, all provider
   wire dialects, and secrets/control sequences spanning text boundaries.
5. Test root/child/summary/compaction paths, context compaction distinct from
   retained output, cancellation/disk failure, verification/seal/export and a
   single continuous TUI card. No real provider or key is used in CI.
6. Update English/Spanish configuration docs, format-impact notes if needed and
   release notes. Public-launch preparation resumes after this priority change.
