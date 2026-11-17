# Prompt-cache accounting: first increment

Proposed concrete amendment to [context cost](context-cost-design.md), limited
to the stable trusted prefix and provider-reported cache usage. This is a
contract for review, not an implementation or a claim of provider savings.

## Model port and signed receipts

Add `cache: Option<CacheUsage>` to `ModelUsage` and `UsageEvent`. The existing
`input_tokens` means **all charged logical input**, including cache reads and
writes, exactly once. `output_tokens` keeps its present meaning. `CacheUsage`
has closed fields `read_input_tokens: u64`, `write_input_tokens: u64` and
`write_lifetime`, a closed enum (`not-applicable`, `five-minutes`, `one-hour`,
`unknown`). Ordinary input is the checked difference between total input and
read plus write. Counters must be disjoint; their sum cannot exceed input.
Unknown is `None`, never an invented zero. `not-applicable` requires zero writes.
Mixed or unreported write lifetimes use `unknown` and cannot use a five-minute
price. Construction and deserialization validate these invariants.

The optional member is omitted when absent. Existing no-cache JSON retains its
bytes. When present, append `cache` after existing fields, with the nested fields
in the order above; enum strings are fixed. Signed child reply payloads and their
matching `ModelUsage` receipt carry the identical breakdown. The existing
reservation settlement digest binds those bytes; neither a client nor a verifier
may rewrite them. Existing reply/usage checks also compare the breakdown.
There is no new audit kind, case marker, export section or settlement capability.
Export V8 includes and verifies the same signed records. Existing frame, guard,
stream and child-summary limits remain unchanged.

This is an amendment of public model-port value types and signed payload fields;
the general design alone did not approve its concrete encoding. No format or
port change is implemented before this amendment is reviewed. Pre-1.0 release
notes describe the additive payload/configuration change.

## Provider normalization

| Provider | Inclusive input | Disjoint cache counts |
| --- | --- | --- |
| OpenAI | `prompt_tokens` | `prompt_tokens_details.cached_tokens` is read; separately charged writes are structurally zero. Missing read detail means unknown. |
| DeepSeek | `prompt_tokens` | `prompt_cache_hit_tokens`, or documented cached-token detail, is read; validate any accompanying miss count and agreement between duplicate representations. Writes are structurally zero. |
| Anthropic | `input_tokens + cache_read_input_tokens + cache_creation_input_tokens` | Preserve reported read/create counts and declared/reported write lifetime. Never add them twice. |

An inconsistent breakdown does not discard a paid response. If inclusive input
is still independently known, retain that total with unknown cache detail and
unavailable differentiated cost. If inclusive input cannot be established safely
(for example incomplete Anthropic counters), keep the reply with unknown usage;
the existing uncertain-usage reservation remains retained. Overflow is never
saturation or credit. Missing usage cannot release a reservation.

Within a stream, use the final supported usage snapshot once; repeated cumulative
snapshots are updates, not additional bills. Reject contradictory or decreasing
counters as accounting uncertainty. Provider-specific events must not mix fields
from unrelated message IDs or requests. Synthetic tests exercise the actual
adapter event protocols, not just the normalization helper.

## Trusted prefix and provider controls

Canonicalize the **currently allowed** tool catalog in stable name/schema order.
Keep fixed trusted system instructions before changing context. Anthropic may
place default five-minute `cache_control` breakpoints at the end of the trusted
system block and the final allowed tool definition. Its four-breakpoint maximum
is not approached by this increment. No marker promotes a user/tool block into
system, pads the catalog, preserves a revoked tool or changes routing.

OpenAI and DeepSeek use their automatic cache without a warm-up request or new
retention setting. Compatible/local endpoints receive no undocumented controls.
Root and child contexts remain separate. Changes to policy, scope, skills, tools
or model immediately affect the next request; there is no permission cache.
Fresh per-turn nonces and `isolate_untrusted` are unchanged. No session nonce,
immutable admission capsule, history rewrapping change, paging, context-window
profile or auxiliary model belongs to this increment.

## Budgets, prices and UI

Charge inclusive input plus output against the existing case budget. A hit is
not a discount to logical token consumption. Child reservations continue to
cover full input and the native output maximum, with the already approved
request-boundary admission and actual-use/debt settlement rules. Cache metadata
cannot create tokens, calls, rounds or bytes and cannot settle twice.

Add optional read and five-minute write rates to the existing signed model-price
configuration and `ModelPricing`. Rates remain integer micro-USD per million
tokens. Use checked `u128` products and floor only the final sum divided by one
million, as today. A nonzero count needs its applicable configured rate; unknown
or mixed write lifetime is unpriced. Zero structurally charged writes need no
write rate. With unknown breakdown, differentiated cost is unavailable. An
aggregate cost is unavailable if any request is unpriced; do not label a known
subtotal as the total bill. These are estimates, never provider invoices.

`/budget` separates ordinary input, cache read, cache write and output, while
showing the unchanged charged total. Partial cache reporting is explicit; do
not present an incomplete sum as complete. The existing cache status-line segment
shows reported read/write counts or unavailable and retains width/priority,
terminal escaping and NO_COLOR behavior. Settings never infer prices or maxima.

## Vectors and acceptance

[Vectors](context-cache-accounting-vectors.json) fix normalized synthetic counts,
canonical usage JSON and SHA-256. The implementation must reproduce these bytes
and add matching child reply/settlement vectors before integration. Existing
current-format vectors without cache metadata remain unchanged.

Tests cover cache-free/unknown/zero counts; OpenAI, DeepSeek and Anthropic SSE;
duplicate/conflicting usage; impossible sums and overflow; unknown write price;
root and child accounting; mismatched signed reply/usage breakdowns; duplicate
settlement; debt without new capacity; export verification; and hostile content
with old/current delimiters. A cache marker cannot change a tool admission.

Repeat the three release-mode scripted workloads from the parent design on the
same runner. Publish input totals and exact-prefix coverage before/after; automatic
providers may already cache that prefix. No actual billed hit, latency reduction
or money saving is claimed without a real provider measurement. Never send a
commercial request merely to measure the design.
