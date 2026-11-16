# Context cost, prompt caching and bounded context management

Design only. The observer and offline calculations measure the current engine;
no product cache markers, nonce changes, paging, context thresholds or auxiliary
models are implemented by this proposal. Output generation continues to use the
native model maximum and request-boundary accounting. No provider was called.

## 1. Baseline and reproducibility

Baseline engine: `41c174bdbcfcf770f23218e0cbcdcec7c1509c8e`. The scripted
`LlmPort` receives real `CompletionRequest` values from ingestion, skills,
investigation, compaction and the three-child broker. It reports simulated usage:
`ceil(provider-neutral UTF-8 JSON bytes / 4)` for input and response bytes / 4
for output. This is a planning convention, **not a provider tokenizer, production
admission bound or measured bill**. Roles, call IDs, schemas, nonces and replayed
messages are included. Existing policy defaults, including 25 rounds, remain.

| Workload | Analyst turns | Ordinary requests | Compaction requests | Input tokens, simulated |
| --- | ---: | ---: | ---: | ---: |
| Conversation, 10 turns | 10 | 10 | 0 | 73,445 |
| Investigation with AWS skill, 15 useful rounds | 1 | 15 | 0 | 126,382 |
| Windows/AWS/Kubernetes plan, three children | 1 | 11 (2 root + 9 child) | 0 | 48,655 |
| Separate stress: same investigation, long preliminary notes | 1 | 15 | 3 | 183,594 |

Conversation answers are about 1.6 KB. The investigation loads the bundled
`aws-credential-compromise` skill and issues thirteen distinct, real local searches
with limits 7–19 over twenty synthetic records. Long-note stress adds about 4 KB
to each scripted preliminary reply. The mixed plan uses its existing synthetic
Windows, AWS and Kubernetes episode and validates, seals and exports its result.
Expected findings remain outside model requests. No remote connector or model is used.

The per-turn conversation inputs are **5,061; 5,568; 6,076; 6,583; 7,091; 7,598;
8,106; 8,613; 9,121; 9,628**. Each single-turn investigation/plan total is the
corresponding table total. Every request, actor, turn, component byte count and
simulated usage is in [baseline.json](context-cost-data/baseline.json).
[repeats.json](context-cost-data/repeats.json) records three repetitions; aggregate
input totals and prefix estimates were identical. Counts are obtained in release
builds; they are not ingestion-throughput or wall-clock benchmarks.

```sh
sh scripts/context_cost/reproduce.sh target/context-cost/run-1
python3 -B scripts/context_cost/test_analyze.py
sha256sum --check docs/development/context-cost-data/SHA256SUMS
```

Use a new trace directory for each repetition. Raw synthetic prompts stay in the
local trace directory; the published metrics contain counts, not prompt contents,
personal paths or machine details. The checksums bind the data and capture/analysis
sources. Random case IDs/nonces and child scheduling need not reproduce byte-for-byte;
the captured request is measured **before** any offline normalization.

## 2. What is repeated, and what is cacheable

| Workload | Repeated system | Repeated tool catalog | Exact replayed message-prefix content | Reusable-prefix ceiling |
| --- | ---: | ---: | ---: | ---: |
| 10 turns | 1,980 | 32,256 | 0 | 33,408 / 73,445 (45.49%) |
| 15 rounds + skill | 3,080 | 45,019 | 61,965 | 107,776 / 126,382 (85.28%) |
| Three children | 926 | 20,910 | 7,793 | 29,056 / 48,655 (59.72%) |
| Long-note stress | 3,188 | 45,019 | 81,634 | 129,152 / 183,594 (70.35%) |

Values are simulated tokens. These columns overlap and must not be added.
Repeated system/catalog means an identical component already sent to that actor.
The message-prefix column counts unchanged non-system messages at the start of
that actor's next request. Old signed turns are also retransmitted in conversation,
but their fresh wrappers prevent that exact-prefix metric from counting them.

The prefix simulation puts tool definitions before messages, then finds the
longest byte prefix among prior requests **of the same actor**. For one illustrative
cache model it requires 1,024 simulated tokens and rounds down to 128-token blocks.
Those parameters are not universal vendor rules. It assumes perfect retention,
no eviction, sufficient breakpoints and compatible routing; real hits may be zero.
HTTP JSON key order is not itself the provider's tokenized prompt order.

Important correction to the initial hypothesis: automatic-cache providers may
already reuse much of a single turn. This run cannot establish actual cache hits
or savings. The engine currently discards their cache breakdown. After a skill
load, the allowed catalog contracts; preserving a larger catalog just to keep a
cache hit would be unacceptable. A greeting remains tool-free.

Current compaction tests **48,000 message/argument bytes**, excluding the tool
catalog, and summarizes in 24,000-byte chunks. Other independent bounds already
reduce `raw_records` to a 2,000-character excerpt. In these traces the largest
Tool messages were 2,520 bytes in the skill investigation and 4,883 in the mixed
plan, including envelopes/skill text: the 10,000-byte policy maximum is not the
size of every tool result.

## 3. Stable context without promoting untrusted content

Build an explicit context plan: trusted instructions and the allowed tool catalog;
then admitted skill capsules and immutable old conversation; then the changing
case snapshot, recent complete exchanges, current analyst input and new results.
The exact provider order may put tools before system. **Skills, case data,
compaction summaries and prior model text stay in guarded UNTRUSTED user/tool
content, never system.** Assistant/tool-call pairs remain atomic and linked by ID;
never move a tool result ahead of its assistant call for caching.

Freeze canonical tool names, descriptions, schemas and ordering for a permission
epoch. A policy/scope/model/profile/skill change starts a new epoch and cache
namespace; it does not preserve obsolete capabilities. Children use their own
source set, context and tool intersection. Never pool root and child histories.
Loading a skill may invalidate the prefix once; afterward reuse its admitted
snapshot. Removing or changing its permissions invalidates the prefix immediately.

### Nonces: retain the present defense by default

A nonce makes an enclosing delimiter unpredictable when untrusted text is first
admitted. It is not an authorization capability or a guarantee that a model will
ignore malicious instructions. The model, the analyst, a provider and potentially
an attacker with observation access can learn a nonce after use. A case/session
nonce would then be predictable for later evidence controlled by that attacker.

Current `isolate_untrusted` escapes **only the opening/closing delimiters for the
supplied nonce**. It does not escape every old nonce. A previous nonce inside a
fresh turn remains literal data; it does not match that turn's enclosing marker.
If every admission isolates against a reused case nonce, exact matching markers
are still escaped: knowledge alone is **not** a bypass. Reuse nevertheless removes
the fresh-boundary defense in depth and makes an accidentally unisolated path
persist across the case. A session nonce only shortens that exposure; it becomes
known after the first request too. Proving coverage of every admission path,
normalization and fragment boundary would be necessary before approving either
choice. Do not claim nonce secrecy is permanent or introduce reuse as a cache-only
change.

Safe first increment: retain the fresh per-turn nonce and cache only the stable
trusted head, with ordinary within-turn append-only reuse. This does not make the
rewrapped historical material cacheable across turns.

A later, separately reviewed alternative is **immutable admission capsules**:
fresh random nonce per newly admitted block, unchanged guarded bytes when replayed,
and bounded escaping of *all delimiter-shaped input* before applying an envelope,
including old active nonces, after final decoding/normalization and concatenation.
Store/hash the guarded capsule and its guard/policy
version; changed guard policy invalidates or regenerates it. No mutable source is
trusted from a previously verified hash. New evidence never inherits an old block's
nonce, and blocks from another case/child are not imported. This requires its own
encoding/escaping contract and hostile-evidence tests before rollout.

The offline entropy-free/reordered reference layout is deliberately **not safe to
deploy**. It estimates a conversation reuse ceiling of 56,704 tokens, versus
33,408 today: 23,296 additional potentially reusable tokens (31.72% of input).
There is no increase for the 15-round or child workloads. In stress it loses 768
reusable tokens. This is an estimate for that layout, not proof of a secure nonce
scheme or a promise that reordering always helps. No nonce change is in v0.5.1.

## 4. Provider cache profiles

| Provider | Proposed behavior and authoritative reference |
| --- | --- |
| Anthropic | Explicit `cache_control` on stable system/tool and guarded message blocks, at most four breakpoints; keep long-gap retention opt-in. A breakpoint's prefix must actually remain identical. The documented 20-position lookback means one final marker is not sufficient for every long history. Read `cache_read_input_tokens` and `cache_creation_input_tokens`. [Official caching guide](https://platform.claude.com/docs/en/build-with-claude/prompt-caching). |
| DeepSeek | Automatic prefix caching; no enable flag or speculative warm-up request. Persistence boundaries and best-effort retention matter. Read `prompt_cache_hit_tokens` / `prompt_cache_miss_tokens`; the former also appears as `prompt_tokens_details.cached_tokens`. [Cache guide](https://api-docs.deepseek.com/guides/kv_cache/), [Chat API usage](https://api-docs.deepseek.com/api/create-chat-completion/). |
| OpenAI | Automatic caching, stable prefixes and model-specific capabilities. Earlier profiles may use an opaque stable `prompt_cache_key`; current newer profiles have different routing/write/lifetime rules. Read Chat Completions usage fields; do not transplant Responses-only controls into the current adapter. [Official caching guide](https://developers.openai.com/api/docs/guides/prompt-caching), [Chat API](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create). |
| OpenRouter | Follow both the selected model and routed provider; preserve supported explicit markers and read `prompt_tokens_details.cached_tokens` / `cache_write_tokens`. Routing changes may lose reuse. Do not silently pin a new provider or change data residency for a hit. [Official guide](https://openrouter.ai/docs/guides/best-practices/prompt-caching). |
| Other compatible/local | Unknown by default. No unsupported cache fields, claimed hits or invented prices. Expose declared capabilities only where documented/tested for that endpoint. Native server-side caches may exist without client controls. |

Use an opaque case/profile/actor-scoped cache namespace where supported, without
case titles, evidence, credentials or personal paths in a routing key. A cache key
is not an access-control boundary. Cache reads never import another case's data.
Do not prewarm, keep a cache alive, retry an ambiguous billed request, extend
retention or send data to a second endpoint without explicit analyst configuration.
Provider retention/residency rules still apply; case sealing cannot erase their cache.

## 5. Accounting and /budget

Normalize reported usage to disjoint **ordinary input, cache read, cache write and
output**, retaining model/endpoint, availability and write lifetime. For OpenAI/
DeepSeek/OpenRouter, cached counts normally subdivide the reported input total:
do not add them again. Anthropic's total input is
`input_tokens + cache_read_input_tokens + cache_creation_input_tokens`.
Missing breakdown is unknown, not zero. Repeated streaming usage snapshots are
updates, not independent bills. Reject inconsistent breakdowns for pricing while
retaining a known total and the paid response.

The case token budget charges **every logical input token once**, including reads
and writes, plus output. Cache-price multipliers affect money, not token identity.
For example, a 0.1× price does not turn ten cache tokens into one budget token.
Child input reservations still cover the full request, never an assumed hit.
Keep request-boundary admission, actual overrun settlement and no credit from debt.

With complete configured rates, estimate:
`ordinary * input_rate + read * cache_read_rate + write * cache_write_rate + output * output_rate`.
Honor the provider/model/TTL rate; writes can cost more than ordinary input.
Without sufficient rates/breakdown, show cost unavailable rather than an invented
zero or a falsely bounded estimate. /budget shows all four quantities separately,
the combined charged total and any known cost; status-line display stays compact.

Extending `ModelUsage`/`UsageEvent`, branch reports and signed accounting bindings
requires a concrete receipt/schema amendment and new canonical vectors. Current
parsers use closed fields; extra JSON keys cannot simply be slipped into signed
records. Unknown usage must not free an unsettled reservation. This design is not
that format approval.

## 6. Profile-aware compaction

Add a context profile distinct from `ModelOutputProfile`: documented/declared
window, tokenizer/counting capability, provenance and analyst input threshold.
Proposed initial prudent ceilings: **128,000 input-token upper bound and 512,000
serialized request bytes**, including tools/envelopes; lower provider windows win.
Use a safety margin and the unchanged native output maximum. An incompatible
window/output declaration produces an actionable settings error, not a smaller
output allowance or omitted safety instructions.

Use exact compatible token counts when available. Without an approved tokenizer,
use a conservative byte/framing upper bound for admission; the four-byte planning
estimator from this study is not safe enough for that job. New tokenizer
dependencies or counting-network calls require separate review. Unknown windows
retain the current conservative behavior and show how to configure the profile.
A candidate trigger is 75% of the safe input allowance, with a 45% post-compaction
target, instead of compacting repeatedly just below the same boundary.

Summarize one large eligible block **only if it fits the summarizer's window,
byte bounds and case admission**. Otherwise retain bounded hierarchical batches.
Preserve recent complete exchanges, exact source references, confirmed findings
and pending questions; validate summary citations against the case. Keep the full
guarded model reply signed within existing security limits. A separate bounded
summary used for future context is not a cut to the paid displayed answer.

In the three base workloads, compaction-call savings are **zero**. Stress has
three summary calls in two episodes, totaling 12,317 input tokens. Merging the
adjacent small tail with its preceding chunk, assuming the same scripted summary,
reduces that to two calls and saves only **154 input tokens (0.084% overall)**.
Larger windows may send *more* history and raise the case's token consumption;
they are not a cost reduction by themselves. Gate tuning on captured replay costs,
not only fewer summary calls. Test citation/pending-question retention; prompted
preservation alone does not prove semantic completeness.

## 7. Bounded tool summaries and pages

Most ordinary tool results are already stored as full bytes with an evidence
hash and signed `ToolResult` reference before a guarded model excerpt is returned.
Reuse those immutable bytes rather than rerunning queries. Skill reads and child
summaries have their own snapshot/branch provenance and are not silently replaced.

Propose a typed summary containing coverage/truncation, source hashes, useful row
IDs and a result ID, initially budgeted near 1 KiB plus 160 bytes of reference
metadata. A bounded Read tool can request a page of that exact result. Bind every
cursor to case, result hash, original authorized call/source set, row order and
policy epoch. Revalidate current scope/organization ceiling; never treat a hash
as permission. Each page counts as a tool call, is cancelable and passes taint,
provenance and ContentGuard. No fresh remote read is hidden behind a local cursor.

Keep the existing 5 MB acquisition cap, 1 MB guard input and 10,000-byte model
result policy. Initial paging should only expose a complete logical text that can
be screened safely within the existing guard limit; larger/binary objects remain
unavailable rather than bypassing it through tiny chunks. Do not leak a secret
split across page boundaries. No unlimited result retention, calls or page count.
A bounded case-local result lookup may need a reader port; the tool vocabulary,
receipt authorization and cursor encoding need a concrete contract first.

The **size-only**, zero-extra-page oracle saves 8,055 input tokens (6.37%) in the
skill workload, 6,810 (3.71%) in stress, and zero in the other two. It excludes
skill bodies and delegated summaries. It does not demonstrate a useful semantic
summary. At the 10 KB maximum, an approximately 1.18 KB reply can avoid up to about
88% of *that result's bytes*, not 88% of the whole case. If a quarter of thirteen
results require another model round, four extra full-context requests can exceed
the measured 8,055-token saving. Validate 0%, 25% and 100% page-demand workloads
and findings/citations before choosing a default. Never claim missing evidence
was inspected merely because its result ID was returned.

## 8. Optional auxiliary model

A signed auxiliary profile for compaction/summaries is off by default; absence
uses the primary model. Provider, endpoint, model, native output/context capability,
SecretBackend key reference and role are explicit. A different remote endpoint
requires its own data-disclosure confirmation; no ambient key or silent fallback.
Summarization remains tool-free and guarded, with the actual model and usage signed.
An optional child-model choice must be visible in the plan and frozen before its
reservation; it cannot change a running child's budget or allowed sources.

Switching models alone saves **no logical tokens**. At an illustrative half input
price, summary input cost saves 0% in the base workloads and 3.35% in stress, before
output/rate/cache differences. Child requests account for 37,795 / 48,655 input
tokens; a half-price child model gives an input-cost-only ceiling of 38.84% there.
These are price-ratio sensitivities, not model recommendations or observed bills.
Different model caches start cold and cheaper summaries may lose important facts.
The profile registry/configuration and per-request accounting contracts need review.

## 9. Priority, effort and acceptance gates

| Order | Proposal | Measured opportunity | Effort / complication |
| --- | --- | --- | --- |
| 0 | Normalize usage and expose cache accounting | 0 direct saving; necessary to know the actual bill | Medium: adapters, signed receipts, broker/verifier and UI |
| 1 | Cache the stable allowed head, then eligible append-only history | Illustrative head-only input-price reductions: 40.66%, 32.61%, 33.75% for the three base workloads | Small/medium after accounting; automatic providers may already do better, so incremental saving is unknown |
| 2 | Result summaries + authorized pages | 0%, 6.37%, 0% input reduction with no extra pages | Medium/large: exact result references, guard boundaries, authorization and quality evaluation |
| 3 | Profile thresholds / larger summary batches | 0 base saving; 154 stress input tokens and one request | Medium; more context can increase cost, lower-water hysteresis needs measurement |
| 4 | Immutable historical/skill capsules | Optimistic extra 23,296 reusable tokens across 10 turns; none in other base traces | Large: nonce/escaping contract, signed provenance, protocol preservation and invalidation |
| 5 | Auxiliary summarizer, optional child model | 0 base summary gain; 3.35% stress input-cost sensitivity at half price | Medium/large: second profile/egress, cold caches, model quality and reservation binding |

The head-only price illustration uses ordinary input 1×, reads 0.1×, writes 1.25×,
a cold first write and no eviction. It changes no transmitted token count and is
not an incremental estimate against an already warm automatic cache. Provider
rates/eligibility must be measured separately; writes and expiry can erase savings.

After design review: first concrete ports/usage vectors; then adapter accounting
and cache markers with recorded synthetic streams; then prefix planning without
nonce changes; finally separately reviewed paging, capsules and auxiliary profiles.
No speculative cache hits fund reservations. No per-response token cap returns.
Tests must cover unknown/missing cache fields, conflicting snapshots, write/read
normalization, cache expiry/routing changes, old-nonce injection, edited evidence,
role separation, tool-pair validity, source-restricted children, page-boundary
secrets, exhausted budgets and full-response export. Compare quality and paid
usage on real models only through an explicit analyst-run evaluation.
