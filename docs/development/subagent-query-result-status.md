# Typed completeness of delegated evidence queries

Approved additive refinement of the
[subagent query contract](subagents-format-contract.md).
[Español](../es/subagent-query-result-status.md).

## Current boundary

`TaskEvidenceQueries::execute` returns `TaskEvidenceResult`. Its current variants
are `Text(String)`, `Timeline(Vec<TimelineEvent>)` and
`Original(Box<Tainted<SourceRecordV1>>)`. The implementation is visible in
[the subagent implementation](https://github.com/ns2switch/irmind/blob/94e96d0921732d6d0bd2c9bbd2bac278e83dcefe/crates/app/src/subagents/queries.rs).

Queries already retain their result, sampling, expansion and time bounds. Some
backend APIs render completeness information into a string before returning it.
That boundary cannot reliably tell the child dispatcher whether a successful
query returned complete data or a partial result. Parsing phrases from the
display text would also confuse source content with engine status.

## Proposed application result

Keep the trait signature and all three existing variants. Add two variants and
one closed reason type:

```rust
pub enum TaskQueryPartialReason {
    Sampling,
    Expansion,
    Deadline,
    ResultLimit,
    ExcerptLimit,
    Coverage,
}

pub enum TaskEvidenceResult {
    Text(String),
    Timeline(Vec<TimelineEvent>),
    Original(Box<Tainted<SourceRecordV1>>),
    PartialText {
        text: String,
        reason: TaskQueryPartialReason,
    },
    PartialTimeline {
        events: Vec<TimelineEvent>,
        reason: TaskQueryPartialReason,
    },
}
```

There is no recursive result wrapper, free-form status, new trait method,
dependency or credential. Existing adapters can keep returning their existing
variants. An adapter that knows a result is partial must use a partial variant.
Other failures continue to return an error; an unsupported source view never
falls back to an unrestricted query.

## Backend propagation

Add private typed result helpers below the native query adapter. They preserve
the status already known by the Parquet scan, candidate sampling and path
expansion code. Existing graph ports keep their signatures and rendered output;
their wrappers render the same internal result as before. Delegated queries use
the typed helper directly, without executing a query twice.

The adapter must not detect status by searching returned text, JSON field names,
evidence excerpts or model output. A record containing `partial`, `truncated` or
a phrase resembling an engine message remains ordinary source data.

Preserve each query's existing meaning of requested limits versus incomplete
execution. A normal bounded result is not reclassified solely because a limit
was requested; an existing sampling, truncation, coverage or deadline condition
must not be cleared. Raw-record and original-record excerpt clipping also
propagate completeness explicitly, without changing their size bounds.

## Branches, parent results and export

The dispatcher screens the text as before and sets the existing
`BranchToolResult.partial` flag from the typed status or from its own output
clipping. A closed reason produces a fixed, guarded coverage notice. A later
model reply cannot clear that flag: the terminal task result remains partial
when a prior result was incomplete, as required by branch verification.

No new signed field, event kind, canonical code, envelope, frame or export
section is introduced. The current checkpoint, terminal and export V8 formats
and their golden bytes remain unchanged. Ordinary successful results retain
their bytes; affected partial results use the flags and coverage fields already
defined by the approved format.

## Acceptance checks

- A source-restricted path stopped by its existing time or expansion budget
  returns a typed partial result and retains the existing bounds and text.
- A sampled neighbors result retains its sampling marker and becomes partial
  in the child branch, parent projection and independently verified export.
- Partial timeline rows remain ordered and source-restricted; no broader query
  is issued to fill the missing rows.
- A model that claims completion after a partial query cannot produce a
  completed terminal record. A re-signed inconsistent terminal is rejected.
- Source text containing status-like words or JSON fields never controls the
  status. Existing complete-result fakes and canonical vectors still pass.
- Fixed-clock runs with 1, 2, 4 and N workers remain byte-identical, including
  partial results. No query limit, timeout, validation or policy is relaxed.
