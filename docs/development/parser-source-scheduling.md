# Parser source scheduling proposal

This proposal is for module authors and maintainers. It describes an additive local-parser capability, without changing source manifests, artifact schemas or custody formats.

## Port

Add a closed `SourceParallelism` type to `irmind-app` with two values: `Concurrent` and `Serial`. Add this optional method to `StreamingEventParser`:

```rust
fn source_parallelism(&self, _source: &str) -> Result<SourceParallelism, AppError> {
    Ok(SourceParallelism::Concurrent)
}
```

The method is synchronous and performs no I/O. Its default preserves existing parser behavior. Selection wrappers delegate using the already-selected source parser and reject unknown sources. The coordinator still imposes its existing maximum of four active source workers; `Concurrent` never means unbounded execution.

The EVTX module declares `Serial` on Windows to reflect its existing one-decoder-per-AppContainer-session contract. Linux and macOS retain concurrent independent helpers. The storage adapter consumes the declared capability; it does not inspect module names or infer native behavior from the platform.

## Coordinator

Keep initial streaming hashes parallel. Grant parser-start permits in canonical source order when a batch contains a serial parser. Start a serial source only when the coordinator can consume its bounded output. Independent parsers keep the current concurrent path.

Use cancellation-aware bounded sends, receives and start waits. Dropping a consumer closes its producer path. An error cancels sibling provisional work before returning. Keep the current queue, record, normalized-size and temporary-disk bounds. Preserve whole-batch rollback and authenticate the complete source before publication.

This metadata controls scheduling, not authorization. It cannot add native capabilities, relax isolation, extend scope, expose secrets, or change the signed source order. Witness reuse, services, explicit handles and the native execution lease remain mandatory.

## Validation

- A deterministic fake serial parser forces competing source startup and exercises bounded output on Linux, macOS and Windows.
- Cancellation and a failed source stop all provisional producers and release the case lock.
- Concurrent parsers retain their current execution path and byte-identical derived artifacts.
- Native Windows ingestion completes multiple EVTX files in one request with one session witness.
- Repeat the release collection benchmark with batches of one and four, retaining the 600-second invocation bound and all byte/record limits.

No production port or scheduling implementation is changed by the benchmark PR.
