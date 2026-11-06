# EVTX helper validation

This page is for maintainers reviewing the experimental decoder boundary. Read the [design](evtx-helper-design.md) for its protocol, limits and platform requirements.

## Tests and fixtures

The independently resolved helper tests cover the 27 supported event IDs, real record offsets, 100 ns timestamps, named EventData fields, the seekable-parser contract, signed V2 ingestion and reconstruction. The synthetic lateral-movement episode includes a network logon and service-install records. Only `source/` is ingested; evaluator expectations remain in `private/`.

A corrupt later chunk must roll back every provisional row and source/artifact manifest. Cancellation and termination of a decoder blocked on stdout must leave no successful completion trailer or private runtime directory. Native enforcement probes check unrelated-file reads, runtime writes, network access and process creation before decoding. Windows additionally tests explicit handle inheritance, private profile cleanup and failed executable startup.

The normal decoder build disables the containment crate's broker-only `launcher` feature. This keeps parent-side profile/launch DLLs out of the Windows decoder. The helper retains mandatory token and enforcement checks. Integration-test dependencies enable the broker API for their parent harness, so the test driver preserves and executes the normal-feature decoder, then restores it beside the main CLI:

```sh
python3 helpers/evtx/test.py
```

## Fuzzing

Local AddressSanitizer runs used the separately locked fuzz workspace, versioned synthetic seeds and a 768 MiB RSS limit:

| Target | Duration | Executions | Crashes found |
| --- | ---: | ---: | ---: |
| Decoder, initial run | 3,601 s | 20,737,363 | 0 |
| Decoder, final run | 3,601 s | 18,798,606 | 0 |
| Parent NDJSON protocol | 601 s | 5,842,132 | 0 |

The decoder target calls the decoding library directly. It does not exercise OS containment or prove coverage of every EVTX template or SIMD branch. Native tests cover the launcher separately. The nightly workflow repeats one hour of decoder fuzzing and ten minutes of protocol fuzzing. Temporary corpora are removed after each run; seeds remain versioned.

## Dependency unsafe audit

Release dry runs produce `EVTX-GEIGER-REPORT.json` with cargo-geiger 0.13.0 AST metrics and `EVTX-UNSAFE-REPORT.json` with the supplementary source inventory. Both are covered by the signed checksum list. The audit tool is downloaded prebuilt, pinned by executable SHA-256, and cannot fall back to source compilation. Published reports omit build-machine paths.

The native Linux AST scan reports these used unsafe expressions in important dependencies: `evtx` 0.15.1: 0; `landlock` 0.4.7: 43; `seccompiler` 0.5.0: 2; `sonic-rs` 0.5.10: 1,378; `utf16-simd` 0.2.0: 767. These are static counts, not a safety certification. Macro expansion, non-Linux conditional compilation and generated inputs limit coverage. The report identifies incomplete AST scans in non-production dependencies (`dbus` and `signal-hook-registry` in the local run). A parse failure in a production dependency or unidentified first-party source blocks the audit instead of silently treating it as safe. The first-party compiler/source gates and native Windows clippy checks independently enforce the dedicated unsafe boundary.

## Performance and platform evidence

The [release benchmark](benchmarks.md#isolated-evtx-conversion) records conversion throughput and its scope. Platform support requires the actual helper's enforcement probe, not merely a successful build. A container validates its userspace on the host kernel; it cannot certify its distribution's stock kernel. Windows Server runners cannot certify Windows 10 or 11, and one macOS version cannot certify other releases.
