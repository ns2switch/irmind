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
| Parent protocol plus Windows witness codec | 601 s | 6,472,865 | 0 |

The decoder target calls the decoding library directly. It does not exercise OS containment or prove coverage of every EVTX template or SIMD branch. Native tests cover the launcher separately. The nightly workflow repeats one hour of decoder fuzzing and ten minutes of protocol fuzzing. Temporary corpora are removed after each run; seeds remain versioned.

## Dependency unsafe audit

Release dry runs produce `EVTX-GEIGER-REPORT.json` with cargo-geiger 0.13.0 AST metrics and `EVTX-UNSAFE-REPORT.json` with the supplementary source inventory. Both are covered by the signed checksum list. The audit tool is downloaded prebuilt, pinned by executable SHA-256, and cannot fall back to source compilation. Published reports omit build-machine paths.

The native Linux AST scan reports these used unsafe expressions in important dependencies: `evtx` 0.15.1: 0; `landlock` 0.4.7: 43; `seccompiler` 0.5.0: 2; `sonic-rs` 0.5.10: 1,378; `utf16-simd` 0.2.0: 767. These are static counts, not a safety certification. Macro expansion, non-Linux conditional compilation and generated inputs limit coverage. The report identifies incomplete AST scans in non-production dependencies (`dbus` and `signal-hook-registry` in the local run). A parse failure in a production dependency or unidentified first-party source blocks the audit instead of silently treating it as safe. The first-party compiler/source gates and native Windows clippy checks independently enforce the dedicated unsafe boundary.

## Performance and platform evidence

The [release benchmark](benchmarks.md#isolated-evtx-conversion) records conversion throughput and its scope. Platform support requires the actual helper's enforcement probe, not merely a successful build. A container validates its userspace on the host kernel; it cannot certify its distribution's stock kernel. Windows Server runners cannot certify Windows 10 or 11, and one macOS version cannot certify other releases.


Linux/macOS baseline evidence comes from [this CI run](https://github.com/ns2switch/irmind/actions/runs/42235137349). The updated Windows witness and cache passed in [the native Windows run](https://github.com/ns2switch/irmind/actions/runs/42266599470). Availability still runs the enforcement probe on each installation.

| Configuration | Evidence | Result |
| --- | --- | --- |
| Ubuntu 22.04.5, x86-64, kernel 6.8.0-1070-azure | Native helper probe and decoder | Passed; this does not certify the original 22.04 GA kernel |
| Ubuntu 26.04.1, x86-64, kernel 7.0.0-1019-azure | Native helper tests and workspace suite | 10 helper and 626 workspace tests passed |
| Debian 12, x86-64, kernel 6.1.0-53-amd64 | Native local helper tests | Passed |
| Debian 12 and Fedora 44 userspace on the Ubuntu 22.04 host kernel above | Pinned containers, without network | Passed; distribution stock kernels remain untested |
| macOS 26.6.2, arm64 | Native sandbox profile, helper tests and workspace suite | 10 helper and 626 workspace tests passed |
| Ubuntu 24.04.5, x86-64, kernel 7.0.0-1017-azure | Native helper probe and same released helper as Ubuntu 22.04 | Passed |
| Windows Server 2025, x86-64, build 10.0.26100 | Native traffic witness, handle checks and session reuse | 6 targeted boundary checks and 13 helper tests passed; no firewall or service changes |
| Windows 10 and Windows 11 clients | No native execution | Untested; no support claim |

The required native tests remain enabled on each platform. A failed probe makes EVTX unavailable; it does not select a weaker launcher. Windows client confirmation remains separate from the passing Server tests.


The [Windows network-probe proposal](evtx-windows-network-probe.md) distinguishes traffic isolation from socket creation and requires controlled live endpoints rather than treating an arbitrary connection timeout as proof. The implementation includes the memory-only session witness, service-change invalidation and per-launch token/handle checks. The full platform matrix and signed distribution dry run remain integration gates.


The [Windows 11 community check](https://github.com/ns2switch/irmind/issues/189) tracks client confirmation using the [manual candidate procedure](manual-validation.md#experimental-evtx-windows-11-candidate-check). No firewall settings, service configuration or loopback exemptions are changed by the tests.

The [completed signed candidate run](https://github.com/ns2switch/irmind/actions/runs/42273621946) passed 630 workspace tests on Linux and macOS and 636 on Windows, plus 10/10/13 separate helper tests. Native Ubuntu 24.04 ARM64 also passed the contained release probe and synthetic decode. Windows 10/11 client confirmation remains separate.
