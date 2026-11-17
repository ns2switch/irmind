# Local `object_store` patch

This directory contains the published Apache `object_store` 0.13.2 source, with its original `LICENSE.txt` and `NOTICE.txt`. The crates.io archive SHA-256 is `622acbc9100d3c10e2ee15804b0caa40e55c933d5aa53814cd520805b7958a49`. The bounded-response change is in `src/client/http/body.rs`; calendar and duration dependency substitutions are described below. Two trailing whitespace lines in the published license and attributes file were normalized for repository checks.

The patch limits buffered HTTP metadata and listing responses to 8 MiB before parsing. It checks both a declared lower size bound and every received chunk. An oversized response returns a non-retryable decode error. Object GET payloads remain on the separate streaming path, where IRMind enforces the signed per-read byte limit.

The tests in `irmind_bounded_response_tests` cover a declared oversize body, an unbounded stream that crosses the limit, and a valid response. `irmind-mod-storage-object` also tests an oversized S3 listing through the real SDK path and a synthetic HTTP server.

When upgrading, compare this file and the patched body against upstream, confirm that every S3, GCS, and Azure list path still uses the bounded collector, and rerun the storage module tests before removing or adapting the patch.


## Maintained date dependencies

Calendar imports now use the safe `irmind-calendar` utility backed by `time`.
Duration parsing and formatting use Jiff, with a bounded normalization table that
preserves the SDK's supported unit aliases and fixed meanings of months and
years. Precision and arithmetic overflow are rejected, without timezone or
calendar inference. UTC serialization and request signing are covered by frozen
synthetic reference vectors and provider contract tests.

IRMind does not use ambient Azure CLI authentication. That SDK-only fallback now
returns an explicit-credentials error without launching the CLI or interpreting
host-local dates. Explicit access keys, SAS and configured service credentials
continue on their existing paths. Full TLS verification and the 8 MiB metadata
collector remain unchanged.
