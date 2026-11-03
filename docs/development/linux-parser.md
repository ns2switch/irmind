# Linux parser contract

This page is for analysts evaluating Linux exports and maintainers reviewing their normalization. The experimental `parser-linux` crate consumes auth.log/secure, auditd, journald JSON and HTTP common/combined files. Read access to the selected exports is enough.

## Selection and source time

The module is compiled by default behind the `parser-linux` feature. A bounded content detector recognizes Linux authentication tags, audit event headers, journald fields or a complete common/combined header. Filename extensions do not prove a format. Confidence is 95. PRI-prefixed syslog stays with parser-syslog; an explicit parser override remains audited. Other formats retain their detector scores and versions.

Classic authentication lines use the same per-ingestion year/offset form, command options and typed context as [syslog](syslog-parser.md). The application owns their shared pure calendar cursor. Each file has independent state; the parser commits a December/January candidate only after the entire row validates. Fixed offsets require explicit confirmation; IANA/DST remains [issue #161](https://github.com/ns2switch/irmind/issues/161). Signed parser versions bind context and basis, and the historical resolver reconstructs the recorded interpretation. SourceManifestV2, artifact and export encodings stay unchanged.

Journald `__REALTIME_TIMESTAMP` is interpreted as UTC microseconds. Audit epoch fractions and explicit authentication offsets retain their full source representation. Normalized text preserves fractional UTC time and the original data. The current V1 index still uses seconds; the approved artifact-V2 work follows this parser. Unknown fields remain in raw record text.

## Mapping

| Input | Normalized fields |
| --- | --- |
| sshd | Login/session action, observed result, authentication method, user, IP, port, host and PID. |
| sudo / su | User, target user, command or session, cwd and host. A command log alone does not prove execution succeeded. |
| useradd / usermod / cron | Recorded user, change or scheduled-command action, command and host. |
| auditd | Correlated syscall, execve argument array and command line, uid/auid, PID/executable, cwd, paths, sockaddr and component locations. |
| journald | Host, uid/auid, PID, executable/command and full microsecond timestamp; complete original JSON. |
| HTTP common / combined | UTC time from the explicit offset, client IP, user, method, URL and status-derived outcome; original request, agent and referrer remain in raw text. |

Audit records group by node, full timestamp and serial, not serial alone. The module retains each component's physical record number and byte offset. It reassembles bounded execve fragments, preserves argument boundaries and decodes unquoted hexadecimal text when valid; quoted numeric strings remain literal. Unsupported socket families or byte encodings remain in raw data. Known IPv4/IPv6 sockaddr values produce a neutral endpoint; direction is not guessed from an architecture-dependent syscall number.

The common/combined format has no server-host field. It remains unknown rather than being inferred from a filename. Use a [declarative definition](../examples/parsers/nginx-apache-custom.toml) matching a custom export when host or additional fields are needed.

## Bounds and partial records

Input is capped at 1 MiB per line, ten million physical lines and 50 GiB per source. JSON depth is at most 64 with 1,024 fields. Rejected lines are counted; at most three escaped samples of 256 bytes are retained. Later valid lines continue. Read, cancellation and whole-source limit failures reject conversion before custody is committed.

Audit grouping holds at most 64 pending events, each with 128 records and 256 KiB of source text. Overflow records are rejected without discarding the already buffered components. A two-second source-time timeout, bounded-state eviction or EOF emits an unfinished group as partial. This is deterministic offline parsing, not a wall-clock wait. Missing core records, argument gaps and conflicting fragments also mark a group partial. An end marker does not make an orphan group complete.

All output is Tainted with source hash, record number, parser identity and byte offset. Guard/redaction apply on model input and display. Process, PID, command and path metadata do not widen the graph tool policy's existing entity-kind allowlist; use permitted host queries, neighbors and text search where a direct kind is unavailable.

## Validation and sources

The shared parser contract, native detection matrix, malformed/oversized input, cancellation, timestamp retention, grouping and signature/rebuild tests use synthetic data. The fixture's private ground truth is evaluator-only. Its expected attack route connects the synthetic SSH source, host and root account. The parser has its own detect/parse fuzz target and release-only 1 GiB benchmark; results are in [benchmarks](benchmarks.md).

Primary format references: [audit event correlation](https://man7.org/linux/man-pages/man8/ausearch.8.html), [audit timeout](https://man7.org/linux/man-pages/man8/aureport.8.html), [journal fields](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html), [nginx access logs](https://nginx.org/en/docs/http/ngx_http_log_module.html), [Apache common/combined logs](https://httpd.apache.org/docs/2.4/logs.html). These describe exported data; validation against a live environment is not claimed.
