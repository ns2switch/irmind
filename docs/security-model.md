# Security model

This page is for analysts and reviewers deciding whether an IRMind evaluation fits their data. It explains what the current build enforces and what it cannot promise.

> IRMind is under development. Do not use it for real incidents or sensitive data yet.

## The trust boundary

The model can suggest a tool call but cannot execute one. The application validates the tool and arguments, checks case scope and limits, and records a signed decision. Only an authorized call reaches a remote connector. Read operations must stay in scope. External enrichment waits for a signed analyst approval. Containment is disabled.

The analyst controls the case, its scope, approvals, and signing key. Files, logs, remote results, graph text, and model output are untrusted. They may contain instructions written by an attacker.

## What the build enforces

- **Custody:** Original evidence is stored locally by SHA-256. Case changes and tool activity enter an append-only SQLite audit chain with Ed25519 signatures. Verification detects changed entries and evidence bytes.
- **Diagnostics:** A private, size-bounded `diagnostics.log` records operation names, result categories, and durations. It is separate from custody, contains no evidence or tool arguments, and is not part of exports or verification.
- **Separate identities:** Analyst and Agent have distinct signing keys in the selected backend. Only an analyst signature can resolve a pending approval. A sealed case has a separate signed operational chain for task cancellations; backend migrations enter a global signed operational chain.
- **Guarded model input:** External text is normalized, screened for prompt injection, redacted for known secret and PII patterns, bounded, and wrapped as untrusted data. The original remains local. A startup self-test blocks the application if the guard's known corpus fails.
- **Constrained connectors:** Credentials come from the explicitly selected secret backend through the composition root. Remote clients require HTTPS, except keyless HTTP to an explicit loopback model service. Redirects are disabled and responses are bounded.
- **Safe presentation:** The TUI removes terminal control characters from model output, evidence summaries, and filenames. Approval views show the exact proposed arguments after terminal escaping.

A case export contains its signed log, seal, evidence, and public key. Use `verify-export --expected-key` with a fingerprint obtained through another trusted channel.

## Threats considered

| Actor or source | Main risk | Current defense |
| --- | --- | --- |
| Author of investigated logs | Hidden instructions, false roles, malicious filenames | Untrusted-data wrapper, guard, policy independent of the model, terminal escaping |
| Compromised provider or network | Data exposure, changed responses, unsafe redirects | TLS, no redirects, bounded responses, local signed evidence, explicit provider selection |
| Process with the analyst's local permissions | Read or alter local files and use the keyring | File permissions and audit verification detect some changes; the process may still act as the user |
| Malformed input package or file | Path traversal, deep JSON, resource exhaustion | Bounded ingestion and export parsing, no symlink following by default, path checks |

## Known limits

- Redaction and injection detection are pattern-based. They can miss sensitive data or malicious instructions. Never rely on them as permission to send regulated data to a provider.
- A process that controls the analyst account and signing key can replace an entire case chain. Pin the public-key fingerprint outside this computer; external seal anchoring is not implemented.
- File permission checks do not protect against a fully compromised user session. Some path components can change between directory traversal and file opening.
- VirusTotal enrichment exposes the queried IOC to an outside service. It always needs approval. A read-only connector still depends on the permissions actually granted by its service.
- The graph is a derived index, not original evidence. Verify or rebuild it from signed inputs when its correctness matters.
- CI binaries have checksums but are not code-signed, notarized, or Authenticode signed. See [platforms](platforms.md).
- The OS keyring and encrypted-file backends are explicit choices, never silent fallbacks. The file backend works over SSH, but its security depends on a strong passphrase and a trustworthy host. Losing the signing key can prevent continued case work.

## Operating guidance

Start with the [synthetic example](getting-started.md). Keep remote scope narrow, use dedicated read-only service credentials, and approve only calls whose exact arguments you understand. For a suspected vulnerability, use the private process in [SECURITY.md](../SECURITY.md) rather than a public issue.
