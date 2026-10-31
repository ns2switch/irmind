# Contributing to IRMind

This guide is for contributors preparing an issue or pull request. IRMind is under development: use only synthetic data in issues, tests, examples, and review discussions. Never attach real incident evidence, credentials, or personal data. Report vulnerabilities privately through [SECURITY.md](SECURITY.md).

## License and DCO

Contributions intentionally submitted for inclusion are offered under **MIT OR Apache-2.0**, without additional conditions, as stated in the [README](README.md#license).

Every commit in a pull request must include a `Signed-off-by` trailer with the author's name and email. The trailer certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/). CI checks that its email matches the commit author.

```text
Signed-off-by: Your Name <you@example.com>
```

Use `git commit -s` for a new commit. To fix your last local commit, use `git commit --amend -s`. Sign each commit in a multi-commit pull request. Never sign on behalf of another person.

## Before opening a pull request

- Keep the change within the current [architecture](docs/development/architecture.md) and document any new public behavior.
- Add meaningful tests for policy, custody, parsing, or connector changes. Use synthetic fixtures.
- Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo nextest run --workspace --all-features --locked`, and `cargo deny check`.
- Describe security implications, tests run, and known limits in the pull request template.

English documentation is authoritative. Update a Spanish translation when its user-facing source changes, and put the English source commit hash in its first line.

## Changes we welcome

We welcome parsers, read-only connectors, accessibility and terminal improvements, better synthetic fixtures, documentation, and performance improvements that preserve custody and verification. Start with [the module guide](docs/development/adding-a-module.md) for a parser or connector. Be kind and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

We do not accept changes that weaken policy enforcement, signed custody, TLS certificate or hostname verification, secret isolation, or the mandatory content guard. Do not submit real incident records, personal data, private keys, or live service responses. Report a security issue through the private process in [SECURITY.md](SECURITY.md), not a public issue.
