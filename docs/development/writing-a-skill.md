# Write a forensic skill

A skill is methodology, not executable code or evidence. Read [the analyst guide](../skills.md)
and [the design](skills-design.md). Use original prose under MIT OR Apache-2.0.

Create one directory with `SKILL.md` and optional `.md`, `.toml`, `.json`, `.csv`, `.yaml` or `.yml`
reference/query resources accepted by the current compiler. Start with an existing
[bundled skill](../../skills/linux-triage/SKILL.md). Its TOML frontmatter is enclosed
by `+++` lines:

```toml
format = "irmind-skill-v1"
name = "example-review"
description = "Review a bounded set of synthetic local observations."
version = "0.1.0"
author = "IRMind contributors"
license = "MIT OR Apache-2.0"
target_schema = "irmind-common-event-v1"
tools = ["graph_summary", "text_search", "raw_records", "case_add_finding"]
sources = ["parser-json"]
categories = []
invocable = true
```

Include collection and coverage requirements, an ordered investigation method,
query examples, alternative explanations, ATT&CK references where justified and
what must be checked before proposing a finding. Missing sources or mappings
produce an explicit limitation, never an invented outcome or role. References
support the method; they do not establish that an attack happened.

The package limit is 128 KiB, with at most 16 resources and 32 KiB per resource.
The methodology is at most 32 KiB. Verify the compiler's current resource allowlist
before introducing a new extension. No scripts, executable files, symlinks or
automatic downloads. Declared tools are a restriction, never a permission grant.

Install the local directory with `/skills` in a disposable evaluation home. Review
the package and sign its admission; invoke `/example-review` in a synthetic case.
Add a scripted episode covering ingestion, skill loading, queries, analyst finding
confirmation, verification, seal and independent export verification. Keep expected
answers evaluator-only. Add the obedient-fake-model test with hostile evidence:
the skill must not bypass policy, scope, tool declarations or approvals.

Contributions need DCO, affected tests and both language documentation. Community
catalog publication is separate from inclusion in the binary and remains pending
its production publisher key. Do not duplicate an included skill name.

Validate a local folder without installing it with `cargo run -p irmind --example validate_skill --locked -- <skill-directory>`. This development example uses FileSkillPackageStore and TomlSkillCompiler, not an approximate second validator.
