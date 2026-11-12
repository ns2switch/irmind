# Forensic skills

This page is for analysts who want a repeatable investigation method without granting the agent more permissions. A skill is a small, versioned folder of methodology and reference data. It contains no executable code.

## Use an included method

Open a case, configure a model in `/settings model`, and type `/` to see the active methods. Version 0.4 includes:

| Command | Method |
| --- | --- |
| `/windows-triage` | Review collected Windows logons, execution, persistence, lateral movement and possible exfiltration. |
| `/linux-triage` | Review Linux authentication, privilege changes, execution and persistence. |
| `/aws-credential-compromise` | Review CloudTrail evidence of credential use, privilege changes and affected resources. |

You can append a question, for example `/linux-triage Review the failed logins in this case.` The agent can also select a method from its description. No model or remote connector is enabled by a skill. You can inspect all methods without configuring a model.

The model initially receives only active names and descriptions. When it requests `skill_read`, IRMind checks policy, pins the approved package in the case, screens its requested resource and signs a load receipt with the Agent key before exposing the text. The conversation shows a collapsible methodology card. Use Ctrl+O or `/expand` for its details.

## Manage local packages

Use `/skills` from the home screen or a case. Choose a method with the arrows. Tab selects an action; Enter opens it. Typing an option number followed by Enter also works.

1. **Inspect** shows the version, package hash, declared tools and resources.
2. **Install/update** opens a folder field. Select a local folder with `SKILL.md`, inspect the exact preview and sign the installation or replacement.
3. **Enable/disable** signs the activation change. Disabling prevents future loads; it does not remove earlier case receipts.
4. **Restore approved file** explicitly restores an installed package from its signed installation record after local files were removed or changed.

Esc returns without applying a preview. Installation, updates and activation changes use the Analyst key and the signed global operation chain. Modified, missing or unsupported installed packages stay unavailable; IRMind never silently substitutes an included method. The demo permits inspection but does not change your real skill installations.

Download community packages explicitly and verify their published hashes before inspecting and signing them. IRMind does not fetch packages automatically. A signature records your approval of exact bytes; it does not make their claims correct or their instructions trusted.

## Limits and security

A package contains `SKILL.md` plus at most 16 resources, with a total limit of 128 KiB and 32 KiB per resource. At most 32 methods can be active. One model turn can load at most four distinct snapshots and eight resources, with at most 64 KiB of screened methodology and any smaller context/token limit. A limit produces a signed result; content is not silently truncated.

Skill text is always untrusted. It never enters a system message, never becomes evidence and cannot be cited as an evidence hash. Declared tools restrict method-assisted calls; normal policy, case scope, organization ceilings, taint checks, approvals and budgets still apply. A skill cannot confirm its own findings. Missing semantic mappings mean incomplete coverage, not permission to invent classification.

The signed case preserves the original package and the screened ranges actually loaded. Export V7 carries the exact referenced installation proofs for independent verification without your keystore. It authenticates recorded methodology use; it does not claim to reproduce a model response or establish the quality of a forensic conclusion.

Pre-1.0 minor versions may change skill and export formats without migration. Keep the version that created a case. See the [security model](security-model.md), [installation configuration](configuration.md) and [development design](development/skills-design.md).
