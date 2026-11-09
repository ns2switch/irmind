# Optional source values in declarative mappings

For mapping maintainers, this design handles documented absent-value markers without changing source records or bypassing typed validation. It extends table interpreter V2 only. It adds no I/O, expression language, port, dependency or custody-envelope field.

## Problem

Windows event fields can contain `-`, and PAM records often contain an empty `logname`. These are valid original strings, not valid IP addresses or named user identities. The current interpreter correctly rejects their typed conversion; its shared boundary then returns an unclassified event. A missing optional identity should not discard an independently documented event classification.

Do not rewrite these strings to null in a parser. Keep every original field and type in `SourceRecordV1`. Do not suppress arbitrary conversion errors.

## Closed primitive

The current interpreter allows an optional `omit_text` list on a field definition:

```toml
interpreter = "irmind-mapping-tables-v2"

[[fields]]
source = ["EventData", "IpAddress"]
target = "source.ip"
conversion = "ip"
omit_text = ["", "-"]
observation = { kind = "ip", role = "source", scope = { kind = "global" } }
```

This is an illustrative field fragment; a complete definition still needs its existing identity, source selector and rules.

- At most eight unique literal strings per field, each at most 256 UTF-8 bytes; reject controls in nonempty literals and duplicates.
- Match exact UTF-8 bytes, case-sensitively, before conversion. No trimming, Unicode folding, glob, regular expression, coercion or negation.
- When an original text value exactly matches a listed literal, omit that whole projected field: neither its common-context value nor its entity observation is emitted. Keep the source and all other projected fields unchanged.
- Missing and null fields retain the current skip behavior. Non-text values never match this primitive.
- Every other value still passes the normal checked conversion and constructors. An invalid IP such as `not-an-ip`, an invalid port or an invalid hash still produces the existing explicit unclassified result; there is no general error suppression.
- Lists are specific to documented source fields. For example, `0` is not a universal absent PID and must not be omitted by default.

The list is signed data in the mapping definition and changes its canonical digest. It cannot affect mapper selection, selector-overlap rejection, permissions, scope, approval or taint. A source-supplied value cannot name a mapping to activate.

## Current format

An absent or empty list is omitted from the canonical definition. Existing current-interpreter definitions without the property retain their bytes and behavior. A nonempty list changes the signed definition digest. The implementation stays in `irmind-mapping-tables-v2`; no additional interpreter version is introduced.

Pre-1.0 minor versions do not promise historical interpreters or definition migration. Removing retired interpreter V1 is a separate format-cleanup change; it is not extended by this primitive. Custody envelope, source manifest, seal and export encodings are unchanged by this implementation.

## Required tests

- Current canonical/golden bytes and installed-definition replay stay unchanged.
- Missing, null, empty text, a declared sentinel and a valid IP remain distinct inputs; only the explicitly listed text values are skipped.
- An unlisted invalid IP, invalid port/hash, unknown conversion or unknown interpreter still fails through the existing boundary.
- Verify case sensitivity, Unicode byte identity, list/count/length/control bounds, duplicate rejection and V1 refusal.
- Same-value actor/target and source/destination observations retain their roles when one unrelated optional field is omitted.
- Contract fixtures cover PAM with empty `logname`, EVTX with `IpAddress = "-"`, and a normal populated record. Original canonical source bytes and provenance remain unchanged.

Status: approved and implemented in the current interpreter.
