# Draft v0.8 implementation vectors

Regenerate with Python 3 and OpenSSL 3.

```sh
python3 -B docs/development/v08-implementation-vectors/generate.py
```

The synthetic Ed25519 signer is the independent fixture generator from the
approved case-7 contract. OpenSSL signs and verifies the synthetic case,
seal and global operations. The new generator changes the case marker and
archive header and adds the extension proof count. [Frozen vectors](wire.json)

The signature fixtures prove byte encoding and domain separation. The
negative nonempty archives contain authentic but unreferenced operations.
The child binding covers the codec with synthetic digest fields. It must
fail if supplied without its authenticated plan, hold, checkpoint and
query projection. A native release test must resolve these references
against actual case state. The illustrative approval presentation digest
is not authorization.

The approved V1 framing and rejection vectors still apply. The
`engine_api.approval_presentation_binding` vector records the superseded
separate-TUI proposal. The forthcoming
[graphical approval protocol](../v08-graphical-approvals-contract.md)
uses its own unsigned V2 presentation domains.
