# Local `arrow-array` date patch

Published `arrow-array 59.3.2` source is pinned by the registry checksum and
per-file upstream hashes in [UPSTREAM.json](UPSTREAM.json). Reviewed file hashes
record the local patch separately. The original Apache license and notice remain.

Calendar imports use the safe `irmind-calendar` utility backed by maintained
`time` primitives. Array layout, encoding, compression, filtering and ordering
algorithms are unchanged. Seven safe accessor bounds checks keep their original
conditions and now use a constant diagnostic instead of formatting indices,
lengths or type prefixes. The exact replacements are recorded in `UPSTREAM.json`.
Sources containing upstream unsafe code are identical after reversing only these
safe diagnostic replacements, the calendar import rename and one documented
comment-whitespace normalization; CI checks this invariant.

IRMind uses UTC and explicit fixed offsets, without host-local-time or IANA
timezone features. The unconfigured Arrow timezone feature fails explicitly.
Existing physical/canonical golden tests run without regenerating expected bytes.
