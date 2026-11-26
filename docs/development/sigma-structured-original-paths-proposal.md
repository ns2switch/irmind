# Proposed Sigma projections for structured original fields

The V3 tables resolve explicit object keys from an authenticated artifact row
with the existing bounded path reader. These bindings already cover
`properties.*` and `protoPayload.*` scalar leaves. Two kinds of source fields
would need new interpretation rules before they can be enrolled.

## Arrays of objects

A future table should name a fixed array object path and a reviewed item shape.
For example, an authorization entry can expose a text permission and a
boolean decision. A selection that tests both fields must satisfy both
predicates on the same array item. Two separate items with one condition each
are a negative control. Empty, absent, null, incompatible and oversized arrays
need distinct outcomes before a negative result can be authenticated.

- Start with GCP `protoPayload.authorizationInfo`. Bind only named fields with
  types documented for that item. Entra `targetResources` and its nested
  `modifiedProperties` should require a separate example and review of binding
  scope before combining terms across two arrays.
- Permit fixed keys and a fixed array anchor. Exclude arbitrary queries,
  recursive descent, path search, automatic stringification and parsing a
  serialized JSON string as an object.
- Charge each visited item and each predicate to the existing work budget.
  Set explicit limits for items, original bytes and nesting. Reuse cancellation
  and the existing exact-field coverage mechanism once its scope and receipt
  representation are approved.
- Include mixed-entry, null, empty and wrong-type fixtures. Verify any
  reported match using the authenticated original row and the signed table,
  both locally and in V10 export.

## Scalar and argument representations

- Sign-in `ResultType` is a provider string in Log Analytics. Some rules use
  integer literals. A named Azure-only decimal projection could be reviewed
  separately, with exact type, range and missing-value behavior. The current
  bindings preserve the source type.
- Apple Endpoint Security exports an argument array. Rules asking for a
  scalar `CommandLine` should stay uncovered until the semantics of spaces,
  quoting, empty arguments and modifiers are agreed. A parent PID or audit
  token cannot supply `ParentImage`.

Any new syntax or conversion changes the interpreted signed field table.
A follow-up contract would specify the codes, bounds, evaluator version,
receipt behavior and negative vectors before implementation. The current
expansion uses the existing scalar and text-list bindings.
