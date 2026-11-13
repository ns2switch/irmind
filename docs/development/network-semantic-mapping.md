# Network semantic mappings

`mapping-network` interprets the original bounded source records from the Zeek
and Suricata modules. The decoders, original time precision, framing and offsets
are unchanged. Separate native mapping identities bind all included finite TOML
classification tables, the scalar validator and the table interpreter through
the native build manifest. Verification reproduces that exact identified code;
no downloaded code runs during verification.

## Division of work

Bundled TOML supplies closed categories, types, source-alert kind and supported
explicit outcomes. JSON and TSV have separate table paths. The native layer is
necessary for preserved TSV strings, field/type conversion, dotted source keys,
bounded protocol-specific nested fields and original UID/flow relations. TSV
HTTP/DNS numeric status needs bounded conversion before applying the same status
intervals; it never forges a normalized SourceRecord to feed another mapper.

The table interpreter exposes a pure header evaluation helper so the native
validator does not serialize the original fields twice. Ordinary table mappings
still use the same selector, ambiguity rejection, action validation, field
constructors and output validation. This changes no abstract port or format.

## Interpretation

- conn/flow: network connection; `SF` is success and `REJ` failure for Zeek.
  Other or missing connection states remain unknown.
- DNS: network protocol, with explicit response-code outcome. Questions are
  domains, endpoints remain source/destination IP occurrences.
- HTTP: network/web protocol; 200–399 is success and 400–599 failure. Missing
  status is unknown. Host is the HTTP domain; it never supplies a sensor host.
- TLS: network protocol. Explicit Zeek establishment is success; false or
  absent establishment does not establish failure. EVE TLS remains unknown.
- files/fileinfo: file telemetry. x509 is network/TLS certificate telemetry;
  unsupported certificate attributes remain original rather than fabricated
  file or process entities.
- notice/weird/alert/anomaly: source alerts, not confirmed case findings.
  Alert action and severity never supply the attack outcome.

Explicit TSV dataset or JSON `_path` takes precedence over unrelated fields.
Unknown datasets stay unclassified. Source and destination can be the same
entity with separate roles. File/rule/flow observations without an authoritative
namespace remain source-record scoped. Existing UID/flow aliases and relations
remain queryable through the explicitly declared source projection.

The common schema has one question slot. For EVE DNS v3 the first question is
projected, while further questions stay original and produce a coverage
warning. Invalid optional values do not create typed identities; their source
text remains available with an unsupported-value diagnostic. No process lifetime
is inferred from extra PID fields.

## Tests

Shared mapping contracts check taint, cancellation, immutable source commitments,
repeated execution and parallel purity. Protocol fixtures cover success, failure,
missing status, identical endpoints in distinct roles, dataset precedence,
precise time and DNS v3 coverage. The updated network skill runs typed network,
connection, unknown-outcome and destination-role queries through real ingestion,
analyst confirmation, reconstruction, sealing and export. A hostile-evidence
scenario continues to enforce its local-only tools and case scope.

The current network logical-projection golden vectors change intentionally for
these new mapping identities and typed classifications. Source decoders and
physical/schema/export golden formats do not change.

## Primary references

- [Zeek connection records](https://docs.zeek.org/en/current/reference/logs/conn.html).
- [Zeek DNS records](https://docs.zeek.org/en/current/reference/logs/dns.html).
- [Zeek TLS records](https://docs.zeek.org/en/current/reference/logs/ssl.html).
- [Suricata EVE schema](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html).
