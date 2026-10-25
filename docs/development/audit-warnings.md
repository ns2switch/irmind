# Cargo audit warnings

This page is for maintainers reviewing the three currently permitted `cargo audit` maintenance advisories. Review date: 2026-10-24. Next review: 2027-01-24, or sooner if the Linux keyring backend changes.

`cargo audit` scans optional packages present in `Cargo.lock`. These advisories enter through `secret-service 4.0.0 → zbus 4.4.0`, an optional asynchronous `keyring` backend. IRMind builds the persistent synchronous `dbus-secret-service` backend instead. `cargo tree --target all -e features -i secret-service` finds no active path in the delivered build. The advisories report discontinued maintenance, not a confirmed exploit in IRMind's active path.

| Crate | Advisory | Why it does not affect the active path | Review by |
| --- | --- | --- | --- |
| `zvariant 4.2.0` | [RUSTSEC-2026-0370](https://rustsec.org/advisories/RUSTSEC-2026-0370.html) | Optional inactive `secret-service` backend only. | 2027-01-24 |
| `zbus_names 3.0.0` | [RUSTSEC-2026-0371](https://rustsec.org/advisories/RUSTSEC-2026-0371.html) | Same inactive backend. | 2027-01-24 |
| `zvariant_derive 4.2.0` | [RUSTSEC-2026-0372](https://rustsec.org/advisories/RUSTSEC-2026-0372.html) | Reached through `zvariant` in that backend. | 2027-01-24 |

If any package appears in the active feature tree of a delivered binary, this exception no longer applies. Update or replace the backend before distribution. The separate fuzz workspace is checked by `cargo-deny` as well.
