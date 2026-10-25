# Avisos permitidos de `cargo audit`

Revisión: 2026-10-24. Próxima revisión: 2027-01-24, o antes si se activa otro backend del llavero.

`cargo audit` inspecciona también dependencias opcionales del `Cargo.lock`. Estos tres avisos proceden de `secret-service 4.0.0 → zbus 4.4.0`, el backend asíncrono opcional de `keyring 3.6.3`. IRMind compila el backend síncrono persistente `dbus-secret-service`; `cargo tree --target all -e features -i secret-service` no encuentra una ruta activada. Se revisará esta excepción si cambia la selección de features o el backend Linux. Ninguno de los tres avisos describe por sí mismo una vulnerabilidad explotable: indican mantenimiento discontinuado.

| Crate | Advisory | Motivo por el que no afecta a la ruta compilada | Revisión |
| --- | --- | --- | --- |
| `zvariant 4.2.0` | [RUSTSEC-2026-0370](https://rustsec.org/advisories/RUSTSEC-2026-0370.html) | Solo llega por el backend opcional `secret-service`; no está activado. | 2027-01-24 |
| `zbus_names 3.0.0` | [RUSTSEC-2026-0371](https://rustsec.org/advisories/RUSTSEC-2026-0371.html) | Solo llega por el mismo backend opcional. | 2027-01-24 |
| `zvariant_derive 4.2.0` | [RUSTSEC-2026-0372](https://rustsec.org/advisories/RUSTSEC-2026-0372.html) | Solo llega por `zvariant` en ese backend opcional. | 2027-01-24 |

Si una de estas dependencias aparece en `cargo tree --target all -e features` de un binario entregado, esta excepción deja de aplicarse y se debe actualizar o sustituir el backend antes de distribuirlo.
