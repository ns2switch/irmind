Traducción de CONTRIBUTING.md en el commit d85c1aa07cfffbfbdf30ac9f1e88b71e5e807efb; si hay diferencias, prevalece la versión en inglés.

# Contribuir a IRMind

Esta guía es para quienes preparan una incidencia o una solicitud de cambios. IRMind está en desarrollo: usa solo datos sintéticos en incidencias, pruebas, ejemplos y revisiones. Nunca adjuntes evidencias reales, credenciales ni datos personales. Informa de vulnerabilidades por el proceso privado de [SECURITY.md](SECURITY.md).

## Licencia y DCO

Las contribuciones enviadas para su inclusión se ofrecen bajo **MIT OR Apache-2.0**, sin condiciones adicionales, como indica el [README](README.es.md).

Cada commit de una PR debe incluir un tráiler `Signed-off-by` con el nombre y correo de su autor. Este tráiler certifica el [Developer Certificate of Origin 1.1](https://developercertificate.org/). La CI comprueba que el correo coincide con el autor del commit.

```text
Signed-off-by: Tu Nombre <tu@example.com>
```

Usa `git commit -s` al crear un commit y `git commit --amend -s` para corregir el último commit local. Firma todos los commits de una PR. No firmes en nombre de otra persona.

## Antes de abrir una PR

- Respeta la [arquitectura](docs/development/architecture.md) y documenta cualquier comportamiento público nuevo.
- Añade pruebas útiles para cambios de política, custodia, parsing o conectores. Usa datos sintéticos.
- Ejecuta `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo nextest run --workspace --all-features --locked` y `cargo deny check`.
- Describe los efectos sobre seguridad, las pruebas ejecutadas y los límites conocidos en la plantilla de PR.

La documentación inglesa es la fuente de verdad. Si cambias contenido para usuarios, actualiza su traducción española y cita al comienzo el commit de la fuente inglesa.

## Cambios que aceptamos

Aceptamos parsers, conectores de solo lectura, mejoras de accesibilidad y terminal, mejores fixtures sintéticos, documentación y mejoras de rendimiento que conserven la custodia y la verificación. Empieza por la [guía de módulos](docs/development/adding-a-module.md) para un parser o conector. Respeta el [Código de conducta](CODE_OF_CONDUCT.es.md).

No aceptamos cambios que debiliten la política, la cadena de custodia firmada, la verificación TLS o del nombre de host, el aislamiento de secretos ni el guard obligatorio. No envíes registros de incidentes reales, datos personales, claves privadas ni respuestas de servicios en producción. Informa de problemas de seguridad por el canal privado de [SECURITY.md](SECURITY.md), nunca en una incidencia pública.
