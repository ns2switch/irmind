Traducción de docs/development/dependency-maintenance-review.md en el commit 5d4385182a483647579242882d78f7f5a16a7fc0; si hay diferencias, prevalece la versión en inglés.

# Avisos de mantenimiento de dependencias temporales

El grafo de producción fijado contiene dos dependencias clasificadas como no
mantenidas por RustSec. La política actual rechaza ambos avisos. Este documento
no modifica la política ni aplica una excepción.

| Dependencia | Aviso | Rutas de producción |
| --- | --- | --- |
| `chrono 0.4.45` | [RUSTSEC-2026-0543](https://github.com/RustSec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md) | Fechas de IRMind, Arrow 59, Parquet 59 y almacenamiento. |
| `humantime 2.4.0` | [RUSTSEC-2026-0542](https://github.com/RustSec/advisory-db/blob/main/crates/humantime/RUSTSEC-2026-0542.md) | `object_store 0.13.2`, mediante su implementación vendorizada y acotada. |

Ambos registros tienen `informational = "unmaintained"` y ninguna versión
corregida. Describen mantenimiento; no documentan un exploit concreto en IRMind.
Véase el [anuncio del mantenedor](https://github.com/chronotope/chrono/issues/1768).
La clasificación no permite aceptar indiscriminadamente hallazgos futuros.

## Opción A: excepciones de mantenimiento acotadas

Conservar las versiones fijadas y evaluar las dos excepciones explícitas de
[la propuesta en inglés](../development/dependency-maintenance-review.md#option-a-narrowly-scoped-maintenance-exceptions),
sin modificar globalmente la política de avisos. Cada motivo identifica la
ruta de producción que impide retirar la dependencia.

Esto reduce explícitamente el control de mantenimiento para esos dos IDs; no
corrige código de producción. Se conservan los demás avisos, restricciones de
registros, licencias y comprobaciones. Una vulnerabilidad posterior, incluso en
esos crates, no queda excluida. Validación temporal, límites, bytes canónicos,
custodia y aislamiento no cambian. Las excepciones se retiran cuando desaparece
la dependencia; no constituyen aceptación general de crates sin mantenimiento.

Antes de integrar, comprobar la política exacta con `cargo deny check` y repetir
la matriz nativa y los vectores de formato actuales. Esta propuesta no aplica
ninguna excepción para obtener una comprobación verde.

## Opción B: retirar primero las dependencias afectadas

Sustituir solo los usos propios de `chrono` no resuelve el bloqueo: también lo
usan Arrow, Parquet y almacenamiento. Retirar `humantime` exige un cambio upstream
o una modificación revisada del almacenamiento vendorizado. Los avisos no
ofrecen una actualización de versión que elimine la clasificación.

El grafo principal ya contiene `time 0.3.55` mediante AWS, pero usarlo directamente
es otra decisión sobre dependencias y semántica temporal. La migración conserva
UTC validado, precisión, orden estable y vectores canónicos. Debe abarcar también
las dependencias transitivas, sin excluir sus avisos silenciosamente. Un cambio
upstream o sustituto mantenido requiere revisar licencia, dependencias,
aislamiento y distribución. Mientras tanto, la política actual bloquea publicar.

## Límite de la validación actual

La etapa completa de tests del workspace Linux del candidato v0.5.3 pasó,
incluidos los snapshots con la versión actualizada. Después falló la comprobación
de dependencias por los dos IDs indicados. Esto no equivale a una matriz nativa
de release en verde ni justifica crear un tag.
