<!-- Translation of docs/development/dependency-maintenance-review.md; source commit: 3a6bfca1 -->
# Retirada de dependencias de fechas sin mantenimiento

La sustitución elimina `chrono` y `humantime` de los cuatro lockfiles: aplicación,
fuzzing, auxiliar EVTX y fuzzing del auxiliar. La política de avisos no cambia:
no hay excepciones nuevas en `deny.toml`. Las operaciones sencillas reutilizan los
tipos UTC ya validados de IRMind; el resto usa primitivas mantenidas de `time`.

## Implementación

- TUI, AWS, Splunk, CrowdStrike y SentinelOne reutilizan los tipos UTC existentes.
  Los filtros EDR comparan instantes exactos, con fracciones y offsets explícitos,
  y rechazan offsets desconocidos y segundos intercalares.
- `irmind-calendar` es una utilidad segura basada en `time =0.3.55`, con
  `std`, `parsing`, `formatting`, `serde` y `large-dates`. Conserva los grupos
  fraccionarios de 3/6/9 dígitos, los límites de fechas y los offsets fijos, sin
  consultar la zona horaria del equipo ni una base de zonas IANA.
- El paquete general `arrow` se sustituye por los componentes ya fijados
  `arrow-array`, `arrow-schema`, `arrow-select` y `arrow-ord` 59.3.2. Al eliminarlo,
  `arrow-cast` deja de ser necesario: no se distribuye un parche de ese crate.
- Se incluyen las fuentes publicadas de `arrow-array` 59.3.2 y `parquet` 59.3.0,
  con sustituciones de calendario. Cada directorio conserva las licencias Apache,
  el hash del archivo publicado, los hashes originales y los del parche revisado.
  CI verifica los 57 ficheros con código unsafe de upstream, revirtiendo
  únicamente cambios exactos documentados: imports, mensajes seguros de límites
  y un espacio de un comentario. Los bloques unsafe se conservan.
- El parche existente de `object_store` 0.13.2 usa la utilidad de calendario y
  Jiff 0.2.39 para las duraciones. Una tabla acotada mantiene los alias de unidades,
  el significado fijo de meses y años y el rechazo de desbordamientos y pérdida
  de precisión. El límite HTTP de metadatos de 8 MiB y el GET en streaming siguen
  igual, con credenciales explícitas y verificación TLS completa. La alternativa
  de credenciales ambientales de Azure CLI, no usada por IRMind, devuelve un error
  claro sin ejecutar procesos ni interpretar fechas locales.
- El auxiliar conserva `evtx` 0.15.1 oficial. El parche de `winstructs` 0.3.2 solo
  retiene su código GUID, errores y licencia originales. No modifica la
  decodificación EVTX, sus timestamps, protocolo ni aislamiento.
- El test de respuestas grabadas de AWS usa un simulador HTTP en memoria que
  comprueba las peticiones firmadas, sin la dependencia diagnóstica del SDK que
  también arrastraba `chrono`. No añade dependencias de producción.

## Por qué no basta con actualizar upstream

Los avisos [RUSTSEC-2026-0543](https://github.com/RustSec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md)
y [RUSTSEC-2026-0542](https://github.com/RustSec/advisory-db/blob/main/crates/humantime/RUSTSEC-2026-0542.md)
indican falta de mantenimiento sin versión corregida. Arrow/Parquet 60.1.0 y
`object_store` 0.14.2 todavía los requieren. Actualizarlos no resuelve la retirada.
Los parches mantienen las versiones físicas actuales y son código local revisado,
no versiones de upstream anunciadas como libres de esas dependencias.

## Verificación

El grafo principal pasa `cargo-deny` con su política intacta. Hay vectores
sintéticos congelados para 756 combinaciones de fecha, fracción y offset, además
de patrones de presentación. Los 21 tests de formatos actuales pasan sin cambiar
los bytes esperados. La matriz nativa completa sigue siendo requisito de cierre.

Los cuatro lockfiles deben seguir sin ambas dependencias. CI comprueba los
hashes de 246 ficheros revisados y la conservación de los ficheros con unsafe.
Se mantienen los golden físicos y canónicos, las firmas, procedencia, rollback,
límites, alcance y exportación. Una diferencia de bytes se investiga; no se
resuelve regenerando el golden firmado. Antes de publicar v0.5.3 se repiten las
mediciones scripted de caché en release y las comprobaciones habituales de
firmas, attestations, SBOM e instalación limpia.


## Portabilidad y diagnósticos de límites

Los ficheros vendorizados conservan sus bytes exactos al hacer checkout, incluidos
los scripts Python originales, y se leen explícitamente como UTF-8. Una prueba
con checkout CRLF y la CI nativa comprueban los mismos hashes. Las pruebas
negativas siguen rechazando cambios de hashes revisados o de código unsafe.

Siete accesores de arrays mantienen sus condiciones de límites y usan un mensaje
constante para no incluir índices, longitudes ni prefijos de tipos en el error.
Los tests ejercitan lecturas válidas y rechazadas en las siete familias. Se
actualizan también las expectativas de los mensajes de los tests originales.
Los cambios seguros exactos quedan registrados por separado para que CI pueda
reconstruir el fichero original completo y rechace cualquier otro cambio. No se
necesitan exclusiones de consultas o rutas ni excepciones de avisos.
