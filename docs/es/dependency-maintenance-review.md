Traducción de docs/development/dependency-maintenance-review.md en el commit a23a25e0d1ccd359f347cc057f8d8a143ddff2ff; si hay diferencias, prevalece la versión en inglés.

# Retirada de dependencias temporales sin mantenimiento

La sustitución retira `chrono` y `humantime` de los cuatro grafos fijados de
compilación, pruebas y fuzzing. La política de avisos no cambia y no hay ninguna
excepción. Se usan los tipos UTC validados de IRMind cuando bastan y una biblioteca
mantenida donde hacen falta calendarios o formatos generales.

## Primera parte implementada

- La TUI, la validación temporal del caso nuevo, AWS, Splunk, CrowdStrike y
  SentinelOne reutilizan los tipos UTC del dominio. Se retiran cinco dependencias
  directas de `chrono` sin añadir un crate sustituto. Los filtros EDR comparan
  instantes exactos con nanosegundos y offsets explícitos; rechazan offsets
  desconocidos y segundos intercalares.
- El código oficial de `evtx 0.15.1` solo importa `winstructs::guid::Guid`.
  Un parche de solo GUID conserva sin cambios el código de GUID, errores y
  licencia; omite los módulos de timestamp, NTFS y seguridad que no se usan.
  El SHA-256 del paquete verificado y sus ficheros están en
  [el manifiesto de origen](../../helpers/evtx/vendor/winstructs/UPSTREAM.json).
  No cambian el decodificador EVTX, sus instantes, protocolo ni aislamiento.
- El lockfile de fuzzing del auxiliar ya no contiene ninguna de las dos
  dependencias. Su grafo de desarrollo aún llega a `chrono` mediante Parquet y
  Arrow; esa ruta se retira con el trabajo restante.

Han pasado 159 tests de TUI y conectores, dos pruebas adicionales de límites
exactos, 14 pruebas nativas Linux de protocolo, aislamiento y custodia EVTX y el
contrato de lectura de GUID truncados. Clippy de TUI y conectores pasa con avisos
como errores. No cambian los golden de formatos firmados ni de la TUI. Todavía
no es la retirada completa ni una matriz de release en verde.

## Por qué no basta actualizar versiones upstream

| Dependencia | Aviso | Rutas de producción |
| --- | --- | --- |
| `chrono 0.4.45` | [RUSTSEC-2026-0543](https://github.com/RustSec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md) | Parsers, Arrow/Parquet, almacenamiento y los timestamps no usados de winstructs en el auxiliar original. |
| `humantime 2.4.0` | [RUSTSEC-2026-0542](https://github.com/RustSec/advisory-db/blob/main/crates/humantime/RUSTSEC-2026-0542.md) | El almacenamiento object_store vendorizado. |

Ambos registros son `informational = "unmaintained"`, sin versión corregida.
Arrow/Parquet 60.1.0 aún requieren `chrono`; object_store 0.14.2 requiere ambos.
Actualizar esas versiones no cumple el objetivo. Se pueden mantener las versiones
físicas actuales mientras se sustituye explícitamente su implementación temporal.

## Propuesta concreta restante

1. Usar **`time = 0.3.55`** directamente en los consumidores generales restantes.
   Ya está en el lockfile principal mediante AWS y admite strftime. Features
   propuestas: `std`, `parsing`, `formatting`, `serde` y `large-dates`, sin offset
   local del equipo ni base de zonas. Mandan los límites de instantes de IRMind.
2. Sustituir el crate paraguas de Arrow por los ya fijados `arrow-array`,
   `arrow-schema`, `arrow-select` y `arrow-ord` **59.3.2**. Conservar arrays,
   lotes, filtros, orden y kernels take. Se retiran kernels ajenos de aritmética
   y cadenas; ninguna herramienta del producto desaparece.
3. Vendorizar los paquetes publicados **arrow-array 59.3.2**, **arrow-cast 59.3.2**
   y **parquet 59.3.0** y sustituir su implementación temporal por `time`. Su
   código Rust actual ocupa **218 ficheros / 6.796.051 bytes**, sin manifiestos
   ni licencias. Sus checksums están en
   [date-dependency-sources.json](../development/date-dependency-sources.json).
   Conservar avisos Apache, registrar los ficheros modificados, usar código nuevo
   seguro y mantener intactos los bloques unsafe upstream existentes. Es un
   parche local mantenido, no una release oficial de Arrow sin chrono.
4. Ampliar el parche actual de **object_store 0.13.2** para usar `time` y retirar
   `humantime`. Conservar el límite HTTP de 8 MiB antes de parsear, streaming,
   credenciales explícitas, TLS completo y firma canónica de peticiones.
5. Aplicar las mismas fuentes a los cuatro workspaces. El parche GUID de
   **winstructs 0.3.2** queda separado del decodificador oficial EVTX. No se
   propone un fork de EVTX ni cambiar el aislamiento.

Las nuevas dependencias directas y fuentes locales son otra elección de cadena
de suministro. La parte de `time` y Arrow aún no está implementada. No concede
permisos, no introduce credenciales ni cambia puertos de dominio o aplicación.

## Condiciones para terminar

- Ningún grafo o lockfile conserva ambos paquetes; cargo-deny pasa con la
  política actual y sin supresión de avisos.
- Fixtures diferenciales de offsets, bisiestos, fracciones hasta nanosegundos,
  pre-epoch, límites de fecha, zonas inválidas y formatos declarados. Conservar
  los instantes admitidos; rechazar límites explícitamente, sin recortar
  precisión ni sustituir silenciosamente la zona por UTC.
- Mantener bytes de frames, hashes Parquet, compromisos, procedencia, hashes,
  rollback, alcance y vectores de exportación. Investigar diferencias, sin
  regenerar un golden firmado para aceptarlas.
- Repetir Linux, macOS, Windows, preserve_order, equivalencia de trabajadores y
  aislamiento EVTX; comprobar hashes de fuentes retenidas.
- Integrar después la caché, repetir sus tres mediciones scripted en release y
  ejecutar la distribución firmada e instaladores limpios antes de v0.5.3.
