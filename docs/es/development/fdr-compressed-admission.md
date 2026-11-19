# Admisión de FDR comprimido

Implementado en la ruta de ingesta de FDR. [English](../../development/fdr-compressed-admission.md).

## Admisión y reserva

`DecodedJson16` se aplica solo a `parser-fdr/fdr-source-v1`. VPC Flow Logs usa
`CompactFlow32`. Extender el perfil de JSON decodificado a ALB, S3 access logs,
CloudTrail gzip u otro decodificador requiere una aprobación aparte.

La primera pasada abre el original en lectura, limita a 50 GiB tanto la entrada
física como la decodificada y valida el CRC y el tamaño de cada miembro gzip.
Cuenta con un búfer reutilizable de 16 KiB y estado de descompresión acotado.
No materializa ni escribe los bytes decodificados. Para JSONL sin compresión,
toma el tamaño del fichero sin leerlo entero en una pasada adicional.

El recuento fija el techo normalizado (`bytes decodificados × 16 + 64 MiB`).
Antes de normalizar, se comprueba el espacio libre del caso frente a la reserva
del grupo completo, incluidos el espacio para ordenar y el margen de seguridad.
Si falta espacio, el error indica los bytes necesarios y disponibles. El techo
por sí solo no reserva espacio físico.

Durante la normalización, el lector lee como máximo los bytes admitidos más
uno para detectar expansión. Si supera el techo, rechaza la fuente. La
comprobación del hash del original sigue siendo independiente y precede a la
publicación. Se mantienen el staging privado en el caso, el rollback y las
comprobaciones de orden.

## Verificación

Un test añade un segundo miembro gzip válido al original abierto tras la
pasada previa y exige que el decodificador y la ruta de ingesta en paralelo
se detengan en el techo anterior. La prueba comprueba también la limpieza del spool.
Otro cuenta 64 MiB en dos miembros con el búfer fijo y comprueba que falla al
truncar el último tráiler. La prueba de integración comprueba reconstrucción,
sello y exportación a partir del gzip original, y rechaza una modificación
posterior del fichero al reconstruir.

El benchmark release usa el mismo corpus de 1 GiB decodificado para JSONL y
gzip. Las [mediciones](../../development/benchmark-data/fdr-gzip-v055.json)
incluyen la ingesta completa y el tiempo de la pasada previa por separado.
En esta única comparación, gzip tarda 68,323 s frente a 71,877 s en JSONL.
La pasada adicional de gzip tarda 0,289 s medida por separado. Las dos
ingestas se verifican correctamente.

```sh
cargo test -p irmind --release --test identity_ingest one_gib_release_fdr_gzip_and_jsonl -- --ignored --nocapture
```
