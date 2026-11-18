# Admisión de FDR comprimido

Propuesta de diseño. [English](../../development/fdr-compressed-admission.md).

## Reproducción

El test sintético `fdr_gzip_admission_characterization` se ejecuta con
`cargo test -p irmind --release --test identity_ingest fdr_gzip_admission_characterization -- --ignored --nocapture`.
Repite 150.000 registros ProcessRollup2 con campos nativos y sin relleno.

| Codificación | Bytes físicos | Bytes decodificados | Registros | Resultado |
| --- | ---: | ---: | ---: | --- |
| JSONL | 69.150.000 | 69.150.000 | 150.000 | Ingeridos y verificación firmada correcta |
| gzip | 954.510 | 69.150.000 | 150.000 | Agota la cuota normalizada; no se publica ningún artefacto |

Es una comprobación de admisión con build release, no un benchmark de throughput.
La reserva por defecto es `bytes físicos * 16 + 64 MiB`: 82.381.024 bytes para
este gzip. Limita el flujo normalizado, por lo que una fuente comprimida puede
agotarla aunque su equivalente en texto quepa. No es falta de disco libre. El
original no cambia y se revierte el grupo. CompactFlow32 sigue siendo exclusivo
de VPC Flow Logs.

## Perfil cerrado propuesto

Añadir `NormalizedExpansionProfile::DecodedJson16`, usado inicialmente solo por
FDR: `bytes decodificados * 16 + 64 MiB` mediante el método opcional existente
`SourceDecoder::normalized_source_budget`. No cambia el puerto. Para la fuente
sintética serían 1.173.508.864 bytes, igual que en texto. CompactFlow32 y los demás
decodificadores mantienen su comportamiento.

Antes de normalizar, una pasada de solo lectura y cancelable cuenta los bytes
decodificados, valida todos los miembros gzip y su CRC y rechaza entrada física
o decodificada por encima de 50 GiB. No escribe evidencia decodificada. Se
mantienen el staging privado dentro del caso, reserva previa de espacio y scratch,
cuotas por fila y totales durante ejecución, rollback, comprobación del hash del
original, límites del parser y orden canónico. El perfil no modifica bytes
firmados ni concede capacidades remotas.

Pruebas: igualdad de cuota entre texto/gzip/miembros concatenados, CRC o truncado
inválidos, cancelación, frontera de 50 GiB, ausencia de escrituras durante la
pasada y éxito del mismo gzip con reconstrucción/sello/export verificados. Sin
espacio se falla antes de normalizar. El desbordamiento aritmético sigue siendo
un error.

## Alternativa

Mantener la cuota actual y documentar la descompresión externa explícita antes de
ingerir. No añade un perfil, pero deja archivos FDR gzip válidos sin la ruta
directa solicitada.
