# Presupuesto de normalización de fuentes compactas

[English](../../development/compact-source-normalization-budget.md)

## Medición y alcance

La propuesta modifica la admisión de recursos del nuevo decodificador VPC, sin
cambiar formatos firmados, mapeos, orden estable ni verificación de fuentes.
La implementación vigente sigue activa mientras no se implemente la propuesta.

La ingesta release de 1 GiB de VPC falla con `StorageNormalizedStagingSpace`.
La entrada tiene cabecera nativa y repite un registro sintético de 131 bytes,
sin relleno para disimular la expansión. No es un resultado de throughput correcto.
El diagnóstico usa `RecordRow::from_mapping` y el serializador `EncodedSize`
de producción:

| Fuente sintética | Bytes de entrada | Bytes normalizados | Expansión |
| --- | ---: | ---: | ---: |
| VPC personalizado, una fila sin contar la cabecera | 131 | 2.898 | 22,122× |
| VPC estándar v2, una fila | 107 | 2.445 | 22,850× |
| Fixture Azure VNet | 866 | 9.240 | 10,670× |
| Fixture Azure NSG | 583 | 8.720 | 14,957× |
| Fixture GCP VPC | 2.434 | 11.071 | 4,548× |

Son medidas de representación, no benchmarks ni cotas del peor caso. La
representación incluye los campos originales consultables, contexto validado,
roles y ámbitos, procedencia, orden y ruta de partición. No se eliminan para
reducir la cifra. Los números de registro y offsets pueden aumentar su tamaño.

```sh
cargo test --release -p irmind-infra compact_flow_normalized_expansion -- --ignored --nocapture
cargo test --release -p irmind --test identity_ingest one_gib_release_throughput -- --ignored --nocapture
```

## Admisión actual

La cuota por fuente es `bytes_físicos * 16 + 64 MiB`. Antes de escribir, el grupo
comprueba espacio para la suma de cuotas más 64 MiB de margen. Cada fila
normalizada tiene un máximo de 64 MiB. Tanto la ruta directa como el spool de
ordenación consumen la cuota, aunque la primera no escriba registros normalizados
a disco. Para gzip también se usa el tamaño físico comprimido. Un fallo revierte
el grupo o la fuente; no se publica un manifiesto de ingesta parcial.

## Método opcional propuesto en SourceDecoder

```rust
fn normalized_source_budget(
    &self,
    file: &mut std::fs::File,
    cancel: &CancellationToken,
) -> Result<Option<NormalizedSourceBudget>, AppError> {
    Ok(None)
}
```

`None` mantiene exactamente la reserva vigente de 16×. El tipo nuevo tiene campos
privados y constructores validados: tamaño descomprimido de hasta 50 GiB y un
perfil cerrado, inicialmente solo `CompactFlow32`. Calcula la cuota como
`bytes_decodificados * 32 + 64 MiB`, con aritmética comprobada. No existe un valor
ilimitado ni un multiplicador propuesto por el modelo. Solo el nuevo decodificador
VPC selecciona este perfil; los demás mantienen su admisión.

En texto plano se usa la longitud del mismo fichero abierto. Para gzip se cuentan
los bytes descomprimidos en una pasada previa acotada, reutilizando el código gzip
existente. Comprueba todos los miembros y sus CRC, limita entrada y salida a los
50 GiB vigentes y comprueba cancelación entre lecturas acotadas. No escribe evidencia
ni registros normalizados y no confía en ISIZE, nombres o ratios declarados.
Esta lectura adicional se mide por separado como coste de gzip.

El coordinador restaura la posición del fichero antes y después del método,
valida el resultado y comprueba el espacio del grupo antes del staging. El hash
inicial y la comprobación final de que la fuente no cambió siguen autenticando
la ingesta real. Un cambio de fuente o una estimación insuficiente causa error y
rollback; la pasada previa no autoriza bytes cambiados. Solo se lee el fichero.
No hacen falta otro método de LargeCaseStore ni dependencias externas nuevas.

## Efecto y controles

Es una ampliación explícita de la cuota del nuevo VPC: de 16× la entrada física
a 32× la entrada descomprimida. También aumenta la reserva de disco: 1 GiB
requiere unos 32 GiB más márgenes. Sin espacio suficiente se falla antes de
normalizar. Gzip deja de reservar según su menor tamaño comprimido. Una fuente
que exceda la nueva cuota se rechaza completa; no se garantiza que toda entrada
sintácticamente válida quepa. La cuota es igual en la ruta directa y la ordenada.

Se mantienen el máximo de 4 MiB por registro decodificado, campos/nodos/profundidad,
diez millones de registros, 64 MiB por fila normalizada, colas, escritores,
límites de fuente, taint, ContentGuard, procedencia, cancelación, rollback y
verificación de hashes y firmas. No se escribe evidencia en el temporal del
sistema. Los golden físicos y canónicos actuales no cambian: el presupuesto
modifica la admisión, no los registros emitidos.

## Pruebas previas a integrar

- Método por defecto: mismas reservas y mismos rechazos que antes.
- Fronteras y overflow de constructores y aritmética.
- Texto y gzip equivalentes: misma cuota; miembros múltiples, CRC inválido y
  exceso de descompresión con errores claros.
- Cancelación previa sin spools, artefactos ni manifiestos publicados.
- Falta de espacio sin escribir; exceso real con rollback completo en ambas rutas,
  también al descargar desde object storage.
- Mutación tras preflight sin publicación de una fuente verificada.
- Bytes y compromisos idénticos con 1/2/4/N trabajadores y golden vigentes intactos.
- Repetir 1 GiB release sin relleno y gzip por separado; medir throughput correcto,
  memoria y pico de staging. Repetir 1/64/1.024/1.025 hosts y consultar el último
  host que quede en desbordamiento.
