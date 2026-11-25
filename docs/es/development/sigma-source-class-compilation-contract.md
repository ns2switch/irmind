# Compilación de Sigma por clase de fuente

[English](../../development/sigma-source-class-compilation-contract.md)

**Estado:** aprobado para v0.7.3. El lector de pruebas opcional al final
del documento es una propuesta separada en revisión.

## Qué cambia

En v0.7.2, Sigma ya compila un programa por clase. El plan descarta todos
los programas de una regla si alguna clase aplicable carece de una
correspondencia exacta. La propuesta ejecuta la regla completa donde se
puede interpretar con exactitud y deja constancia firmada de cada clase
omitida. Mantiene los campos, modificadores, límites de evaluación,
herramientas, política y confirmación individual de hallazgos vigentes.

Una clase corresponde a una entrada de la tabla de campos autenticada.
Su ordinal parte de cero y la identifica dentro de la ejecución. La
clase fija las identidades de parser y mapeo, el `logsource`, el canal o
dataset cuando aplica, los campos tipados y los predicados de fila.
Planificar a partir de una clase disponible significa que la fuente
seleccionada tiene un artefacto activo con un pipeline firmado
compatible. Cada fila aún debe pasar sus propios predicados y estar
dentro del intervalo solicitado.

1. Validar la regla completa antes de resolver sus campos. Un error
   global de sintaxis, condición, modificador o límite obedece al
   rechazo global, aunque falte también alguna correspondencia.
2. Para cada clase disponible que coincida con el `logsource`, resolver
   todos los campos. Si falta alguno, omitir ese par por falta de
   correspondencia. Si todos existen pero su tipo no permite el
   predicado, omitirlo por tipo incompatible. Una correspondencia
   ausente tiene prioridad si se dan ambas causas. Una clase fuera del
   `logsource` queda fuera del recuento de omisiones.
3. Evaluar la condición completa en cada clase elegible, sin recortar
   selecciones, sustituir campos ni convertir tipos para forzar la
   compilación. Una fila con un campo de precisión exacta marcado como
   no disponible sigue siendo indeterminada para las reglas que lo
   necesitan, incluso con negación. La ausencia normal de un valor
   mantiene su semántica actual.

Por ejemplo, una regla amplia de creación de procesos que exige
`ParentImage` puede ejecutarse en Sysmon y Defender. FDR ofrece
`ParentBaseFileName`, que tiene otra semántica, y su clase queda
omitida. Si la regla pide solo Sysmon, FDR queda fuera del `logsource`.
Cuando Kubernetes conserva una fila con `sourceIPs` no disponible,
esa fila indeterminada se cuenta por separado de cualquier clase
omitida.

## Custodia y verificación

Se conservan el marcador de caso 6, la cabecera y las secciones de V10,
los cuerpos actuales de `SigmaRunV1`, `SigmaCompiledRulesV1` y
`ReportCoverageV2`, la tabla, el alcance y la admisión del pack. El
evaluador propuesto es `irmind-sigma-evaluator-v3`. El objeto de resultado
sigue en la posición 5 con dominio `irmind-sigma-run-results-v3\0`.
Los recibos y resultados V1 y V2 conservan sus bytes e interpretación.
Un binario anterior a V3 no puede verificar una ejecución nueva aunque
reconozca la cabecera V10.

Después del dominio, el objeto V3 conserva las cuatro listas de V2 en
su orden y codificación. Añade una matriz con contador `u64`, ordinales
`u64` estrictamente crecientes y contador de reglas `u64`, todos en big
endian. Cada fila, en orden por identificador y SHA-256 de regla, emplea
dos bits por clase desde los bits bajos. Una fila ocupa exactamente
`ceil(clases / 4)` bytes y los bits altos sin usar se escriben a cero.

| Código | Significado |
| --- | --- |
| 0 | Fuera del `logsource` o regla rechazada globalmente |
| 1 | Elegible para evaluar la condición completa |
| 2 | Falta una correspondencia exacta |
| 3 | El tipo de una correspondencia exacta es incompatible |

Los ordinales con código 1 deben coincidir exactamente con la lista
compilada de cada regla. La matriz abarca todo el pack admitido y añade
como máximo 1.056.784 bytes dentro de los límites existentes. El nuevo
estado `CoverageLimited = 6` indica que se omitió al menos un par o
que hay reglas sin clases elegibles. Un límite operativo o una
cancelación que interrumpa la ejecución conserva su estado propio y la
matriz, si ya se había completado el plan. Sin huecos de clase, se usa
`ExactFieldsUnavailable` cuando hay filas indeterminadas para alguna
regla elegible, o `Complete` en el resto. Un pack sin clases disponibles
deja la matriz con cero columnas, sin coincidencias y con cobertura
limitada.

El hash del resultado y el compromiso del conjunto de pruebas cubren
la matriz. El verificador local y el del export reconstruyen el plan
desde el checkpoint autenticado, las reglas admitidas y la tabla
firmada. Comprueban el estado y las coincidencias contra la fila exacta
y su clase elegible. Esta comprobación de las coincidencias citadas
se distingue de repetir toda la búsqueda para comprobar su
exhaustividad. Un evaluador desconocido, una combinación incompatible
de versiones o una prueba que exceda los límites se rechazan.

`/sigma`, `/verify` y el informe distinguen las clases omitidas, las
filas indeterminadas y los límites operativos. Los avisos indican que
las clases omitidas no permiten concluir que no hubo actividad y que
los valores inesperados pueden indicar manipulación de la fuente. El
informe resuelve los detalles desde los resultados autenticados y sigue
exigiendo confirmación del analista para cada hallazgo que cita.

## Pruebas y medición

El contrato canónico y la lista completa de comprobaciones están en
la [versión inglesa](../../development/sigma-source-class-compilation-contract.md).
Los [vectores independientes](../../../crates/testkit/fixtures/contracts/sigma_source_class_compilation.json)
incluyen resultados completos y limitados, interrupciones, rechazos
de matrices incoherentes y coincidencias en clases omitidas. La
implementación deberá reproducirlos en Rust, verificar un caso sintético
firmado y un export cruzado, y conservar los bytes con 1 y N
trabajadores y con `serde_json/preserve_order`.

Se repetirá la admisión de la misma release de SigmaHQ fijada por hash,
sin evidencia y sin incluir reglas de terceros. Los resultados
distinguirán, por familia, las reglas que compilan en todas, algunas o
ninguna de las clases, los pares omitidos y las reglas recuperadas
respecto a V2. También se compararán ambos evaluadores en release
sobre el corpus sintético de al menos 2.000 reglas y 1 GiB. Se medirán
tiempo de planificación y escaneo, memoria pico, positivos esperados
y detectados, falsos positivos y huecos de cobertura.

## Lectura de las pruebas para el detalle del informe

Se propone por separado el método opcional
`LargeCaseStore::read_sigma_proof(case, kind, digest, cancel)`, con error
por defecto. Lee del caso indicado la prueba a la que apunta el recibo
autenticado y verifica su hash dentro del límite actual. El export usa
su lector acotado existente. Así el informe puede resolver los mismos
nombres de clase y recuentos en local y en el export. No cambia los
bytes firmados ni introduce dependencias.
