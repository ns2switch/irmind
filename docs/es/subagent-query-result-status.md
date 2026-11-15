# Completitud tipada de las consultas delegadas de evidencia

Ampliación aditiva aprobada del
[contrato de consultas de subagentes](subagents-format-contract.md).
[English](../development/subagent-query-result-status.md).

## Límite actual

`TaskEvidenceQueries::execute` devuelve `TaskEvidenceResult`, con las variantes
`Text(String)`, `Timeline(Vec<TimelineEvent>)` y
`Original(Box<Tainted<SourceRecordV1>>)`. El código está en
[la implementación de subagentes](https://github.com/ns2switch/irmind/blob/94e96d0921732d6d0bd2c9bbd2bac278e83dcefe/crates/app/src/subagents/queries.rs).

Las consultas conservan sus límites de resultados, muestreo, expansión y tiempo.
Algunas APIs del almacén convierten el estado de completitud en texto antes de
devolverlo. Ese límite no permite distinguir de forma fiable una consulta
completa de un resultado parcial. Interpretar frases del texto mostrado también
confundiría contenido de la fuente con estado del motor.

## Resultado propuesto

Conservar la firma del trait y sus tres variantes. Añadir:

```rust
pub enum TaskQueryPartialReason {
    Sampling,
    Expansion,
    Deadline,
    ResultLimit,
    ExcerptLimit,
    Coverage,
}

// Variantes adicionales de TaskEvidenceResult:
PartialText {
    text: String,
    reason: TaskQueryPartialReason,
},
PartialTimeline {
    events: Vec<TimelineEvent>,
    reason: TaskQueryPartialReason,
},
```

No hay envoltura recursiva, estado de texto libre, método nuevo, dependencia ni
credencial nueva. Los adaptadores existentes pueden seguir devolviendo sus
variantes actuales. Si un adaptador sabe que su resultado es parcial, debe usar
una variante parcial. Los demás fallos siguen siendo errores; una vista de
fuentes no soportada nunca da paso a una consulta sin filtro.

## Propagación desde el almacén

Añadir resultados tipados privados bajo el adaptador nativo. Conservan el estado
que ya conocen el escaneo Parquet, el muestreo y la expansión del camino. Los
puertos de grafo actuales mantienen firmas y salida; sus envolturas renderizan
el mismo resultado interno. La consulta delegada consume directamente ese
resultado tipado, sin ejecutar la consulta dos veces.

Nunca se obtiene el estado buscando palabras, nombres de campos JSON, extractos
de evidencia o respuestas del modelo. Un registro que contenga `partial`,
`truncated` o una frase parecida a un mensaje del motor sigue siendo datos.

Se conserva la distinción actual de cada consulta entre un límite solicitado y
una ejecución incompleta. Solicitar un resultado acotado no basta para marcarlo
como parcial; tampoco puede borrarse una condición existente de muestreo,
truncamiento, cobertura o plazo. El recorte de extractos de registros originales
o indexados también se propaga explícitamente, manteniendo sus límites.

## Ramas, resultado del principal y exportación

El despachador aplica el guard y marca el campo existente
`BranchToolResult.partial` según el estado tipado o su propio recorte de salida.
La razón cerrada produce un aviso fijo de cobertura que también pasa por el
guard. Una respuesta posterior del modelo no borra ese estado: el resultado
terminal sigue siendo parcial si hubo resultados incompletos.

No se añade ningún campo firmado, evento, código canónico, sobre, frame o
sección de exportación. Los formatos actuales de checkpoint, resultado terminal
y export V8, y sus bytes golden, permanecen intactos. Los resultados completos
habituales conservan sus bytes; los parciales usan los indicadores y campos de
cobertura ya aprobados.

## Comprobaciones de aceptación

- Un camino detenido por su presupuesto actual de tiempo o expansión devuelve
  un parcial tipado y conserva límites y texto.
- Los vecinos muestreados conservan su indicador y aparecen como parciales en
  la rama, la proyección al principal y la exportación verificada por separado.
- Las filas parciales de timeline conservan orden y fuentes; no se amplía la
  consulta para completar las filas que faltan.
- El modelo no puede declarar un terminal completo tras una consulta parcial;
  un terminal inconsistente, incluso firmado de nuevo, se rechaza.
- Palabras o campos de la fuente no controlan el estado. Siguen pasando los
  fakes de resultados completos y los vectores canónicos actuales.
- Con reloj fijo, 1, 2, 4 y N trabajadores producen los mismos bytes también
  para resultados parciales, sin relajar límites, plazos, validación ni política.
