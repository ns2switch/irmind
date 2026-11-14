# Contrato de puertos, registros canónicos y export V8 de subagentes

Propuesta derivada de la [arquitectura aprobada](../development/subagents-design.md).
Solo contiene contratos y vectores sintéticos: no cambia código, golden actuales
ni export V7. Primero se revisa; después se implementa un hijo con verificación,
y finalmente paralelismo/panel. En v0.5 no hay tipos comunitarios ni límites en
dinero. [English](../development/subagents-format-contract.md)

## Alcance y coordinación de V8

Se conservan SignedEntry, SignedOperation, sus desafíos de firma, Parquet V3,
recibos de origen/mapeo, bytes del sello V2 y `export_case`. Se añaden los tipos
cerrados descritos abajo. La versión productora actualiza el marcador de formato
y rechaza formatos ajenos antes de procesarlos; no hay lector histórico ni
migración implícita.

Los dos contratos proponen una única cola V8: después de las pruebas de admisión
de skills de V7, contador u64 de pruebas de catálogo y sus frames, y contador u64
de chunks de subagentes y sus frames. Siempre están ambos contadores, incluso
cero. No hay sección de admisión de tipos comunitarios. Magic
`IRMIND-EXPORT-V8\0`; cabecera con campos de V7 en orden: version (8), case_id,
title, severity, scope y seal. Las etiquetas V2 de instalación/instantánea del
catálogo y esta cola común son puntos de revisión explícitos. Una extensión no
vacía no soportada se rechaza, nunca se omite su verificación.

Marcador compartido propuesto: CaseCreated.version=4, con los mismos campos
ordenados version,title,severity,scope,budget y presupuesto inicial obligatorio.
Sin otros cambios al evento o desafío. Versión 3/desconocida se rechaza antes
del trabajo, con guía para usar el ejecutable creador o reingerir, sin inventar
su patch exacto. case-created-v4.json fija bytes; el código actual no cambia.

## Puertos propuestos

Se mantienen SourceDecoder, SourceMapper, LlmPort, Signer, Verifier,
AuditLog::append_batch y EnginePorts::new. Se propone el builder opcional
`with_subagents(SubagentPorts)`. Sin adaptadores, subagentes no disponibles; no se
usa el grafo sin restricciones como alternativa.

- `SubagentBranchStore`: stage(case, CheckedBranchChunk, cancel) devuelve un
  StagedBranchChunk; publish consume ese handle y devuelve PublishedBranchChunk;
  read(case, BranchChunkRef, cancel) devuelve BoundedBranchBytes; discard consume
  solo staging pendiente. Todos devuelven Result con AppError.
- `TaskEvidenceQueries::execute(view, query, cancel)` recibe VerifiedTaskQueryView
  y TaskEvidenceQuery y devuelve TaskEvidenceResult, con los argumentos/resultados
  tipados actuales. Sin E/S implícita o consulta alternativa sin filtro.
- `AnalystPlanInteraction::review(preview, cancel)` devuelve PortFuture de
  AnalystPlanChoice (Start/Cancel), solo desde el adaptador confiable de la TUI.
- `EngineEventSubscription::poll(cursor, max, cancel)` devuelve un batch acotado;
  los eventos no conceden autoridad de aprobación.

Las firmas Rust completas y orden de campos son normativos en la versión inglesa.
Los handles de staging son propios, no Clone; los tipos verificados tienen campos
privados y no se deserializan desde el modelo. El almacén no firma ni concede
confianza. Sincroniza fichero/directorio y publica antes del append principal.
Borrar staging no borra chunks comprometidos. Se usan permisos 0600/0700 o ACL
del usuario; lectura de chunk limitada a 1 MiB. Fallar publicación/firma no expone
un resultado o aprobación parcial.

VerifiedTaskQueryView vincula caso, tarea, generación congelada, conjunto de
fuentes y alcance/política más estrechos. Solo lo construye el broker. Incluye
EvidenceSearch/Read, GraphSummary, EntityLookup, Neighbors, Timeline, Path,
TextSearch y RawRecords: filtrar antes de agregación, muestreo, expansión, orden
y límites. Los originales usan SourceEvidenceReader autorizado. No soportar la
vista devuelve TaskSourceViewUnsupported. Las llamadas remotas mantienen la misma
lease en el dispatcher de política/aprobación.

El broker usa bloqueo y append_batch actuales, sin tener el bloqueo durante UI,
modelo o red. El adaptador de interacción es del analista nativo confiable, no
JSON del modelo ni un evento. Solo el broker conserva el firmante Analyst. Un
llamante no interactivo sin ese adaptador queda PlanPending; ningún parámetro de automatización puede
eludir el consentimiento. Las esperas usan colas acotadas y comprobación de plazo/
cancelación independiente de callbacks bloqueados.

## Vista y reservas

La vista muestra todas las tareas, tipos, fuentes, cuotas y presupuesto restante.
No hay temporizador. Un solo preview pendiente por caso; ningún hijo arranca hasta
Start. La retención de preview no ejecuta herramientas/proveedores. Cancelar o
expirar devuelve solo capacidad que se sabe no utilizada, con motivo firmado.
Nunca se devuelve gasto incurrido o incierto como si estuviera libre.

Bajo transacción: mínimo de asignación firmada y techo vigente, menos consumo y
otras retenciones principales pendientes. Al revalidar se excluye la retención
propia de este preview para no restarla dos veces. Las cuotas de hijos/peticiones
son subdivisiones del plan, no reservas adicionales del caso. El total incluye
coordinación/resumen y todos los hijos.

1. Rechazar T > RT, C > RC, exceso de rondas/bytes o error aritmético.
2. Exigir firma si `u128(T)*4 > RT || u128(C)*4 > RC`. Sin división. Exactamente
   25% no la exige; superar cualquiera de los dos recursos sí.
3. Registrar plan Agent, mostrar su compromiso exacto, recoger Start y, cuando
   corresponda, registrar SubagentPlanApprovalV1 Analyst antes de ejecutar.
4. Recalcular bajo bloqueo al admitir: cambios requieren nueva vista/decisión.

start_plan es único por plan; repetir consentimiento/Start no arranca hijos dos
veces. Recuperar no repite proveedores; un reintento crea plan/tarea nuevos.
Dividir en hijos no evita el umbral agregado. Cada plan posterior usa el restante
actual. Se conservan los cargos existentes de Allowed/ToolDispatch y bytes de
nube. Reservas y checkpoints no vuelven a cobrar esos eventos. Tokens/rondas de
hijos, compactación y resúmenes comparten el techo del turno/caso. Uso incierto
queda reservado. El agotamiento conserva un resultado parcial y usa resumen local
si no cabe una última petición sin herramientas.

El coste solo se estima cuando hay precios/uso suficientes o se muestra no
disponible. No hay límites en dinero ni compilación/instalación de tipos externos.

## Codificación e identidades

JSON UTF-8 exacto, orden fijo de campos como los vectores, null explícito,
enteros, sin espacios innecesarios ni salto final. Rechazar desconocidos,
duplicados, códigos ajenos y tamaños excesivos antes de asignar colecciones.
Usar constructores de dominio: SHA-256 minúsculo64, UUID canónico e instantes
operativos u64 en segundos. La evidencia de origen mantiene su precisión actual.

`Id(D,J)=SHA256(UTF8(D)||00||JSON_canónico(J))`. Payload principal:
`etiqueta-minúscula:hex_minúsculo(J)`, con envelope/firma actuales, evidence null
y clave Agent o Analyst correcta. Ninguna firma vuelve confiable el texto.

| Registro | Contenido y firmante |
| --- | --- |
| SubagentSourcePageV1 | case_id, ordinal, sources; Agent. |
| SubagentSourceSetV1 | case_id, count, pages; Agent. |
| SubagentTypeSnapshotV1 | case_id, inventory_sha256, type; Agent. |
| SubagentPlanV1 | identidad, caso/turno/ordinal, checkpoints, política, asignación/consumo/reservas/restante, coordinación, deadline_at y tareas; Agent. |
| SubagentPlanApprovalV1 | plan_sha256, budget_checkpoint_sha256, remaining_tokens/calls, reserved_tokens/calls, decision; Analyst. |
| SubagentReservationV1 | operation_id, plan_sha256, task_id, request_ordinal, action, purpose, amount, parent_operation, cause_sha256, accounting_audit_sha256; Agent. |
| SubagentCheckpointV1 | caso/tarea, first/last/count, checkpoint previo, compromiso de entradas, hash/tamaño de chunk, nuevas fuentes, terminal; Agent. |
| SubagentResultV1 | caso/tarea, checkpoint final, estado, resumen/hash, citas, cobertura, uso y aprobaciones pendientes; Agent. |

Siempre format_version=1 primero. Los dominios separados y todos los campos
exactos, incluidas estructuras anidadas, están en la tabla inglesa y los JSON.
Las páginas tienen hasta 256 hashes ordenados únicos; máximo 64 páginas/16.384
fuentes por conjunto, 256 conjuntos y 65.536 referencias acumuladas por caso.
Se publican páginas antes del conjunto y este antes del plan. Las fuentes deben
pertenecer a la generación autenticada. Nuevas fuentes propias requieren recibo
principal anterior y admisión en checkpoint; nunca hashes elegidos por el modelo.

Inventario cerrado por código 1–6: triage, cloud, endpoint, network, kubernetes,
threat-intelligence, versión 1; tools/skills ordenados y únicos. Su compromiso es
Id(irmind-subagent-type-inventory-v1, inventario) y la instantánea debe coincidir
con el inventario compilado, no con una declaración comunitaria.

Plan ID: SHA-256 de dominio `irmind-subagent-plan-id-v1\0`, UUID caso16, UUID turno16
y ordinal u64 big-endian (desde 1). Task ID: dominio
`irmind-subagent-task-id-v1\0`, plan ID32 y ordinal u64 (desde 0). No dependen de
llegada o títulos. Cada tarea fija task_id, ordinal, type_snapshot_sha256, nonce,
source_set_sha256, remote_scope, objective, skill_snapshot_sha256, budget y
deadline_at. Nonce único del motor; objetivo de hasta 2.048 bytes; alcance tipado
más estrecho. remote_scope null no concede red. El plazo no supera el del plan;
se impone con servicio monótono, no con un instante del modelo.

Los recursos son tokens,calls,rounds,cloud_bytes u64. Tokens/llamadas/bytes son
totales del caso; rounds es del turno principal, no una cuota vitalicia nueva. El snapshot de política
conserva todos los límites y herramientas denegadas actuales, sin dinero. Runtime
lee la política real; offline autentica la registrada y sus intersecciones, sin
inventar una firma de administrador de organización que no existe.

Aprobaciones approve/cancel deben corresponder al plan/presupuesto exactos y
recalcularse desde historia autenticada; los números no prueban consentimiento.
Reservas: hold_preview, start_plan, reserve_request, settle_request, release_plan,
expire_preview; propósitos plan/model/tool/cloud. IDs deterministas con dominio,
plan, presencia/tarea, códigos de acción/propósito y ordinal, según el contrato
inglés. Slices no amplían el plan. Liquidar requiere prefijo comprometido anterior;
no futuro/autorreferencia, cargo duplicado ni devolución de uso incierto.

Un hijo usa exactamente un Allowed local o ToolDispatch remoto para contabilizar.
El payload de atribución mantiene los campos object_read vigentes y vincula tarea,
llamada, propuesta, reserva, argumentos y conjunto de fuentes. La liquidación
referencia ese evento o ModelUsage existente y no lo cobra otra vez.

## Ramas y orden acíclico

Wire: `{body,hash,signature}`; body ordena format_version,case_id,turn_id,task_id,
nonce,seq,at,kind,payload,prev,public_key. Hash con dominio
irmind-subagent-branch-entry-v1; firma Ed25519 sobre esos 32 bytes. Clave pública
hex32 igual a la clave Agent confiable del caso y firma hex64. Seq desde 1;
prev cero32 solo en la primera entrada.

Códigos cerrados: 1 petición de modelo, 2 respuesta saneada, 3 propuesta de
herramienta, 4 resultado, 5 SkillLoadV1 exacto, 6 compactación, 7 aviso de
presupuesto y 8 terminal. Se conserva el protocolo de tool call IDs, argumentos
validados y procedencia; nunca razonamiento bruto. Los payloads y orden de campos
están fijados en inglés/vectores. SkillLoad usa nonce del hijo, instantánea
principal y límites compartidos. Texto firmado sigue siendo UNTRUSTED.

Chunk: array JSON canónico no vacío y contiguo; SHA-256 ordinario del fichero.
Compromiso ordenado: SHA256(`irmind-subagent-entry-set-v1\0` || u64(count) ||
hashes32 en orden de seq). Verificar first/last/count, firmas/cadena, bytes/hash
y membresía exacta. Sin huecos, duplicados ni prefijos solapados.

Orden: prefijo de propuesta → checkpoint principal → decisión/reserva → efecto
→ prefijo de resultado → checkpoint → liquidación. La entrada terminal no apunta
a su checkpoint futuro. El resultado principal se añade después y repite el
resumen comprometido. Un ciclo, decisión colgante o fichero ausente falla; no se
presenta como éxito parcial. Consentimiento del plan y aprobación de herramienta
son decisiones distintas.

Fusión por plan/oleada/tarea congelados y secuencia local. Se registran instantes
reales; no se reescriben para aparentar determinismo. Con reloj/script fijos se
comparan bytes con 1/2/4/N trabajadores. Cancelar conserva prefijo y consumo, sin
reiniciar llamadas al recuperar.

## Frames, eventos y verificación

Límites: 1 MiB/frame serializado; payload 256 KiB; chunk 64 entradas y 1 MiB;
tarea 4.096 entradas/16 MiB; caso 256 tareas/256 MiB/16.384 chunks; resumen 16 KiB.
Longitudes y contadores u64 big-endian comprobados. Tras catálogo va contador de
chunks y pares de frame descriptor + frame de array. Descriptor: task_id,first,
last,chunk_sha256,chunk_bytes, ordenado por tarea/first. Exactamente lo referenciado
por checkpoints, incluidos prefijos cancelados; sin extras ni bytes finales.

Eventos: version,session_id,cursor,case_id,turn_id,task_id,kind,payload. Versión 1,
cursor monótono por sesión; proyecciones saneadas, nunca claves, razonamiento ni
capacidad de aprobación. Cola de 1.024 eventos/1 MiB, deltas ≤16 KiB y preview
inmutable ≤64 KiB. Agrupar progreso transitorio; preservar aprobación/finalización/
presupuesto/durabilidad con contrapresión y cancelación. Reconectar no repite
herramientas. No se implementa transporte/API de red.

Antes de sellar/exportar: claves, inventario, fuentes, consentimiento, reservas,
ramas, aprobaciones, uso, skills, mapeos y citas. El hash principal compromete
checkpoints sin cambiar sello V2. Verificación offline/streaming, sin modelos,
red ni código descargado. Un material comprometido ausente invalida; coste no
disponible es solo una estimación ausente.

## Vectores y puerta de implementación

[Vectores](../development/subagent-format-vectors/README.md): identidades, fuentes,
plan/consentimiento firmado, ramas/checkpoints, reservas, atribución, resultados y
fragmentos V8. SHA256SUMS los cubre. 25% exacto, +1, restante cero y aritmética ancha
son explícitos; u64 máximo es solo aritmética, no una política válida por encima
de los máximos actuales. Todas las claves son sintéticas.

Son fragmentos de codificación con contexto previo sintético, no casos/archives
completos aceptables. La implementación construirá casos completos y probará
actores/claves erróneos, bypass del modelo, consentimiento ausente/obsoleto,
alcance, contabilidad duplicada, ciclos, límites, cancelación y export independiente.
Verificar una firma de fragmento no sustituye esa prueba de caso completo.
