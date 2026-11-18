Traducción de docs/development/source-queries-format-contract.md en el commit ec22a8f293e7a381a87579d2d48c6412fcd0a7ed; si hay diferencias, prevalece la versión en inglés.

# Puertos de consultas, adquisición firmada y export V9

[English](../development/source-queries-format-contract.md)

**Estado: propuesta de contrato concreto para revisión; sin implementación ni activación.**
Complementa la [arquitectura de consultas en origen](source-queries-design.md).
Propone puertos, marcador de caso 5, export V9 y vectores canónicos sintéticos.
No cambia código de producción, dependencias, credenciales, golden ni workflows.
El flujo Entra y los puertos necesitan aprobación concreta antes de implementarse.
Cada servicio sigue siendo un módulo independiente.

## 1. Alcance y fronteras conservadas

Primeros módulos: `query-athena` para CloudTrail, `query-bigquery` para Cloud Audit
Logs y `query-azure-log-analytics` solo Analytics comprobado. Security Lake OCSF
y Cloud Logging enlazado reutilizan los dos primeros tras sus contratos de campos.
CloudTrail Lake, ADX, Basic y Auxiliary siguen no disponibles. No sustituir un
módulo ausente por una llamada SIEM o de objetos sin filtros.

No cambian SourceDecoder, SourceMapper, SourceRecordV1, ParquetArtifactV3,
MappingProfileV1, MappingRunV1, inventario de sello V2, desafíos de SignedEntry y
SignedOperation ni `export_case`. Reutilizar spool privado, publicación de
evidencia, ingesta mapeada, bloqueo del caso, ramas y broker aprobados. No añadir
caché, remap ni lectores históricos. No reinterpretar etiquetas ni golden actuales.

### Caso y export propuestos

`CaseCreated.version = 5`, claves ordenadas
`version,title,severity,scope,budget,source_queries`. `budget` mantiene sus tres
dimensiones; `source_queries` contiene la asignación inicial, incluso desactivada
y a cero. Rechazar marcadores distintos de 5 antes de abrir/verificar/exportar,
con versión creadora si se puede leer de forma segura y las opciones de usar ese
ejecutable o reingerir. Sin migración implícita, conforme a la política pre-1.0.

Magic `IRMIND-EXPORT-V9\0` y cabecera con versión 9; mismos campos ordenados que
V8. No cambian firmas ni algoritmo del sello. Se verifican también skills,
catálogo, ramas y artefactos mapeados aunque las nuevas secciones estén vacías.

## 2. Tipos validados, límites e identidades

SourceQueryV1 contiene `version,source,dataset,from,to,filters,fields,result,limit`.
Los constructores validan los conjuntos cerrados de campo/operador/valor. El
modelo no aporta SQL/KQL, cuentas/workspaces/tablas, endpoints, opciones ni
cursores. Campos desconocidos/duplicados, traducciones no exactas o proyecciones
incompatibles con el mapeo son errores; nunca retirar filtros para continuar.

| Cantidad | Propuesta por defecto / cota fija |
| --- | --- |
| Intervalo | 31 días configurables por organización; `[from,to)` no vacío dentro del caso/hijo. Techo de código propuesto: 366 días, reducible por servicio. Sin ventana basada en el reloj implícito. |
| Filtros / pertenencia / columnas | Hasta 16 / 32 / 32; valores de hasta 256 bytes UTF-8 tipados. Filtros canónicos ordenados y únicos; columnas por nombre de wire. |
| Evidencia por consulta | Hasta 100.000 filas y 100.000.000 bytes decodificados, lo que llegue antes. `limit` puede reducir filas; permanecen límites por registro. |
| Evidencia por caso | Asignación inicial propuesta de 1.000.000 de filas / 1.000.000.000 bytes, reducible. Suma todas las adquisiciones e hijos, no solo ficheros activos del grafo. |
| Escaneo | Asignación separada nullable, tope por consulta y umbral de aprobación. Sin asignación explícita no se habilita un servicio facturado por escaneo. Sin precio monetario inventado. |
| Azure | 180 segundos totales, una consulta pendiente y seis envíos por minuto móvil por workspace/credencial, compartidos. Reintentos consumen frecuencia. Otros servicios usan el menor plazo configurado o del proveedor. |
| Control y wire | Registro canónico hasta 128 KiB; frame SignedEntry hasta 1 MiB incluyendo envoltura/firma. Validar tamaño final antes de firmar. Profundidad 32, 4.096 nodos y asignaciones acotadas. |
| Streaming | Trozos de transporte hasta 64 KiB; de export hasta 512 KiB; hasta 4.096 páginas por adquisición. Cursores opacos hasta 4 KiB, nunca exportados ni al modelo. No dividir filas demasiado grandes. |
| Vista del modelo | Resumen protegido actual, independiente del volumen retenido. Guard de 1.000.000 bytes, stream de 2.000.000 y frame de 1 MiB sin cambios. |

Los bytes retenidos incluyen cuerpos decodificados y envolturas, no bytes
comprimidos, Parquet o tokens. Reservar espacio para toda la captura admitida,
overhead conocido y margen actual antes de descargar. Disco/decodificador pueden
rechazar antes; no se sustituyen sus límites.

ResolvedQuerySourceV1 congela módulo/versión, alias, cuenta/proyecto/workspace y
propietario, ubicación, dataset/tabla, particiones, referencia de credencial y
revisiones de configuración/política. La referencia no contiene secretos ni
concede permisos. Destinos solo de configuración; TLS/CA/hostname completos y
sin redirecciones que reenvíen autenticación.

CompiledSourceQueryV1 congela texto UTF-8 exacto, parámetros tipados ordenados,
identidad/hash del traductor, decodificador/mapeo, columnas obligatorias, orden y
desempate, predicados de fuente/alcance. Solo lo construye el compilador puro del
módulo. Estado/rol no traducible falla. Los prefijos `%`/`_` son literales. Fuentes
particionadas compilan todas las fechas acotadas y los filtros de cuenta/región.

### Bytes canónicos nuevos

Solo para los registros nuevos: J(x) es JSON UTF-8 compacto, claves recursivamente
ordenadas por bytes UTF-8, sin espacios, salto final ni BOM. Rechazar desconocidos,
duplicados, floats, enteros no canónicos, Unicode inválido y bytes sobrantes.
Ausencia permitida como `null` explícito. Escapes JSON para controles, comillas y
barra inversa; resto UTF-8 literal sin normalizar evidencia. Enteros u64 validados,
booleanos JSON, hashes hex minúsculas de 64 caracteres, UUID minúsculas. Instantes
UTC fijos `YYYY-MM-DDTHH:MM:SS.fffffffffZ`, nueve cifras fraccionarias.

`Id(D,x) = SHA256(UTF8(D) || 00 || J(x))`. Payload firmado: J(x) como cadena del
SignedEntry actual, etiqueta AuditEventKind exacta y desafío Actor sin cambios.
La identidad no sustituye la firma. Ningún codec depende de features del mapa
serde_json; no recanonizar silenciosamente antes de comprobar la firma.

Todos tienen `version=1,case_id`. `task_id:null` representa al principal donde
proceda. Las referencias solo apuntan hacia atrás; el plan no incluye ID propio,
reserva, aprobación ni resultado posterior.

## 3. Puertos concretos de aplicación

Firmas propuestas, no incorporadas al ejecutable. Usan async-trait y cancelación
existentes, sin runtime o SDK nuevos:

```rust
#[async_trait]
pub trait SourceQueryExecutor: Send + Sync {
    fn descriptor(&self) -> SourceQueryModuleV1;
    fn compile(&self, source: &ResolvedQuerySourceV1, query: &SourceQueryV1)
        -> Result<CompiledSourceQueryV1, AppError>;
    async fn preflight(&self, call: &AuthorizedCall,
        query: &CompiledSourceQueryV1, cancel: &CancellationToken)
        -> Result<QueryPreflightV1, AppError>;
    async fn submit(&self, lease: &AdmittedSourceQuery,
        cancel: &CancellationToken) -> Result<SubmitObservationV1, AppError>;
    async fn reconcile(&self, lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef, cancel: &CancellationToken)
        -> Result<ExecutionObservationV1, AppError>;
    async fn fetch(&self, lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef, cursor: &QueryResultCursor,
        cancel: &CancellationToken) -> Result<QueryResponsePage, AppError>;
    async fn cancel(&self, lease: &AdmittedSourceQuery,
        execution: &QueryExecutionRef, cancel: &CancellationToken)
        -> Result<CancelObservationV1, AppError>;
}

#[async_trait]
pub trait RemoteOriginalVerifier: Send + Sync {
    async fn verify(&self, lease: &AdmittedOriginalVerification,
        target: &FrozenRemoteOriginalV1, method: RemoteVerificationMethodV1,
        cancel: &CancellationToken)
        -> Result<RemoteVerificationObservationV1, AppError>;
}
```

SourceQueryModuleV1 declara ID/versión, capacidades exactas, formatos, modo de
contabilidad, semántica del tope, recuperación/cancelación y versiones de API.
Comprobar antes del plan, nunca ejecutar una consulta más amplia para descubrirlo.

QueryPreflightV1 contiene compromiso de configuración, metadatos/instante,
digest del plan exacto, estimación/unidad/base/incertidumbre, tope del servicio y
modo `scan_priced` o `analytics_no_query_charge`; no aprueba. Metadatos y dry run
requieren AuthorizedCall restringida a la fuente, política, TLS, plazo y
contabilidad de llamadas/frecuencia. No ejecutar consulta real ni crear recursos
facturables sin admisión durante preflight.

AdmittedSourceQuery y AdmittedOriginalVerification tienen campos privados, no
son deserializables y solo los crea el broker tras política/alcance/firma/reserva.
Vinculan caso, hijo, fuente, plan/sello/objeto, límites, revisión, actor y fase;
sin firmante Analyst. Rechazar capacidades de otro módulo/fuente/hijo/fase/plan.
Cada HTTP, incluso reintento/poll/fetch/cancel, comprueba la capacidad.

QueryExecutionRef vincula plan, intento y job ID opaco, nunca URL del modelo.
El motor crea QueryResultCursor desde respuestas validadas, por ejecución/ordinal;
repetición, desorden o cambio de plan falla. QueryResponsePage devuelve estado y
cabeceras validados, próximo cursor y stream cancelable de bytes acotados, no una
ruta del caso. Azure síncrono usa una página, sin acumular 100 MB antes de entregarla.

El motor prepara, hashea y decodifica. El módulo no firma/publica, amplía alcance,
cambia presupuesto ni repite un envío incierto. SubmitObservationV1 distingue
aceptado, definitivamente no enviado y desconocido; desconocido no es un error
ordinario reintentable. Reconcile/cancel pueden declarar `unsupported`; no
inventar estado de job ni cancelación exitosa en una API sin esa capacidad.

RemoteVerificationMethodV1 es metadata o sha256. El objetivo viene de la
identidad firmada, no de URI del modelo. La capacidad fija versión inmutable
S3/GCS/Blob, tamaño/ETag/hash, sello y transferencia. Metadatos condicionales y,
solo para sha256 aprobado, GET/hash en streaming con comprobación antes/después.
Devuelve observaciones, no veredicto firmado. Sin versión exacta,
`ExactVersionUnavailable`, nunca alternativa al objeto actual.

### Registro y almacenamiento

Proponer `EnginePorts::with_source_queries(SourceQueryPorts)` opcional con mapas
de ejecutores/verificadores. `EnginePorts::new` no cambia; sin adaptador,
SourceQueriesUnavailable. Claves únicas y features por módulo. Reusar HTTP,
SigV4 y OAuth/RS256 de Google del keystore antes de añadir SDKs.

Reusar spool y publicación/ingesta actuales, sin puerto de almacenamiento genérico
nuevo. Capturas en rutas del caso derivadas de hash; son originales copiados de
la fuente **derivada**, no referencias a temporales. 0600/0700 o ACL del usuario,
no-follow, espacio, cancelación y limpieza de huérfanos obligatorios. Si falta una
primitiva durable en la implementación, parar para un contrato aditivo preciso;
nunca usar temporal del sistema ni eludir append atómico.

## 4. Broker, aprobación y trabajos inciertos

SourceQueryAllocationV1 contiene `enabled,analytics_allowed,scan_bytes,
retained_rows,retained_bytes`. Desactivado/cero explícitos. La organización acota
además intervalo, filas/bytes/escaneo por consulta, plazo, frecuencia/concurrencia
y umbral de escaneo. Cambios de caso mediante SourceQueryBudgetV1 firmado por
Analyst; no superar techo ni reducir por debajo de uso/reservas vigentes.

Un broker serializa admisión entre procesos y principal/hijos con los bloqueos
existentes; uso + reservas + nueva reserva deben caber. Sin bloquear durante UI
ni red. Escaneo separado de cloud_bytes, que conserva transferencia de objetos.
Tráfico/retención de consultas aparte; GET de reverificación sha256 sigue
reservando cloud_bytes.

Para vincular fuentes remotas y reservas del plan completo, proponer
SubagentPlanV2, nueva etiqueta/dominio `irmind-subagent-plan-v2`: todos los
miembros V1 y `query_resources` obligatorio; format_version pasa a 2.
Payload V2 usa J y su dominio nuevo, sin reinterpretar el codec V1. Array por task_id con
`task_id,sources,scope,scan_bytes,retained_rows,retained_bytes`; hasta 32 fuentes
configuradas únicas por hijo, nunca hashes locales ficticios. Los task ID
mantienen su cálculo actual, sin hash de vuelta al plan padre. Aprobación,
reserva y checkpoint existentes referencian la nueva identidad en sus campos
hash sin cambiar codec. Así el consentimiento cubre toda la asignación antes de
arrancar. Sin entrada de recursos, el hijo no consulta fuentes remotas. Plan V2
y umbral ampliado son puntos explícitos de revisión.

La consulta consume llamadas y escaneo/retención. Cada hijo usa la misma bolsa.
Extensión propuesta del 25%: comparar la reserva del plan completo en escaneo,
filas y bytes retenidos con sus asignaciones restantes; superar cualquiera exige
consentimiento Analyst. Demanda positiva con saldo cero se rechaza; Analytics
sin demanda de escaneo no inventa 0/0. Siguen los umbrales de tokens/llamadas/bytes
y la preferencia de confirmar todos los planes. Un hijo nunca se autoaprueba.

Aprobación exacta por encima del umbral, con estimación no fiable y cuando lo
exige la política externa. Analytics es admisión explícita sin cargo de consulta,
no aprobación de coste de escaneo desconocido. Una firma no salva un techo no
imponible. Vista previa con consulta/parámetros, alcance, eje temporal/ventana,
columnas, particiones, estimación, máximos, retención y saldo. Un cambio de
consulta/configuración/mapeo/límites invalida el consentimiento.

Orden: compilar → preflight → plan firmado → aprobación si procede → reserva e
intención de envío firmadas → envío → observaciones → captura y resultado
validados → publicación atómica → liquidación. Nada aparece como evidencia
admitida antes de validar vínculos y append acotado. Un fallo local revierte
admisión; uso remoto y reservas inciertas permanecen, porque la red no se revierte.

La intención es durable antes del envío. Tras timeout/crash reconciliar el mismo
job/idempotency key, no crear otra consulta facturable por perder el HTTP. Reenvío
del mismo intento solo si el servicio garantiza esa idempotencia y el contrato la
prueba. En otro caso conservar desconocido/reserva y bloquear trabajo incompatible.
Poll/fetch no reinician plazo, frecuencia ni filas/bytes acumulados.

Una liquidación por reserva, enlazada a observación terminal y retención real.
Procesados, escaneados y facturados separados; desconocidos `null` con motivo.
Cancelar también puede consumir. El cutoff de Athena dispara cancelación, no es
frontera física exacta: registrar exceso y bloquear nuevas consultas; no disponible
si la organización exige ese tope exacto. No extender deuda de tokens al escaneo.

Timeout Azure no reconciliable queda unknown y ocupa el hueco de ejecución.
Recuperación propuesta: reconocimiento Analyst firmado tras la vida máxima
oficial del servicio que cubra cola y ejecución; liberar solo el hueco, conservar incertidumbre/consumo,
sin convertir escaneo desconocido en cero ni habilitar un servicio facturado.
Es un punto de revisión, no una excepción implementada. Sin cota documentada de
vida completa no se habilita esa recuperación; 600 s de ejecución por sí solos
no bastan. Si la política exige
terminación remota comprobable, un adaptador sin ella no está disponible.

## 5. Azure Analytics y propuesta de credenciales

Primero SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs y AzureActivity,
con esquema/mapeo/traducción exacta comprobados. Revisar Analytics, retención
interactiva, estado estable y propietario justo antes del envío; conservar
observaciones previa y posterior y cambio de plan si lo informa. Rechazar Basic,
Auxiliary, plan desconocido, metadatos ilegibles, archivo/search/resultados
restaurados, expresiones entre tablas/recursos y fuentes internas no verificables.

Los [precios oficiales](https://azure.microsoft.com/en-us/pricing/details/monitor/)
distinguen Analytics de los planes cobrados por escaneo. Base
analytics_no_query_charge, texto «sin cargo por consulta según el plan de la
tabla», escaneo/facturación `null:not_reported` salvo métrica real. Ingesta,
retención y transferencia no se declaran gratuitas. La
[API de tablas](https://learn.microsoft.com/en-us/rest/api/loganalytics/tables/get?view=rest-loganalytics-2025-07-01)
no bloquea el plan durante la consulta; un cambio externo detectado registra
incertidumbre y desactiva nuevas ejecuciones, sin prometer prevención retroactiva.

Campos nuevos propuestos del keystore:
`query-azure-log-analytics/<source>/tenant-id`, client-id y client-secret.
Necesitan aprobación con este contrato; aquí no se crean credenciales. Usar el
[flujo oficial Entra](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api),
audiencias separadas para ARM y Logs Query, tokens solo en memoria y TLS completo.
Sin entorno, CLI, login delegado o identidad ambiental. POST v1 con KQL del
compilador y timespan explícito. ARM exige tables/read; la lectura sigue acotada
por tabla/fila, sin ampliar permisos para que pase el chequeo de metadatos.

## 6. Registros y vínculos acíclicos

Dominios: prefijo `irmind-`, sufijo de la tabla y byte cero antes de J. Etiquetas
AuditEventKind exactas en la primera columna. Todos llevan version=1 y case_id;
campos nullable presentes. J ordena claves; la lista define pertenencia.

| Etiqueta / sufijo del dominio | Resto de campos; actor |
| --- | --- |
| SourceQueryBudgetV1 / source-query-budget-v1 | revision,previous,budget,reason,at; Analyst. previous refiere al presupuesto anterior o null para la asignación inicial autenticada en CaseCreated. |
| SourceQueryPlanV1 / source-query-plan-v1 | task_id,attempt,query,compiled,source,scope,configuration,policy,allocation_revision,preflight,limits,decoder,mapping,at; Agent. Sin referencias posteriores. |
| SourceQueryApprovalV1 / source-query-approval-v1 | plan,task_id,decision,reason,at; Analyst. approve/deny sobre plan y revisión exactos; la política existente también manda. |
| SourceQueryReservationV1 / source-query-reservation-v1 | plan,task_id,approval,allocation_revision,scan_bytes,retained_rows,retained_bytes,at; Agent/broker. approval=null solo si todas las reglas lo permiten. |
| SourceQueryExecutionV1 / source-query-execution-v1 | plan,reservation,previous,attempt,phase,execution_key,provider_id,provider_request_id,started_at,observed_at,provider_at,status,usage,source_observation,reason; Agent. previous encadena observaciones del intento. |
| SourceQueryResultV1 / source-query-result-v1 | plan,reservation,execution,capture_sha256,capture_bytes,page_count,page_commitment,row_count,rejected_rows,completeness,coverage,decoder,mapping,at; Agent. execution anterior, nunca liquidación futura. |
| SourceQuerySettlementV1 / source-query-settlement-v1 | plan,reservation,execution,result,scan_charged,retained_rows,retained_bytes,usage,uncertainty,at; Agent/broker, una sola vez. result=null sin captura admitida; no liquidar normalmente escaneo desconocido. |
| SourceQueryRecoveryV1 / source-query-recovery-v1 | plan,reservation,execution,action,reason,not_before,at; Analyst. Solo reconocer ejecución Analytics expirada no reconciliable; no concede escaneo ni afirma éxito. |

SourceQueryExecutionV1.phase: intent, accepted, running o terminal; status:
pending, succeeded, failed, cancelled, partial o unknown. Transiciones validadas;
unknown no prueba terminación. source_observation es null o snapshot cerrado de
metadatos, incluido plan Azure posterior. El job ID no cambia tras asignarse.
Unknown nunca produce un resultado exitoso.

compiled contiene texto/parámetros y traductor exactos. source/scope/policy/limits
son snapshots completos acotados no secretos, no solo hashes. El verificador
comprueba compromiso y gramática/predicados con el compilador versionado local.
El techo/asignación requiere prueba Analyst autenticada, no un techo creado solo
por Agent. Proponer operación global `source-query-configuration-v1:` seguida de
hex(J({version,source,policy})), con desafío SignedOperation existente e incluida
en el export. Atesta la política adoptada por el analista, no una autoridad
empresarial independiente. Solo referencias del keystore, nunca secretos. Preflight conserva plan de tabla/estimación, instante e incertidumbre.
El JSON remoto no puede escoger otro endpoint o alcance.

usage contiene scanned_bytes,processed_bytes,billed_bytes,returned_wire_bytes,
returned_decoded_bytes,query_price_basis; escaneos nullable con motivo en
uncertainty cuando falten. El coste requiere perfil completo versionado, nunca
precio cero por falta de datos. IDs remotos acotados y no confiables; sin tokens,
Authorization, URLs firmadas ni claves privadas.

Contenedor de bytes retenidos: magic `IRMIND-QUERY-CAPTURE-V1\0`, descriptor J
hasta 128 KiB sin ID futuro del resultado, contador u64 de páginas, y por página
frame de metadatos J más longitud u64/cuerpo. Metadatos: ordinal, columnas/tipos
nativos, filas, encoding, SHA-256 completo y completitud. El límite incluye
metadatos/envolturas. Hash de captura antes del registro de resultado.

`PageCommitment = SHA256("irmind-source-query-pages-v1" || 00 || u64(count) ||
concat(u64(ordinal) || hash32(body) || u64(bytes) || u64(rows) || u8(completeness)))`.
Ordinales contiguos desde cero. Cambiar orden/fila/longitud/cuerpo o quitar/duplicar
página falla. Códigos: 0 completo, 1 parcial del proveedor, 2 límite local,
3 cancelado, 4 rechazado. Resultado global conserva causas ordenadas únicas.
N filas exactas bajo LIMIT no prueba que se adquirieran todas las coincidencias.

SourceManifestV2 fija hash/tamaño y `queries/<capture_sha256>.sqc`, copied=true;
la referencia no autoriza rutas arbitrarias. SourceRecordSetV1 usa ToolResult y
acquisition=ID de SourceQueryResultV1; MappingRunV1/ParquetArtifactV3 siguen igual.
Decodificadores conservan campos, página/fila e instantes reales. Offsets solo de
los bytes capturados, nunca inventados del S3 o tabla remotos. Descriptor/páginas
→ hash de captura → resultado → manifiesto/conjunto → mapeo/artefactos es acíclico.
Los perfiles pueden preceder al resultado sin enlazar hacia él.

### Miembros wire anidados

Los [esquemas de vectores](../development/source-query-format-vectors/schemas.json)
fijan miembros exactos y enums; rechazar extras incluso con firma externa válida.
compiled: text,bindings,translator,required_fields,order; binding: name,type,value
(text/u64/bool/ip/timestamp); translator: id,version,sha256. source:
module,module_version,id,owner,location,dataset,table,partitions; las particiones
son datos finitos tipados, nunca SQL. scope: accounts,projects,workspaces,regions,
from,to,proof; listas ordenadas y únicas; dimensión vacía no aplicable, no comodín.
configuration: sha256,adoption; policy: sha256,rules,adoption, con prueba global
firmada incluida. limits: interval_seconds,rows,retained_bytes,scan_bytes,
deadline_seconds,queries_per_minute,concurrency; scan_bytes null solo Analytics.
preflight: plan_digest,observed_at,accounting,estimate,provider_ceiling,
source_metadata,uncertainty. plan_digest cubre compiled/source/scope/limits,
no el plan posterior que contiene preflight. estimate: unit,value,basis,reliable;
null es desconocido, no cero. Metadatos cerrados por servicio. Decodificador y
mapeo con identidades/versión actuales, hash de definición y esquema objetivo
cuando corresponda. El mapeo de extracción del vector es sintético, sin afirmar
que exista implementado en producción.

## 7. Retención, análisis local y publicación

Reservar filas/bytes antes de enviar. Conservar una vez, validar esquema, elegir
pipeline congelado e ingerir con el escritor normal. Incluir campos del mapeo o
rechazar proyección. Ausencias de rol/clasificación siguen desconocidas con
cobertura. Agregados estadísticos no fabrican CommonEvent ni hallazgos de eventos.

Detener al menor tope. Páginas completas o prefijo de registros con framing
probado pueden admitirse como parciales. No reparar un JSON truncado adivinando
el final: conservar su captura rechazada acotada y recibo, sin registros de grafo
de esa página. Separar PartialError, truncado local, filas inválidas y cobertura.
Contabilizar y sanear las muestras de rechazo como datos no confiables.

Publicar captura, resultado, manifiestos, recibos mapeo/Parquet y liquidación de
retención atómicamente en principal/rama tras hash y tamaño final. Recibos previos
de ejecución/escaneo se conservan aunque falle la admisión. Ficheros de append
fallido se limpian como huérfanos, sin fuente admitida a medias. Ningún dato entra
al rol system. Mantener Provenance, ContentGuard y UNTRUSTED con nonce.

El modelo recibe ID/hash de fuente, ventana, filas/bytes, completitud/cobertura
y vista previa acotada. Timeline, búsqueda, entidades y lectura consultan después
en local con los límites existentes; nunca generan consultas remotas ocultas.
Otra adquisición requiere otro plan firmado y presupuestado.

## 8. Export V9, sello y reverificación separada

Conservar el orden V8 hasta pruebas de catálogo y chunks de ramas. La sección
de operaciones incluye además las pruebas globales de adopción referidas por
planes: primero las operaciones del caso en su orden actual, después adopciones
únicas ordenadas por hash. Es regla V9 explícita, no V8. Verificar desafío/firma
actuales con Analyst esperado, aceptar solo source-query-configuration-v1 y
comparar fuente/política con el plan. Falta, prueba ajena o clave distinta invalida.
Atesta la operación referida, no todo el historial global; no exportar otra
configuración global no relacionada. Después de las ramas, añadir dos
contadores u64 big endian obligatorios, incluso cero:

1. Capturas, ordenadas por SHA-256: frame descriptor J
   `{capture_sha256,bytes,chunks}` y exactamente esos chunks de bytes, hasta
   512 KiB cada uno. Rechazar repetidos, no referidos, faltantes, desorden,
   tamaño/hash incorrectos u overflow.
2. Recibos separados de reverificación, ordenados por ID, un frame firmado por recibo.

Capturas obligatorias aunque se omitan originales externos. No duplicarlas en
la sección opcional de originales, reservada a File externos. Contadores/capturas
deben coincidir con referencias del grafo de eventos principal/ramas verificado.
Mantener comprobaciones de todos los activos/pruebas V8. Rechazar bytes finales,
versiones desconocidas o secciones obligatorias no soportadas.

El inventario V2 del sello no cambia de bytes ni algoritmo. La cadena/checkpoints
ancla planes, reservas, recibos y capturas antes del sello. No usar el contador
Parquet como contador de capturas. Un tercero prueba admisión/firma/vínculos,
bytes retenidos y reconstrucción local, no verdad/completitud de la base remota
ni firma del proveedor. Reejecutar es otra adquisición, no reconstrucción remota.

RemoteOriginalVerificationV1: version,case_id,seal,source_manifest,object,method,
observed_at,outcome,observed,sha256,transfer_bytes,reason,nonce. object fija versión
inmutable. Métodos metadata/sha256; resultados identity_match,digest_match,changed,
missing,denied,unavailable,cancelled. Metadatos nunca digest_match; ETag no es
SHA-256 y 403 ambiguo no es missing. Hash distinto es changed aunque coincidan
ETag y tamaño.

Envoltura `{payload,public_key,signature}`: payload es hex de J, clave pública y
firma Ed25519 en hex. Desafío
`"irmind-remote-original-verification-v1" || 00 || u64(len(J)) || J`.
ID=SHA-256 del desafío. Comparar clave con Analyst/sello esperado, no solo con
la propia envoltura. Nonce nuevo de 32 bytes, distinto de delimitadores UNTRUSTED.
No inferir caducidad ni reemplazo de recibos anteriores.

No reabrir/añadir a cadena sellada. Guardar recibo independiente del sello fijo;
incluirlo requiere otro fichero de export, nunca sobreescribir el anterior. Un
recibo solo prueba la observación en su instante. No exportar credenciales. GET
posterior usa sesión de verificación admitida y presupuesto de transferencia
independiente, sin editar el ledger sellado; el recibo conserva el uso firmado.
Sin concesión de presupuesto implícita tras sellar.

## 9. Vectores y pruebas de implementación

El [inventario y método](../development/source-query-format-vectors/README.md)
fija marcador 5, magic V9, contadores vacíos, identidades/preimágenes de registros,
captura completa, compromiso de páginas y cola V9. Incluye Analytics con escaneo
null, Basic rechazado, resultado parcial y literal malicioso como dato. La firma
Ed25519 y clave alternativa son **sintéticas públicas**, no claves de producción.

Casos negativos: cambiar consulta tras aprobación, revisión/fuente, quitar o
reordenar páginas, cambiar captura, inventar cero escaneado, reserva de otro hijo,
liquidación duplicada y atribuir prueba de hash a una lectura de metadatos.
Son ejemplos de formato/cálculos de referencia; no afirman que el runtime esté
implementado o haya pasado esos contratos.

La implementación añadirá pruebas de cada rechazo, HTTP sintético por servicio,
registros grandes/malformados, ausencia de temporal del sistema, disco lleno,
cancelación/callback bloqueado, rollback/crash, sobresuscripción entre procesos,
modelo obediente malicioso, carreras de versión y reconstrucción offline V9.
Golden también con preserve_order y 1/N trabajadores, sin cambiar los actuales.
Sin cuentas ni escaneos pagados en CI. Benchmarks release separan planificación,
preflight y decodificar/mapear/escribir de la latencia del servidor falso.
La validación real será opcional del analista. No implementar hasta revisar
puertos, etiquetas, caso/export, credenciales y vectores de este contrato.
