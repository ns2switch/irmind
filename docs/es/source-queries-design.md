Traducción de docs/development/source-queries-design.md en el commit aeeb2dd2bc330a00f82468bb0e90ac21ab295f93; si hay diferencias, prevalece la versión en inglés.

# Consultas en origen para v0.6

[English](../development/source-queries-design.md)

**Estado: diseño para revisión; no hay nada implementado ni activado por este documento.**
Se proponen consultas remotas de solo lectura mediante módulos independientes.
No se activa ningún proveedor, se crean recursos, se añaden credenciales o
dependencias ni se cambia un puerto o formato firmado actual. Los contratos de
partida son el [pipeline de fuentes y mapeos](../development/source-mapping-design.md),
el [esquema común](../development/common-event-schema.md), los
[presupuestos](configuration.md) y los [subagentes](subagents-design.md).

## 1. Alcance y prioridades

| Prioridad | Módulo y fuente | Entrega propuesta |
| --- | --- | --- |
| Primero en v0.6 | `query-athena`: tablas existentes de CloudTrail en S3 | Athena SQL engine 3, catálogo/base/tabla de Glue y workgroup fijados; filas nativas de CloudTrail. |
| Primero en v0.6 | `query-bigquery`: tablas existentes de Cloud Audit Logs | REST v2, proyecto de facturación, ubicación y tablas/vistas aprobados; jobs bajo demanda con tope de bytes del proveedor. |
| Después de esos contratos, en v0.6 | Security Lake mediante `query-athena` | Acceso regional de consulta ya concedido en Lake Formation y tablas OCSF; sin otro motor ni creación de suscriptores. |
| Después de esos contratos, en v0.6 | Log Analytics de Cloud Logging mediante `query-bigquery` | Dataset/vista enlazados previamente; mismos controles de ejecución, alcance y escaneo. La documentación llama ahora Observability Analytics a la interfaz. |
| Posterior, con extensión explícita del diseño | `query-cloudtrail-lake` | Solo clientes existentes; estimación previa desconocida y sin equivalente documentado al tope de bytes por job de BigQuery. |
| Posterior, condicionado al control del coste | `query-azure-data-explorer` | Clúster/base/tabla fijos y endpoint Kusto de consulta de solo lectura, sin gestión. |
| Posterior, condicionado al control del coste | `query-azure-log-analytics` | Workspace y tablas fijos; Logs Query API v1 de Azure Monitor con KQL generado. |

Son prioridades, no compromisos de release. AWS indica que **CloudTrail Lake no
admite clientes nuevos desde el 2026-05-31**; no se recomienda para empezar.
Security Lake permite consultar tablas de Lake Formation, habitualmente con
Athena. El SQL de Cloud Logging desde clientes externos usa datasets BigQuery
enlazados. Esto favorece dos ejecutores reutilizables antes de añadir adaptadores.
[Disponibilidad/API de CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StartQuery.html),
[consulta de Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-query-access.html),
[datasets enlazados de Cloud Logging](https://docs.cloud.google.com/logging/docs/analyze/query-and-view).

Cada módulo tiene feature, manifiesto, configuración, suite de contrato y estado
experimental propios. Compilarlo no habilita consultas: hacen falta configuración
y admisión por la política. IRMind no crea tablas, sinks, suscripciones,
workgroups ni datasets.

## 2. Consulta estructurada y acotada

Se propone `SourceQueryV1` como valor validado de dominio. El modelo no proporciona
SQL, KQL, URLs, nombres de tabla, credenciales ni opciones de petición. Se
reutilizan los tipos validados de campos y roles del esquema común.

| Componente | Representación cerrada y límites propuestos |
| --- | --- |
| Fuente | Un `SourceId` configurado y un alias de dataset aprobado; antes de aprobar se resuelven cuenta/proyecto/workspace, región/ubicación y tabla inmutables. Sin comodines ni expresiones entre servicios. |
| Tiempo | Intervalo UTC obligatorio `[from, to)`, no vacío y dentro del caso y del techo. Partir del máximo actual de 24 horas de las consultas SIEM; puede reducirse. Sin ventana implícita ni reloj del servidor. |
| Filtros | AND de hasta 16 predicados: igualdad, pertenencia a conjunto de hasta 32 valores, rango tipado, prefijo literal y ausencia explícita. Sin expresiones booleanas arbitrarias, regex, funciones, subconsultas ni negación del alcance. |
| Campos | Hasta 32 campos comunes permitidos: instante, categoría/tipo/acción/resultado, actor/objetivo, IP/puerto de origen/destino, host, nube y recurso. Cada backend declara su subconjunto exacto. |
| Valores | Enums, enteros, IPs e instantes validados; texto de hasta 256 bytes UTF-8. Se rechazan controles e identificadores/Unicode inválidos. La puntuación literal sigue siendo un dato. |
| Resultado | Eventos, cuenta exacta, cuenta por hasta dos campos o principales cuentas. Sin joins, UDFs, aritmética arbitraria, distinct aproximado, escrituras ni exportación a una ubicación elegida por el modelo. |
| Filas | Máximo actual de 100 filas SIEM entre todas las páginas, reducible por política. Limitar filas no limita bytes escaneados. |
| Trabajo | Se mantienen los límites actuales de llamadas, tiempo, respuesta, transferencia, guard y contexto; manda el menor. La admisión por bytes escaneados se añade. |

Ejemplo de datos, **no comando disponible ni definición instalable actual**:

```json
{
  "version": 1,
  "source": "aws-lab",
  "dataset": "cloudtrail-management",
  "from": "2026-11-17T00:00:00Z",
  "to": "2026-11-18T00:00:00Z",
  "filters": [
    {"field": "event.category", "op": "eq", "value": "authentication"},
    {"field": "event.outcome", "op": "eq", "value": "failure"}
  ],
  "fields": ["@timestamp", "event.action", "user.target.name", "source.ip"],
  "result": "events",
  "limit": 100
}
```

El motor valida primero el alcance, resuelve las capacidades del mapeo y compila
un único AST de lectura con identificadores/operadores del adaptador versionado.
Un campo desconocido, fuente contradictoria, filtro no admitido o cuenta ausente
produce un error concreto, nunca un reintento sin esa restricción. Un valor no
puede introducir otra fuente.

Los identificadores de la configuración firmada también pasan la gramática del
servicio y la lista exacta permitida: una firma no convierte SQL en identificador.
Al traducir un prefijo literal con LIKE se escapan `%`, `_` y el carácter de
escape, o se usa un operador fijo de prefijo con semántica equivalente. Los
parámetros no eliminan por sí solos la semántica de comodines.

### Traducción y completitud

| Servicio | Traducción segura y obtención del resultado |
| --- | --- |
| Athena / Security Lake | `SELECT` fijo con columnas y orden explícitos; parámetros posicionales `?` en predicados admitidos. El adaptador codifica cada valor tipado como literal de parámetro Athena: no recibe SQL del modelo. Identificadores de catálogo, tabla y columnas de partición solo de la configuración firmada. `StartQueryExecution`, `GetQueryExecution`, `GetQueryResults` y `StopQueryExecution`. |
| BigQuery / Logging enlazado | GoogleSQL con `queryParameters` tipados, `useLegacySql=false`, tablas y ubicación fijadas. REST v2 con job ID propio para idempotencia; dry run del mismo plan y ejecución con `maximumBytesBilled`, consulta de estado y resultados acotados. Sin funciones remotas ni conexiones externas. |
| CloudTrail Lake | `QueryStatement` generado por AST cerrado y codificador de literales probado. `QueryParameters` se documenta para alias de dashboards, no parámetros generales de consultas arbitrarias. `DescribeQuery` y `GetQueryResults`; sin entrega opcional a S3 inicialmente. |
| Azure Data Explorer | POST `/v2/rest/query`, base/tabla fijas y `x-ms-readonly`; parámetros escalares declarados en `properties.Parameters`. Opciones de tiempo y truncado del compilador. Sin `/mgmt`, funciones almacenadas, expresiones entre clústeres, plugins ni datos externos. |
| Azure Log Analytics | POST `/v1/workspaces/{id-fijo}/query`, `timespan` y predicado idéntico de `TimeGenerated`. No se presupone que acepte la bolsa de parámetros de ADX. AST KQL pequeño y codificador de literales propio; nunca concatenar texto del modelo. Sin `workspace()`, `app()`, `resource()`, unions, search jobs ni consulta entre recursos. |

Referencias de parámetros y peticiones:
[Athena](https://docs.aws.amazon.com/athena/latest/ug/querying-with-prepared-statements.html),
[BigQuery](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/jobs/query),
[CloudTrail Lake](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StartQuery.html),
[HTTP de Kusto](https://learn.microsoft.com/en-us/kusto/api/rest/request),
[parámetros Kusto](https://learn.microsoft.com/en-us/kusto/query/query-parameters-statement),
[API Azure Logs](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/overview).

Los filtros comunes necesitan una traducción versionada asociada al mapeo.
Authentication/failure en CloudTrail usa sus reglas de operación y estado, no
una búsqueda del texto "failure". Se preservan ausencia/unknown, roles y espacios
de nombres. Si no puede aplicarse exactamente el filtro remoto, v0.6 lo rechaza
y explica la falta de cobertura. No consulta sin filtro para descartar filas
después del LIMIT y afirmar completitud. Las cuentas exigen la misma exactitud.
No se sustituye una capacidad ausente por una descarga completa o join entre nubes.

El orden generado es determinista por instante y una clave nativa de desempate
documentada cuando exista. Los tokens de página se vinculan al recibo/job, no
los elige el modelo; se detectan páginas repetidas o ausentes. Sin paginación
estable de snapshot se indica esa limitación, sin afirmar una reconstrucción
del estado en un instante.

## 3. Presupuesto de escaneo, estimación y aprobación

`CaseBudgetLimits.cloud_bytes` mide hoy **transferencia de objetos** reservada,
no escaneo remoto. No se reinterpreta. Se proponen `scan_bytes_per_query`,
`scan_bytes_per_case` y `scan_approval_threshold` en la política de organización,
y asignaciones de caso firmadas que no superen el techo. Sin asignación no se
habilita la función; no se amplía ningún valor de producción en silencio. El
modelo no puede modificar asignaciones.

La unidad queda explícita: bytes procesados, facturados, de objetos y devueltos
son contadores distintos. Se guardan las métricas originales y la interpretación
versionada del adaptador. En BigQuery bajo demanda se reserva contra el máximo
facturable y se conservan aparte los procesados; Athena registra escaneados.
CPU/slots con tarifa por capacidad no se convierten en bytes o dinero ficticios.
Los precios opcionales tienen moneda, región, unidad y versión; sin ellos el
coste no está disponible.

| Backend | Estimación y control del proveedor | Consecuencia |
| --- | --- | --- |
| BigQuery | Dry run exacto y `maximumBytesBilled` en el job real. Tablas externas/federadas o seguridad por filas pueden invalidar la estimación. | Inicialmente tablas/vistas nativas aprobadas bajo demanda y contabilidad comprobada. Estimación no fiable exige firma; techo desconocido o no imponible implica denegar. |
| Athena | Particiones autorizadas de fecha/cuenta/región; workgroup fijo con `EnforceWorkGroupConfiguration` y `BytesScannedCutoffPerQuery`. Metadatos acotados cuando estén autorizados. El tamaño comprimido o EXPLAIN no es un dry run facturable garantizado. | Se firma la base e incertidumbre. Sin cota defendible se exige aprobación y un cutoff de workgroup no mayor que la reserva. IRMind no cambia el workgroup. |
| Security Lake | Mismo cutoff de Athena; particiones según el esquema registrado, no nombres de directorio supuestos. | Sin metadatos de partición, estimación desconocida, nunca cero. Lake Formation sigue aplicándose. |
| Cloud Logging enlazado | Controles de BigQuery y comprobación de tabla/vista y limitaciones del dry run. | El administrador crea el enlace, nunca IRMind; proyecto de facturación explícito. |
| CloudTrail Lake | `DescribeQuery` informa `BytesScanned` después; un rango temporal no garantiza un techo. | Soporte posterior condicionado a política revisada de coste desconocido; una firma no supera un techo duro. |
| ADX / Azure Log Analytics | Límites de tiempo, filas, memoria y ejecución; estadísticas posteriores. No se establece aquí un tope duro equivalente de bytes ni dry run fiable. | No disponible con techo estricto de bytes. No confundir tamaño del resultado, coste de ingesta, extents o CPU con escaneo. |

Restricciones oficiales:
[dry run de BigQuery](https://docs.cloud.google.com/bigquery/docs/running-queries),
[cutoff de Athena](https://docs.aws.amazon.com/athena/latest/APIReference/API_WorkGroupConfiguration.html),
[cargos por cancelación de Athena](https://docs.aws.amazon.com/athena/latest/ug/workgroups-setting-control-limits-cloudwatch.html),
[estadísticas de CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeQuery.html),
[recursos Kusto](https://learn.microsoft.com/en-us/kusto/concepts/query-resource-consumption),
[estadísticas Azure Logs](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/prefer-options).

La admisión es atómica entre principal e hijos: uso + reservas vigentes + nueva
reserva deben caber en el caso y el techo. La estimación no es la reserva: se
reserva el máximo admitido de ejecución. Antes de firmar se muestran fuente y
alcance resueltos, intervalo, consulta y parámetros exactos, estimación/rango o
desconocido, reserva máxima y disponibilidad del coste. La firma es obligatoria
al superar el umbral o con estimación no fiable. Se vincula al hash del plan,
configuración, identidad del mapeo y revisión de presupuesto; cualquier cambio
la invalida. Siguen aplicándose las aprobaciones externas de la política aunque
no se alcance el umbral de coste.

Polling con esperas acotadas. Cancelar no libera la reserva hasta reconciliar
estado terminal y uso. Se cobran consultas fallidas/canceladas si el servicio
informa consumo. Un envío de resultado desconocido mantiene la reserva y bloquea
trabajo incompatible; un timeout no permite reenviar a ciegas. Athena puede
escanear más allá del disparador de cancelación: se registra el exceso real y
se bloquean consultas posteriores, sin presentar el cutoff como frontera física
exacta. **No** se extiende la excepción de deuda de tokens a los escaneos. Si un
servicio no satisface el control duro exigido por la organización, sigue
desactivado. Una política futura de coste flexible sería otra decisión.

`/budget` muestra escaneo usado/reservado/restante, bytes escaneados/facturados/
transferidos, ejecuciones inciertas y coste monetario solo si se conoce. Un
segmento cerrado de la barra muestra escaneo y el aviso actual del 80%. Al agotar
se nombra el contador y `/budget`; la ampliación sigue firmada y bajo el techo.
La caché local o del proveedor no implica coste cero: mandan las métricas
informadas y se etiqueta su reutilización.

## 4. Credenciales, alcance y permisos mínimos

Credenciales, material de sesión y renovación solo en el keystore: nunca entorno,
argumentos, configuración, SQL ni recibos. Reutilizar AWS SigV4 y RS256/OAuth de
Google existentes cuando proceda; la autenticación Azure es una propuesta de
flujo nuevo, no se activa aquí. TLS y nombre de host completos, con la opción
actual de CA por fuente. Sin descubrimiento ambiental. Endpoint y destino del
resultado los configura el analista; se rechazan redirecciones que reenviarían
autenticación a otro origen. Comprobar región, proyecto facturado y propietario
independientemente de los argumentos; revisar los metadatos antes de ejecutar.

El alcance efectivo intersecta techo, caso, tablas/particiones configuradas y
fuentes/alcance del hijo. Una identidad con acceso a una suscripción o a tablas
de otra cuenta no amplía el caso. Los predicados de cuenta/proyecto/región los
inyecta el compilador y no los sustituye un filtro del usuario. Sin aislamiento
fiable de tenants, una tabla no está disponible para un caso más estrecho. No
hay ampliación implícita a instancia, workspace u organización ni herramienta
del modelo para configurarla.

Solo lectura significa no cambiar la **evidencia fuente**. Consultar puede crear
jobs, tablas anónimas o ficheros de resultado, efectos acotados que se explican
al analista. Un prefijo de salida Athena dedicado es el único destino de escritura;
sin escritura en los originales, DDL/DML, tablas persistentes, publicación de
resultados ni cambios IAM. La limpieza por ciclo de vida la prepara el
administrador, sin conceder borrado de objetos a IRMind.

| Servicio | Ejemplo de concesión mínima sobre los recursos configurados |
| --- | --- |
| Athena | `athena:GetWorkGroup`, `StartQueryExecution`, `GetQueryExecution`, `GetQueryResults`, `StopQueryExecution` en un ARN de workgroup. Lectura Glue solo en catálogo/base/tabla aprobados. List/Get S3 en prefijos fuente; ubicación/List/Get/Put y multipart necesarios solo en el prefijo de resultados. KMS decrypt para fuentes y cifrado del resultado solo si se usa. Sin FullAccess. |
| Security Lake | Lo anterior y SELECT/DESCRIBE de Lake Formation en tablas compartidas regionales, con `lakeformation:GetDataAccess` si lo exige el acceso. El administrador prepara grants/enlaces; IRMind no se concede permisos ni crea suscriptores. |
| CloudTrail Lake | `cloudtrail:StartQuery`, `DescribeQuery`, `GetQueryResults`, `CancelQuery`, `GetEventDataStore` para el almacén fijado. Hay que comprobar por acción los recursos admitidos; sin creación, ingesta ni entrega opcional a S3. |
| BigQuery | Rol personalizado de ejecución con `bigquery.jobs.create` y Data Viewer en dataset/tabla o vista autorizada concretos. Sin Editor, creador de datasets ni Data Editor. Las pruebas deben confirmar lectura/cancelación de jobs propios sin job-administrator global. |
| Cloud Logging enlazado | Permisos BigQuery y Logs View Accessor sobre la vista exacta cuando proceda. Sin Logging Admin ni creación del enlace. |
| ADX | Database Viewer en una base dedicada; sin Admin ni Ingestor. Viewer lee ampliamente la base: usar separación o vistas restringidas gestionadas por el administrador si el alcance es menor. |
| Azure Log Analytics | Lectura/query del workspace y lectura de datos de tablas con RBAC granular limitado a tablas/filas aprobadas. Preferir Log Analytics Data Reader con condiciones a Reader/Contributor amplios; sin sharedKeys, ingesta, search jobs ni escritura del workspace. |

Referencias:
[acciones Athena](https://docs.aws.amazon.com/service-authorization/latest/reference/list_athena.html),
[políticas de workgroup](https://docs.aws.amazon.com/athena/latest/ug/example-policies-workgroup.html),
[recursos IAM CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/security_iam_service-with-iam.html),
[permisos de consulta BigQuery](https://docs.cloud.google.com/bigquery/docs/running-queries),
[vistas enlazadas](https://docs.cloud.google.com/logging/docs/analyze/query-with-bigquery-studio),
[roles ADX](https://learn.microsoft.com/en-us/kusto/access-control/role-based-access-control),
[RBAC granular Azure](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/granular-rbac-log-analytics).

Ejemplo de statement Athena, incompleto sin los grants separados de Glue/S3/KMS:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["athena:GetWorkGroup", "athena:StartQueryExecution",
      "athena:GetQueryExecution", "athena:GetQueryResults", "athena:StopQueryExecution"],
    "Resource": "arn:aws:athena:eu-west-1:111122223333:workgroup/irmind-lab"
  }]
}
```

Un ejemplo GCP es `{"includedPermissions":["bigquery.jobs.create"]}` en el
proyecto facturado más `roles/bigquery.dataViewer` en el dataset/vista autorizado.
En Azure: `Actions = [workspace/read, workspace/query/read]` y
`DataActions = [workspace/tables/data/read]`, con nombres completos
`Microsoft.OperationalInsights/workspaces/...`, asignados al workspace y con
condiciones de tabla/fila. Son plantillas, no políticas probadas. Los recursos
admitidos por cada acción CloudTrail y los grants de cifrado son puertas de
contrato/validación real: si no se confirma un endpoint o permiso, el adaptador
no está disponible e indica la carencia, sin ampliar permisos automáticamente.

## 5. Custodia, evidencia derivada y mapeo

Se proponen **registros nuevos para una revisión concreta posterior**; estos
nombres no asignan etiquetas ni alteran golden actuales:

| Registro | Contenido firmado y propósito |
| --- | --- |
| `SourceQueryPlanV1` | Consulta estructurada canónica, texto traducido UTF-8 exacto y parámetros tipados ordenados, versión/hash del traductor, compromiso de configuración, cuenta/proyecto/workspace, región, alcance, instante, identidades de decodificador/mapeo, límites, base de estimación y referencias de reserva/aprobación. Sin secretos ni Authorization. |
| `SourceQueryExecutionV1` | Hash del plan, ejecución/request ID del servicio, clave de idempotencia, actor/hijo, instantes locales y del servicio, estado, unidades y métricas del proveedor, liquidación, reintentos/cancelación y datos desconocidos explícitos. |
| `SourceQueryResultV1` | Vínculo a ejecución, orden y cantidad de páginas, hash/tamaño de cada respuesta acotada y compromiso ordenado del conjunto, filas, errores/truncados/parciales del proveedor y límites locales. SourceRecordSet y recibos de mapeo enlazan la fuente derivada a la adquisición. |

Firmar plan antes de enviar; aprobación del analista separada cuando proceda;
después resultado/uso y evidencia admitida con las claves de actor actuales. Un
hijo firma en su rama, nunca como Analyst. Conservar **texto y parámetros exactos**,
no solo hash o explicación. Los valores tainted siguen siéndolo dentro de SQL
generado: escapar su visualización y pasar cualquier vista al modelo por
ContentGuard/UNTRUSTED. Sin credenciales, URLs firmadas, tokens ni valores
sensibles en diagnóstico. Una proyección solicitada no evita redacción o alcance.

Los cuerpos capturados se guardan en ficheros privados y acotados dentro del caso,
nunca en el temporal del sistema. Hash antes de decodificar, indicando si hubo
descompresión de transporte y su encoding. Commit atómico de páginas/recibos;
controles actuales de espacio, permisos, cancelación y rollback. Evidencia parcial
retenida no equivale a consulta completa. Resultado inválido produce rechazo
firmado y recibo de consumo, sin perder filas en silencio. HTTP 200 no basta:
Azure Logs puede devolver `PartialError`.
[Respuesta de Azure](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/response-format).

El resultado es una fuente derivada. Los decodificadores acotados de respuesta
preservan nombres/tipos en `SourceRecordV1`, con ejecución/página/fila como
procedencia, sin offsets de objeto inventados. Se selecciona el mapeo identificado
actual o un wrapper versionado explícito: CloudTrail para Athena/Lake, OCSF para
Security Lake, Entra ID/Azure Activity para Azure y Cloud Audit Logs para
BigQuery/Logging. Se valida la forma de entrada. Sin mapeo semántico, resultado
sin clasificar y aviso de cobertura; no inventar roles ni resultados. Una
agregación es un resultado estadístico derivado, no eventos ficticios de
autenticación. Conserva grupo/consulta/ventana y solo los IDs realmente devueltos.

El export incluye consulta, parámetros, plan/aprobación/ejecución/uso, respuestas,
compromisos y pruebas de ramas, manteniendo **1 MiB por frame** y los límites del
guard/stream. Resultados grandes usan assets acotados, no un frame enorme. No se
añaden significados silenciosos al marcador de caso 4 ni al export V8: se propone
la siguiente versión de caso/export con secciones explícitas, en otro contrato
y con golden antes de implementar. El puerto sigue llamándose `export_case` y
la verificación no exige credenciales ni nube.

Un tercero sin conexión verifica firmas, admisión/alcance, vínculos, hashes,
completitud del resultado **retenido** y reconstrucción determinista de su
decodificación/mapeo. Autentica el registro de IRMind, no una firma del proveedor
ni la verdad o completitud de la base remota. Reejecutar la consulta **no es
reproducible**: cambian retención, eventos tardíos, permisos, motor y datos. Una
reejecución crea evidencia nueva y comparación; no sustituye la anterior. La
reconstrucción local de las respuestas conservadas es otra comprobación.

## 6. Reverificación remota tras el sellado

Comprobar originales con identidad inmutable firmada: VersionId S3, generación
GCS o versión/snapshot Azure Blob, con ETag y tamaño. HEAD/metadatos contra la
**versión firmada exacta**; informar además si la referencia actual cambió, cuando
esté autorizado. ETag es una condición opaca, no un hash universal. Igualdad de
metadatos confirma identidad/metadatos, nunca SHA-256.

Para igualdad de bytes, admitir por separado GET condicional con presupuesto de
transferencia y SHA-256 en streaming sobre esa versión. Metadatos antes/después;
rechazar carreras, sustitución o ausencia. Acceso denegado, eliminado, cambiado
y no disponible son resultados distintos; un 403 ambiguo no prueba ausencia.
Sin versiones inmutables la garantía es explícitamente menor.
[HEAD de S3](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html),
[precondiciones GCS](https://docs.cloud.google.com/storage/docs/request-preconditions),
[propiedades Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob-properties).

No se reabre ni se añade a una cadena sellada. Se propone recibo firmado separado
que vincula hash del sello, objeto, instante de comprobación, método, resultado,
bytes/coste y actor. Se guarda como producto de verificación adicional, sin
sobrescribir exports. Su formato necesita el contrato posterior. Una tabla
mutable no adquiere garantía de versión de objeto al sellar su resultado.

## 7. Subagentes y límites del motor

El hijo de nube recibe fuentes de consulta configuradas exactas, hashes locales
asignados, alcance reducido y reserva de escaneo. Solo el broker conserva
credenciales y envía con autorización no falsificable. El hijo no elige cuentas,
añade tablas, aumenta presupuesto ni aprueba coste desconocido. La cola identifica
hijo, fuente, plan y reserva. Cancelación/recuperación mantienen las reservas
de jobs remotos aún no reconciliados.

Se propone dimensión de escaneo nueva en el broker, sin reinterpretar
`cloud_bytes`. Restante del caso menos todas las reservas es el único fondo.
Aplicar la regla aprobada del 25% del plan completo también a esta dimensión es
una **extensión propuesta que necesita contrato aprobado**. Llamadas, tokens,
rondas y transferencias siguen independientes; no se hereda la excepción de
deuda de tokens. El principal recibe solo resumen protegido; evidencia y recibos
quedan en rama verificada, fusión determinista y export.

Se propone `SourceQueryExecutor` con preflight, envío, estado, lectura y
cancelación de planes autorizados, y `RemoteOriginalVerifier` para identidad/hash
de versión. Los adaptadores no firman, aprueban ni cambian política. El motor
reserva y ensambla recibos. Mejor puerto separado que convertir `ObjectSource`
en ejecutor de consultas. Son **propuestas de puerto**, no firmas aprobadas:
tipos, recuperación, cancelación y vectores requieren revisión antes de código.

## 8. Dependencias y autenticación

| Backend | Opción SDK completo | Alternativa propuesta; revisar antes de añadir nada |
| --- | --- | --- |
| Athena | AWS SDK Athena y Glue/STS cuando hagan falta | HTTP actual, API JSON acotada y SigV4 existente; sin cliente SQL ni proceso AWS CLI. |
| CloudTrail Lake | AWS SDK CloudTrail | HTTP firmado; siguen las puertas de clientes existentes y coste. |
| Security Lake | SDKs Athena/Glue/Lake Formation | Consultar tablas compartidas existentes con Athena; sin SDK administrativo en runtime. |
| BigQuery / Logging | SDK BigQuery y autenticación Google | REST v2 con RS256/OAuth del keystore existente; sin ADC ambiental ni proceso `gcloud`. Logging enlazado no necesita otro ejecutor. |
| ADX / Azure Logs | Kusto / Azure Identity / Azure Monitor | HTTP/TLS existente y credenciales cliente Entra explícitas en keystore; revisar flujo OAuth, certificados y endpoints por separado. |
| Objetos remotos | Adaptador de almacenamiento actual | Reutilizar metadatos/GET condicionales; una capacidad aditiva de metadatos puede requerir revisión. Sin SDK adicional por defecto. |

Publicar el diseño no autoriza dependencias, features, credenciales ni puertos.
Antes del código hay que inventariar signers/auth existentes, medir tamaño SDK
frente a HTTP, documentar API/región y pedir aprobación de las adiciones. Sin
CLIs externos que manejen secretos ni alternativas ambientales automáticas.

## 9. Contratos y validación opcional del analista

CI usa servidores falsos por servicio, credenciales sintéticas y respuestas
sintéticas grabadas; nunca cuentas reales ni escaneos de pago. Suite mínima:

- AST y peticiones golden por adaptador/filtro, parámetros estables y predicados
  de alcance iguales para llamadas del principal y de los hijos.
- Valores maliciosos como `' OR 1=1 --`, backticks, `'; .drop table X`, pipes,
  `workspace("other")`, comodines/escape de LIKE, saltos codificados y controles Unicode: rechazo o un único
  literal, sin sintaxis adicional. Identificadores maliciosos se rechazan.
- Sustitución de cuenta/proyecto/región/workspace, filtro semántico no soportado,
  metadatos manipulados, mapeo ausente, credencial/endpoint desconocidos.
- Estimaciones cero/desconocidas, cambio entre firma y envío, rechazo por tope,
  consumo parcial/cancelado, caché, sobresuscripción, recuperación y reservas
  de ejecución incierta.
- Tokens de paginación repetidos/de otro job, filas inválidas/grandes, IDs
  duplicados, esquema roto, error parcial HTTP 200 y truncado explícito.
- Modelo falso obediente con evidencia/skill/hijo maliciosos que intentan SQL,
  URLs, ampliación de alcance, presupuesto o autoaprobación: no se ejecuta.
- Recibos firmados y alteración/reordenado/eliminación, reconstrucción derivada,
  verificación sin red, sello/export y comprobación remota sin alterar la cadena.
- Versión exacta S3/GCS/Blob, objeto actual cambiado, borrado, acceso denegado,
  ETag igual con hash distinto, carrera y GET cancelado.

Tras implementar, añadir guía opcional por servicio con fuente desechable:
preparar datos públicos/sintéticos, registrar servicio/región/esquema, conceder
permisos mínimos y credenciales en keystore, límites bajos de escaneo/transferencia
y umbral, ejecutar eventos y cuenta exacta, comprobar rechazo/aprobación,
presupuesto, verificación, sello y export sin conexión. Registrar métricas reales
del proveedor, limpiar jobs/resultados con herramientas administrativas y revocar
credenciales. Nunca ejecutar automáticamente este procedimiento de pago.

| Servicio / API / región | IRMind / adaptador / mapeo | Estimación y base | Tope / escaneado / facturado / devuelto | Aprobación / parcial | Hash / sello / export | Resultado y no probado |
| --- | --- | --- | --- | --- | --- | --- |
| Pendiente del analista después de implementar | | | | | | |

## 10. Orden de revisión e implementación

1. Revisar alcance, denegación por coste desconocido y dimensión de escaneo;
   aprobar después puertos concretos y vectores de formato por separado.
2. Compilador/admisión y verificación de recibos/export con fakes, sin cambiar
   límites ni fronteras de contenido no confiable.
3. Athena CloudTrail y BigQuery bajo demanda en módulos/PRs propios, midiendo
   planificación y decodificar/mapear/escribir resultados acotados en release.
4. Security Lake y Logging enlazado con ejecutores probados y mapeos explícitos;
   publicar cobertura y observaciones de servicios reales por separado.
5. Retomar CloudTrail Lake y Azure solo con contrato de coste demostrado. Un
   HTTP exitoso no basta para afirmar soporte.

Esta PR solo documenta. No cierra la validación del conector, autoriza gasto
en nube ni implementa consultas en origen.
