Traducción de docs/parsers.md en el commit 09424e9a2da7020b92f1932f69cac6bd4904397a; si hay diferencias, prevalece la versión en inglés.

# Parsers de logs

Esta página ayuda al analista a elegir un parser local y probar un formato propio antes de ingerirlo. Todos los parsers actuales son experimentales y tienen pruebas con datos sintéticos. Un analista también ha registrado una [investigación parcial con un modelo real y datos públicos de CloudTrail ingeridos localmente](manual-validation.md#investigación-parcial-con-modelo-real-2026-11-17); no valida todos los parsers, un conector remoto ni el uso en incidentes reales. Consulta [módulos](modules.md) para los formatos concretos y [configuración](configuration.md) para el directorio de datos.

## Cómo se elige el parser

El registro entrega como máximo los primeros 64 KiB a cada detector compilado. El nombre del archivo es una pista, nunca una prueba. Solo se elige automáticamente una coincidencia única con confianza del 80 % o superior. Si hay empate o confianza baja, el analista confirma. La ingesta desatendida no elige un parser ambiguo. El manifiesto firmado guarda identidad, versión, confianza y modo de elección.

`/ingest` abre el selector de archivos. `/ingest --parser <nombre> <ruta>` fuerza una elección que queda auditada. **Settings → Preferences** muestra nombres y versiones de los parsers compilados. Compilarlos no selecciona ningún modelo remoto.

| Parser | Entrada | Detección | Campos mapeados | Estado |
| --- | --- | --- | --- | --- |
| Microsoft 365 Unified Audit Log | CSV de Purview, JSON de Search-UnifiedAuditLog y Management Activity API | AuditData/Operation, CreationTime y workload originales; 98 | Instante UTC, actor, buzón objetivo explícito, recurso, IP de origen, user agent, workload y tablas de operación/resultado | experimental |
| Okta System Log | Arrays JSON de la API y exports JSON/NDJSON | eventType, uuid, actor e instante published; 98 | Autenticación, MFA, administración, políticas y suplantación; actor/objetivo e IP de origen | experimental |
| Depuración de DNS Server de Windows | Resúmenes de paquetes en texto | Cabecera de creación y columnas de paquete, 79 o 98 | Consulta, tipo, código de respuesta e IP remota según el sentido del paquete | experimental |
| IIS W3C | Texto de registros de acceso extendidos | Fecha, hora y columnas HTTP de `#Fields`, 98 | Método, ruta, consulta original, estado, bytes, cliente y servidor | experimental |
| Route 53 VPC Resolver | JSON, NDJSON | Versión 1.x, consulta, cliente y VPC o perfil, 98 | Consulta DNS, tipo, clase, cliente, puerto, código de respuesta, cuenta y región | experimental |
| Auditoría de GitHub | CSV y JSON de organización o empresa, NDJSON nativo del streaming | Acción, fecha e identidad o ámbito de auditoría nativos, 98 | Membresía, tokens, claves, acceso a repositorios y configuración de Actions | experimental |
| Reports API de Google Workspace | Páginas, arrays y objetos JSON, y NDJSON | ID de actividad, aplicación, instante y eventos nativos, 98 | Login, SAML, administración, OAuth, Drive y Gmail con campos originales | experimental |
| Unified Log y eslogger de macOS | Arrays y objetos JSON, y NDJSON | Campos nativos de Unified Log o envoltura y esquema de Endpoint Security, 98 | Proceso, fichero, autenticación, sesión, montajes y notificaciones de seguridad seleccionadas | experimental |
| CrowdStrike FDR | JSONL, texto o gzip | event_simpleName, cid, aid e instante nativos; 98 | ID de proceso separados por tenant/sensor, PID por registro, extremos de red, DNS/autenticación y tablas de fichero/registro | experimental |
| Microsoft Defender | CSV/JSON de Advanced Hunting y JSON de Streaming | Timestamp nativo, DeviceId/ActionType o AlertId y estructura: 98 | Proceso/padre, fichero, registro, red y acceso; AlertInfo/AlertEvidence no confirmados | experimental |
| Correo RFC 5322 | Un `.eml` o volcado de cabeceras por fichero; MIME acotado | From y combinación de cabeceras nativas: 98; cabeceras mínimas: 70, elección del analista | Saltos Received ordenados, direcciones, cabeceras/bytes originales, URLs y metadatos/hashes de adjuntos; resultado desconocido | experimental |
| AWS GuardDuty | JSON de API, CLI/consola y EventBridge | Cuenta, ID/tipo de hallazgo, región, recurso e instante originales; 98 | Alerta de origen sin confirmar, roles de actor/recurso/IP, severidad exacta e instantes originales | experimental |
| AWS VPC Flow Logs | Texto con cabecera/personalizado o v2, gzip y mensajes CloudWatch | Cabecera nativa: 98; v2 sin cabecera: 70 y confirmación del analista | Extremos y roles, resultado explícito, bytes/paquetes, cuenta/región y host de instancia explícito | experimental |
| Azure flow logs | Contenedores JSON VNet y NSG | Categoría del proveedor y estructura de flujos: 98 | Tupla original, instante preciso, extremos, resultado, contadores, suscripción y regla | experimental |
| GCP VPC Flow Logs | JSON/NDJSON de Cloud Logging y envolturas entries | logName de VPC, connection e instante: 98 | Roles de extremos, proyecto, VM observadora, bytes/paquetes; resultado ausente desconocido | experimental |
| JSON y logs de nube exportados | JSON/NDJSON; AWS, GCP, Azure y HuntEval | Campos reconocidos del registro | Instante, identidades, cuentas, recursos e IP | experimental |
| GCP Cloud Audit Logs | LogEntry JSON/NDJSON; exportaciones de GKE | Servicio/método protoPayload e instante originales | Nanosegundos UTC, estado explícito, roles de principal, recurso y extremos; clúster GKE confirmado | experimental |
| Microsoft Entra ID | JSON/NDJSON de Azure Monitor y filas-objeto de Log Analytics | Categoría o Type documentado e instante original | Accesos y auditoría, resultado explícito, tenant, actor, objetivo e IP | experimental |
| ECS | NDJSON | Versión de ECS e instante/campos característicos | Evento, host, usuario, origen, destino, proceso, archivo, URL | experimental |
| OCSF | JSON/NDJSON o Parquet local | Clase, categoría y metadatos; Parquet requiere confirmación | Autenticación, API, red, procesos, archivos y hallazgos | experimental |
| Herramientas DFIR | Velociraptor, Hayabusa, Chainsaw, plaso, EZTools | Marcadores o cabecera CSV exacta | Instante, host, usuario, proceso, acción y entidades disponibles | experimental |
| Windows EVTX | EVTX binario: Security, System, PowerShell y Sysmon | Cabecera EVTX y checksum válidos; 95 | UTC con precisión de 100 ns, host, usuario, proceso, IP/puerto y offsets reales | disponible; experimental |
| Linux | auth.log/secure, auditd, journald JSON y HTTP common/combined | Etiquetas de autenticación, cabecera audit, campos de journald o cabecera HTTP completa | Tiempo, host, usuario, proceso, comando, IP/puertos, acción y resultado; grupos audit parciales | experimental |
| Syslog | RFC 5424/RFC 3164, texto o gzip acotado | PRI y forma de cabecera/instante, no extensión | Host, aplicación, PID, facility, severity, mensaje y tiempo completo | experimental |
| Zeek | TSV o JSON de red | Cabecera o campos reconocidos; 95 en los fixtures conn/DNS | Tiempo preciso, extremos, correlación UID y host explícito del sensor | experimental |
| Suricata EVE | JSONL de alertas, flujo y protocolos | Tipo compatible, instante y flow ID; 95 | Tiempo preciso, extremos, correlación y detecciones sin confirmar | experimental |
| Auditoría Kubernetes | Event nativo `audit.k8s.io/v1`, JSON/NDJSON | Versión de API y tipo explícitos; 98 | Campos originales, nanosegundos y contexto firmado de clúster. La clasificación semántica corresponde a módulos de mapeo separados. | experimental |
| Falco | Detecciones JSON/NDJSON | Regla, prioridad, instante y objeto output-fields; 98 | Regla y campos originales, tiempo preciso; los registros Kubernetes requieren contexto de clúster confirmado. Una detección de origen no es una confirmación del analista. | experimental |
| Declarativo | CSV, JSON, NDJSON o regex acotada | Cabecera exacta, campos JSON o regex; máximo 70 % | Mapeo explícito descrito abajo | experimental |

## Contexto de clúster por ingesta

Los eventos nativos de auditoría Kubernetes no contienen una identidad global del clúster. La TUI pide una identidad explícita con proveedor, por ejemplo `kubernetes:urn:k8s:team-a`, antes de ingerir. Confírmala para un archivo o selecciona expresamente la opción del lote. No se toma un valor por defecto del equipo, nombre de archivo o directorio. Falco requiere la misma confirmación si hay metadatos Kubernetes; las detecciones solo de host no inventan un clúster.

En automatización: `irmind ingest <case-id> <path> --cluster kubernetes:urn:k8s:team-a`. En el campo de conversación: `/ingest --cluster kubernetes:urn:k8s:team-a <path>`. Ambos usan el mismo contexto tipado y acotado en el manifiesto firmado y la reconstrucción. Sin el contexto obligatorio, no se ingiere. Confirmar una identidad no concede permisos remotos. Los nombres iguales en distintos clústeres o namespaces mantienen identidades distintas. Los decodificadores conservan request/response como campos originales, sin copiarlos automáticamente a la proyección de búsqueda.

Estos módulos cubren Events nativos, las envolturas de CloudWatch GetLogEvents de EKS y los diagnósticos kube-audit/kube-audit-admin de AKS. GKE usa Cloud Audit mediante el módulo GCP descrito abajo. No se activa ningún conector a la API de Kubernetes.

## Lectores actuales y casos existentes

Las ingestas nuevas usan la versión del parser registrada en su manifiesto firmado. JSON usa `json-source-v1`. No se conservan lectores históricos. Los bytes firmados existentes se pueden autenticar y exportar; para regenerar registros de un lector anterior, crea un caso nuevo e ingiere los originales verificados. Reinstala las definiciones declarativas después de actualizar su lector. Consulta el [registro de cambios](../../CHANGELOG.md#known-issue-fixed).

## Cobertura de Windows

Hoy se investigan estos artefactos mediante exportaciones procesadas. Todos los módulos de la tabla son experimentales y están probados con datos sintéticos. IRMind ingiere las salidas; no ejecuta KAPE, EZTools, Velociraptor ni plaso, ni abre por sí mismo sus artefactos binarios originales.

| Artefacto | Qué ayuda a responder | Cómo se ingiere hoy |
| --- | --- | --- |
| Logs de eventos de Windows, incluido Sysmon | ¿Qué inicios de sesión, procesos o servicios quedaron registrados y cómo se relacionan? | CSV/JSONL de Hayabusa → `parser-hayabusa`; CSV de EvtxECmd → `parser-eztools`. EVTX directo → `parser-evtx` con el auxiliar aislado; Hayabusa y EvtxECmd siguen siendo alternativas. |
| Registro y sus logs de transacciones | ¿Qué claves y valores de cuentas, configuración o persistencia se registraron? | Procesar externamente con RECmd batch e ingerir su CSV mediante `parser-eztools`. |
| Prefetch (`.pf`) | ¿Qué ejecutables, recuentos e instantes de ejecución aparecen? | CSV de PECmd → `parser-eztools`. |
| Amcache | ¿Qué rutas, hashes y fechas del inventario de aplicaciones se registraron? | CSV de AmcacheParser → `parser-eztools`. |
| AppCompatCache / ShimCache | ¿Qué rutas y metadatos de caché se registraron? | CSV de AppCompatCacheParser → `parser-eztools`. La presencia en caché no demuestra por sí sola ejecución. |
| `$MFT` | ¿Qué rutas y fechas del sistema de archivos se registraron? | CSV de MFTECmd → `parser-eztools`. |
| Accesos directos LNK | ¿Qué destinos, directorios de trabajo y fechas del acceso directo se registraron? | CSV de LECmd → `parser-eztools`. |
| SRUM (`SRUDB.dat`) | ¿Qué aplicaciones y usuarios tienen datos de uso de recursos o red? | CSV de SrumECmd → `parser-eztools`. Los totales de uso no demuestran por sí solos exfiltración. |

Otra vía admitida para estos artefactos es exportar resultados JSONL de Velociraptor con timestamp y metadatos de artefacto, para `parser-velociraptor`, o `json_line` de `psort` de plaso para `parser-plaso`. El esquema debe coincidir con [los contratos de los módulos](modules.md#parser-de-velociraptor): no se admite automáticamente cualquier salida de un colector. EZTools requiere los nombres de columna reconocidos y un timestamp utilizable; los campos no mapeados permanecen en el registro. Empieza por los eventos y correlaciona ejecución, persistencia, movimiento lateral y posible exfiltración, sin tratar un único artefacto como prueba concluyente.

Los [targets y módulos de KAPE](https://github.com/EricZimmerman/KapeFiles), [EZTools](https://ericzimmerman.github.io/) y [los artefactos de Velociraptor](https://docs.velociraptor.app/docs/artifacts/) describen la recogida y el procesamiento externo. Conserva los originales y selecciona las exportaciones procesadas para ingerirlas. Los parsers nativos de registro y `$MFT` quedan como trabajo futuro según demanda, con el auxiliar aislado descrito en [la hoja de ruta](roadmap.md#entregado-hasta-v05x). Está previsto [un parser de JSON de Volatility 3](https://github.com/ns2switch/irmind/issues/158); no se ingieren directamente imágenes de memoria.

## Un formato propio sin Rust

Abre `/parsers`, elige **Test definition** e introduce un TOML y un archivo de muestra pequeño. La vista previa muestra la confianza y hasta diez filas saneadas. No ingiere evidencia, crea casos ni contacta con un modelo. `/parsers test <definición> <archivo>` abre el mismo formulario con las rutas rellenadas; usa el formulario si contienen espacios.

Parte de uno de los [ejemplos](../examples/parsers/README.md). Cada definición contiene:

- `version = 1`, nombre en minúsculas y descripción breve.
- `input.format`: `csv`, `json`, `ndjson` o `regex`. CSV declara delimitador y cabecera. Regex usa capturas con nombre y el motor de Rust de tiempo lineal.
- `detect.header`, `detect.required_fields` o `detect.pattern`. La confianza va de 1 a 70, por debajo de los formatos nativos de alta confianza. En JSON, los campos son punteros JSON. Solo se analiza la muestra acotada.
- `mapping`: campo común a columna CSV, puntero JSON o captura regex. `time` es obligatorio. Son opcionales `host`, `user`, `process`, `command_line`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `action`, `outcome`, `account` y `region`. El resto del original se conserva en el registro.
- `timestamp.format`: `rfc3339`, `unix` en segundos decimales o un patrón de fecha de chrono. `timestamp.default_timezone` es `UTC`, `Z` o un desplazamiento fijo como `+02:00`. El desplazamiento del original tiene prioridad. Se conserva el texto temporal completo; los artefactos actuales conservan la precisión indicada por la fuente mediante microsegundos UTC y un resto en nanosegundos.
- `limits` opcional para reducir `record_bytes`, `depth`, `fields` y `records`. No permite superar 1 MiB por registro, profundidad 32, 1.024 campos JSON ni diez millones de registros. Cada fuente tiene un máximo de 50 GiB.

La definición no supera 64 KiB. Cada regex tiene como máximo 4 KiB de fuente y 1 MiB para la compilación y el DFA. La muestra de vista previa no supera 1 MiB. Los registros inválidos se cuentan y dejan hasta tres extractos acotados y escapados. Un error irrecuperable de estructura o límite de archivo detiene ese archivo. Nunca se ejecuta la entrada.

## Instalar, cambiar, desactivar y recuperar

Revisa primero la vista previa. Elige **Install definition**, comprueba nombre y SHA-256 y confirma **Sign and apply**. La aplicación firma la definición completa validada en la cadena operativa global, escribe de forma atómica con permisos privados y reinicia la sesión. No necesita un caso. Para cambiarla, instala la versión revisada mediante el mismo flujo; no edites archivos activos para evitar la aprobación.

Los archivos aceptados viven en `parsers/active/` dentro del directorio de datos privado y sus copias por hash en `parsers/archive/`. Un archivo ausente, cambiado, inválido o sin firma queda desactivado y visible en `/parsers`, sin impedir el arranque. **Restore approved file** restaura explícitamente la versión firmada. **Deactivate definition** firma la desactivación para futuras detecciones; las versiones históricas siguen disponibles para reconstruir. Un fallo de escritura tras firmar requiere restauración explícita, nunca aceptación silenciosa.

El hash de la definición forma parte de la versión del parser en el manifiesto existente. Reconstruir un caso usa esa versión exacta, incluso tras cambiarla o desactivarla. El manifiesto exportado conserva el hash; reconstruir en otra máquina requiere también la definición aprobada correspondiente. Verificar una exportación no ejecuta definiciones. Se rechazan enlaces simbólicos. Las escrituras temporales quedan dentro del directorio privado y se borran al terminar o fallar; el arranque limpia temporales huérfanos.

Los registros conservan taint y procedencia de fuente, parser y offset. El guard sanea vista previa, evidencia mostrada y contexto del modelo. Una definición no concede permisos ni cambia el techo de la organización. Mantén las respuestas esperadas de episodios sintéticos fuera del directorio de fuentes que ingieres.

### Tiempo de syslog clásico

RFC 3164 abre un formulario temporal antes de ingerir. Confirma el año del primer registro, el desplazamiento UTC fijo, si diciembre → enero incrementa el año y si la elección se aplica a un fichero o a toda la ingesta. Los campos empiezan vacíos. Otras fuentes verificadas del mismo host pueden sugerir el año y la zona; debes confirmarlos. IRMind nunca usa el reloj del equipo ni la fecha de modificación. Otros retrocesos de mes cuentan como registros inválidos. La elección queda firmada con la fuente. Consulta [el contrato y los límites de syslog](../development/syslog-parser.md).

### Exportaciones de Linux

Auth.log/secure clásico usa el mismo formulario temporal por ingesta que syslog. Journald conserva el instante original en microsegundos. Auditd agrupa registros acotados con el mismo nodo, instante y serial; los grupos incompletos se marcan como parciales. Los formatos de acceso HTTP estándar no incluyen el host del servidor: IRMind lo deja desconocido. Para formatos propios, adapta el [ejemplo declarativo de exportación HTTP](../examples/parsers/nginx-apache-custom.toml). El [contrato de Linux](../development/linux-parser.md) detalla los límites y los campos mapeados.

### Windows EVTX

Cada fuente EVTX admite hasta 4 GiB y 8.000.000 de registros. El auxiliar tiene un límite de 600 segundos por invocación, 4 MiB por frame y hasta 8 GiB de salida total, también limitada a 32 veces los bytes de entrada más 1 MiB. Alcanzar un límite rechaza el fichero completo con un diagnóstico explícito; no se publica una fuente parcial. En Windows se parsean las fuentes en orden canónico y sus hashes iniciales siguen calculándose en paralelo.

EVTX está disponible al compilar desde el código y en los paquetes firmados a partir de v0.2.0. Los paquetes v0.1.x no incluyen el auxiliar. El módulo experimental `parser-evtx` utiliza el auxiliar independiente `irmind-evtx`. Reconoce la cabecera y su checksum, no la extensión. Recibe un único descriptor de solo lectura. Los archivos locales y los objetos descargados en el spool privado del caso siguen la misma ruta.

Linux requiere kernel 5.13 o posterior, Landlock ABI 1 habilitado y seccomp sin privilegios. Bubblewrap no es obligatorio. Windows requiere que los servicios de firewall BFE y MpsSvc estén activos. Utiliza un AppContainer sin capacidades, una lista explícita de handles y un Job Object que termina los procesos al cerrarse. macOS aplica un perfil restrictivo. Una prueba de arranque comprueba que se deniegan lecturas ajenas, red y creación de procesos. Si falla, Preferencias explica por qué EVTX no está disponible; nunca se ejecuta sin aislamiento.

Security, System, PowerShell y Sysmon se normalizan al esquema común. Se conservan los campos no mapeados, la resolución temporal original de 100 ns y los offsets reales. Consulta el [diseño del auxiliar](../development/evtx-helper-design.md) para conocer los límites y las pruebas. Instala el auxiliar de la misma release verificada junto al ejecutable principal.

Entornos nativos probados: Ubuntu 22.04 y 24.04, Debian 12 (kernel 6.1), macOS 26.6.2 arm64 y Windows Server 2025. Fedora 44 solo se probó como espacio de usuario en contenedor. Windows 10/11 siguen como experimentales y sin confirmación; consulta el [issue de validación en Windows 11](https://github.com/ns2switch/irmind/issues/189) y la [evidencia exacta por plataforma](../development/evtx-helper-validation.md). Cada instalación debe superar las pruebas de aislamiento.

Al compilar desde el código, compila el ejecutable principal y fija `CARGO_TARGET_DIR` a `target` en la terminal y ejecuta `cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked` desde la raíz del repositorio. Usa el mismo directorio de destino para ambos workspaces. Mantén `irmind-evtx` (o `irmind-evtx.exe`) junto al ejecutable principal. El autotest nativo decide la disponibilidad; instalar el auxiliar nunca evita esa comprobación.

### Exportaciones de red

Zeek y Suricata son módulos experimentales compilados por defecto. La ingesta V3 actual conserva la precisión temporal y usan el perfil de partición por host. En Zeek, `sensor_host` identifica explícitamente el sensor; `host` de HTTP es un dominio. No se deduce el host de la IP ni del nombre del fichero. Ambos lectores cuentan las líneas sobredimensionadas y continúan con los registros posteriores. Consulta los [módulos](modules.md) para sus límites.

### Interpretación de Kubernetes y Falco

Las tablas incluidas de `mapping-kubernetes` clasifican el resultado de la API
mediante el código HTTP explícito; si falta, queda desconocido. Se distinguen el
actor y el usuario suplantado. Las observaciones de pod, nodo, espacio de nombres
y cuenta de servicio objetivo requieren el tipo de recurso explícito. Cada
cuenta de servicio conserva su propio espacio de nombres aunque acceda a otro.
La lista completa de IP de origen queda en el original; la primera dirección
comunicada se indexa como una afirmación de la fuente.

`mapping-falco` separa los selectores del host y de Kubernetes. Las reglas son
alertas de origen, no hallazgos confirmados por el analista. Los usuarios del
sistema del contenedor conservan ámbito de registro; no se convierten en
principales de la API. Un PID nunca implica una vida de proceso. Los IDs de
contenedor y los repositorios de imágenes son consultables con el ámbito de
clúster confirmado. Las etiquetas de imagen y los cuerpos de solicitudes de
pods quedan en el original. Los cuerpos completos de solicitudes y respuestas
no se proyectan automáticamente en la búsqueda.


`mapping-falco-kubernetes-audit` interpreta registros explícitos `source="k8s_audit"` y los campos documentados `ka.*`, separados de los registros syscall de host/Kubernetes. Mantiene actor y objetivo suplantado distintos y exige contexto de clúster confirmado. La alerta de origen sigue sin confirmar y con resultado desconocido. Solo mapea `container.privileged` si es un booleano explícito: ni el título de una regla ni una respuesta API 1xx de cambio de protocolo prueban ejecución exitosa. Los cuerpos de pods y RBAC quedan fuera del índice; los [métodos Kubernetes](skills.md) consultan los originales verificados necesarios, con el guard y los límites actuales.

### Cloud Audit Logs de GCP y GKE

El módulo experimental `parser-gcp-audit`, incluido por defecto, reconoce
LogEntry de Cloud Audit en JSON o NDJSON. `mapping-gcp-audit` interpreta valores
documentados de servicio y estado; `mapping-gke-audit` valida además las rutas
de recursos de GKE. Si falta el estado, queda desconocido. Las direcciones
ocultadas por el proveedor no son entidades IP. JSON genérico queda como opción
de baja confianza para estas exportaciones.

En GKE se confirma la identidad completa
`gke:projects/PROJECT_ID/locations/LOCATION/clusters/CLUSTER`. El formulario
muestra sugerencias de las etiquetas originales, sin aceptarlas en silencio.
Un clúster nuevo encontrado después requiere otra confirmación. Un contexto
manual contradictorio se rechaza. Divide las exportaciones de más de ocho
clústeres o que mezclen recursos de GKE y otros recursos de nube.

Ejemplos con acceso de lectura a logs configurado fuera de IRMind:

```sh
gcloud logging read 'logName:"cloudaudit.googleapis.com" AND NOT resource.type="k8s_cluster"' --project=PROJECT_ID --format=json > cloud-audit.json
gcloud logging read 'resource.type="k8s_cluster" AND protoPayload.serviceName="k8s.io"' --project=PROJECT_ID --format=json > gke-audit.json
```

Elige el proyecto y la ventana UTC autorizados para el caso y limita la
colección con los controles de exportación del proveedor. Exportar no concede
credenciales a IRMind. Consulta el [formato de auditoría](https://cloud.google.com/logging/docs/audit/understanding-audit-logs)
y los [filtros de GKE](https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging).

### Microsoft Entra ID

El módulo experimental `parser-entra`, incluido por defecto, reconoce logs de
Azure Monitor con `category` y `properties`, también bajo `records`, y filas
objeto de Log Analytics con `Type`. Cubre accesos interactivos, no interactivos,
de service principals e identidades administradas, y AuditLogs. Conserva
nanosegundos, nombres, tipos, offsets y detalles originales de MFA y acceso
condicional. Los envoltorios `value` de Graph y las respuestas posicionales
`tables/columns/rows` necesitan una conversión explícita; no son este formato.
El [mapeo](mappings.md#microsoft-entra-id) mantiene actor y objetivo separados.

### Exportaciones de Kubernetes gestionado

EKS: activa los logs de auditoría del plano de control y exporta los eventos del
stream de CloudWatch correspondiente mediante GetLogEvents. `parser-kubernetes`
reconoce `events[].message` y filas NDJSON con `timestamp` y `message`. Confirma
el ARN completo como `eks:arn:aws:eks:REGION:ACCOUNT:cluster/NAME`; el stream o
el nombre de archivo no definen por sí solos el clúster. La envoltura original y
el Event decodificado se conservan juntos, con el offset real de la fila exterior.
No se decodifican automáticamente payloads de suscripción base64/gzip.

AKS: configura una exportación de diagnósticos a Storage para kube-audit y/o
kube-audit-admin y descarga su JSON `records`. Se admite `properties.log`, así
como filas objeto de AzureDiagnostics con `Category`, `ResourceId` y `log_s`.
El resourceId completo se muestra como sugerencia y exige confirmación; IDs
contradictorios se rechazan y un clúster nuevo pide otra confirmación. No se
inventa un Event a partir de una fila posicional de AKSAudit. Exporta datos de
los streams y la ventana autorizados; confirma las identidades por archivo.

GKE: usa la exportación LogEntry de Cloud Audit descrita arriba; se detectan tanto
NDJSON como arrays JSON de gcloud. Conserva las etiquetas completas del clúster.
En un clúster propio, configura el backend de logs de auditoría del API server y
recoge sus Events JSON/NDJSON por una ruta autorizada de solo lectura. Consulta
los [formatos y las fuentes oficiales](../development/managed-kubernetes-transports.md).

## Exports de Microsoft 365 y Okta

Exporta una búsqueda de auditoría de Purview como CSV UTF-8 conservando `AuditData`,
o guarda los resultados de `Search-UnifiedAuditLog` en JSON con ese campo.
Los registros JSON de Management Activity API se ingieren directamente. Conserva
los originales: IRMind no ejecuta PowerShell ni pide acceso al tenant. El
decodificador extrae el objeto de auditoría original; sus parámetros siguen siendo
campos consultables no confiables. El buzón objetivo usa `MailboxOwnerUPN` si está
presente; una ruta de objeto no se interpreta como usuario. Se conserva la precisión
de `CreationTime`, que el formato documenta como UTC.

Exporta las respuestas de System Log de Okta como arrays JSON o un evento por línea.
Conserva `published`, `uuid`, `eventType`, `actor`, `target`, `client`,
`authenticationContext`, `securityContext` y el `debugContext` acotado. Los nombres
de evento y resultados se clasifican mediante tablas finitas. Los resultados
ausentes o desconocidos quedan como unknown. Las operaciones desconocidas siguen
siendo registros API consultables. Ninguno de estos módulos necesita credenciales.

Los arrays originales siguen siendo consultables. El esquema común escalar proyecta
el primer usuario objetivo; los objetivos distintos adicionales se conservan en el
original con un diagnóstico de cobertura. No se deduce un tenant del ISP ni del
nombre del fichero: los usuarios de Okta conservan ámbito por registro de origen.
M365 usa OrganizationId cuando es explícito. No se usa ámbito process_lifetime.

Fuentes: [esquema de Microsoft](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema),
[exportación de Purview](https://learn.microsoft.com/en-us/purview/audit-log-export-records),
[System Log de Okta](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/systemlog),
[catálogo de eventos de Okta](https://developer.okta.com/docs/reference/api/event-types/).

## Exports de GuardDuty

Ingiere el JSON de GetFindings, la salida `get-findings` de AWS CLI, un hallazgo
exportado de la consola o un evento de GuardDuty de EventBridge. El módulo
reconoce por separado las claves lowerCamelCase de la API y PascalCase del SDK/CLI,
sin renombrar los campos originales. Las envolturas `findings`/`Findings` se leen en
streaming; no se consume la primera línea como muestra.

Todos los tipos de hallazgo, incluidos los desconocidos, son alertas de origen sin
confirmar. Se conserva la severidad decimal exacta y los instantes de creación,
actualización y primera/última observación. La IP remota de una llamada API tiene
rol de origen; en conexiones de red se exige la dirección explícita. Una dirección
desconocida no inventa el rol. Los campos específicos del recurso siguen siendo
consultables. La ingesta local no crea ninguna conexión ni credencial de GuardDuty.

Fuentes: [esquema GetFindings](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html),
[salida CLI](https://docs.aws.amazon.com/cli/latest/reference/guardduty/get-findings.html),
[detalles de hallazgos](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-summary.html).

## Exportaciones de flujos de red en la nube

Exporta AWS VPC Flow Logs de S3 en texto o gzip, conservando la cabecera de columnas
de los formatos personalizados. También se admiten exportaciones de mensajes
CloudWatch `events`/`logEvents`. Sin cabecera, el analista debe elegir explícitamente
`parser-vpc-flow` y confirmar el formato estándar v2 de 14 campos. La TUI explica
este requisito al elegir parser; la detección desatendida no ingiere ese fichero
automáticamente. Usa cabecera para cualquier otro formato. Las columnas desconocidas
se conservan. Solo un `instance-id` explícito aporta el host de partición; una
interfaz no se interpreta como host.

Exporta el JSON de VNet o NSG de Azure desde su almacenamiento sin reescribir
`flows` ni `flowTuples`. VNet expresa el instante de la tupla en milisegundos Unix;
NSG, en segundos. Se reconocen VNet 2/4/5 y NSG 1/2. Una versión desconocida se
conserva una vez como registro de red sin clasificar, sin aplicar una disposición
conocida de columnas. Las tuplas expandidas no inventan offsets dentro de cadenas
JSON escapadas. La regla, el recurso y la tupla original siguen siendo consultables.
Una dirección MAC no se convierte en identidad de host.

Exporta las entradas de Cloud Logging de GCP conservando `logName`, `timestamp`,
`resource` y `jsonPayload.connection`; el nombre del log debe identificar
`vpc_flows`. Conserva `src_instance`, `dest_instance` y `reporter` para atribuir el
host observador. Un `DROPPED` explícito se mapea a fallo; su ausencia no demuestra
aceptación. Los bytes de carga útil estimados de GCP, los incrementos de Azure y
los contadores de AWS mantienen su significado propio: no son mediciones
intercambiables de facturación ni de captura de paquetes.

Las tres familias separan decodificador y mapeo. Las tablas finitas de campos y
resultados son declarativas; el código nativo valida los tipos numéricos y expande
las tuplas acotadas de Azure. Son exportaciones locales, no conectores en vivo.
Se mantienen límites, taint, hashes y procedencia firmada. Una entrada compacta o
gzip puede superar la cuota de tamaño normalizado aunque cumpla el límite de fuente. VPC usa una cuota
acotada de 32× los bytes descomprimidos, con recuento gzip previo de solo lectura
y reserva completa del grupo y de su ordenación. Los demás módulos conservan su
cuota. Un exceso rechaza la fuente/grupo, sin omitir registros silenciosamente.

Fuentes: [AWS](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html),
[Azure VNet](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview),
[Azure NSG](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview),
[GCP](https://docs.cloud.google.com/vpc/docs/about-flow-logs-records).

## Exportaciones de correo

Guarda el mensaje original como `.eml` desde el cliente de correo, con cabeceras
completas y estructura MIME; usa un mensaje por fichero o selecciona un directorio.
También se admiten volcados de solo cabeceras. IRMind no conecta con buzones, sigue
enlaces, abre adjuntos ni descomprime archivos. Conserva los originales: firmar su
hash en su ubicación no los copia implícitamente al caso.

El decodificador conserva el orden y los bytes de las cabeceras, incluidos los
saltos Received, From, To/Cc, Reply-To, Return-Path, Message-ID, Date,
Authentication-Results, X-Originating-IP y cabeceras del proveedor. La biblioteca
solo recibe el bloque acotado de cabeceras para interpretar buzones y parámetros.
IRMind controla el recorrido MIME. El texto y el código fuente HTML literal se
conservan por bloques; el HTML nunca se renderiza. Base64 y quoted-printable se
decodifican una vez como transporte. Las URLs HTTP(S) son valores literales: no se
redecodifican escapes de URL o entidades HTML ni se accede a la red. De los
adjuntos solo se exponen tamaño decodificado, tipo declarado, nombre y SHA-256.
Los mensajes `message/rfc822` adjuntos se tratan como archivos opacos.

Límites: 32 MiB por fuente, 64 KiB por bloque de cabeceras, 1.024 cabeceras totales,
16 contenedores multipart anidados y 256 partes MIME. El texto/HTML se divide en
bloques de hasta 256 KiB respetando UTF-8 y conservando los bytes originales.
Se conservan además hasta 4 KiB siguientes para el mapeo entre bloques. Superar un
límite estructural rechaza el mensaje completo, sin recortarlo silenciosamente.
El mapeo puro extrae hasta 127 URLs HTTP(S) por bloque de texto, de hasta 4.096
bytes cada una; valores no admitidos o excesivos producen un aviso de cobertura
y los bytes originales del cuerpo se conservan. UTF-8 y US-ASCII se decodifican como texto; otros
charsets conservan los bytes en hexadecimal con aviso de cobertura. Una
codificación de transporte no admitida o MIME mal formado produce un error claro.
Las cabeceras mínimas requieren elección del analista; el nombre del fichero no
prueba el formato.

El instante procede de Date solo con fecha válida y zona explícita admitida;
si falta, está duplicada o no es válida, queda desconocido. No se usa el reloj ni el mtime.
Una transformación MIME puede impedir indicar el offset original exacto de un
subregistro. En ese caso, toda la fuente omite uniformemente los offsets de
origen; las posiciones conocidas quedan en `source_byte_offset` y
`header_offsets` relativos. `decoded_body_offset` no se presenta como posición
del fichero. `mime_part_index` conserva la relación con la parte MIME.

El mapeo incluye reglas finitas de correo/ficheros en TOML; el código nativo adapta
las listas de buzones a observaciones validadas y conserva entidades de extracción
para URLs y para `email_message`, identificada por el hash de la fuente. El primer
From/To ocupa los roles tipados escalares; todas las direcciones siguen en las
cabeceras originales consultables y en pares de extracción acotados, con un aviso
para objetivos adicionales. Son afirmaciones de las cabeceras, no identidades
verificadas. Authentication-Results sigue siendo contenido no confiable: IRMind no
consulta DNS ni verifica SPF o DKIM, y no deduce éxito de ese campo. El resultado
queda desconocido. No se añade ninguna identidad de vida de proceso ni permiso.

Fuentes: [formato de mensaje](https://www.rfc-editor.org/rfc/rfc5322),
[MIME](https://www.rfc-editor.org/rfc/rfc2046),
[estado de autenticación declarado](https://www.rfc-editor.org/rfc/rfc8601).

## Exports de Microsoft Defender

Exporte Advanced Hunting como CSV o JSON, o conserve el JSON original de Streaming
API desde Event Hubs/almacenamiento. La envoltura usa `records`, la categoría
`AdvancedHunting-<tabla>` y `properties`; los exports de API pueden usar `Results`.
Se contemplan DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents,
DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents,
AlertInfo y AlertEvidence. Proyecte `Table` (o `$table`/`Type`) si las columnas no
identifican una tabla de forma inequívoca. El nombre del fichero no identifica la
tabla. Las estructuras o acciones desconocidas conservan los campos originales,
sin clasificación inventada.

El decodificador conserva nombres, tipos y precisión temporal. Timestamp de
Advanced Hunting es UTC; no se usa el reloj ni el mtime. CSV admite registros
multilínea de hasta 4 MiB/1.024 campos. JSON usa el lector común acotado, incluidos
los documentos cuya primera línea supera 4 MiB. Se mantienen los límites comunes
por fuente y número de registros.

Clasificación, resultados explícitos y roles proceden de tablas TOML incluidas.
El código nativo solo selecciona la tabla y avisa de valores opcionales no
admitidos; no interpreta acciones por heurísticas. DeviceId determina la partición
por host. Procesos y padres usan ámbito de registro, también si se reutiliza el
PID; ProcessUniqueId se conserva en el original y no se usa como vida de proceso.
ProcessGuid de Sysmon sigue siendo la única fuente de ese ámbito. La acción de
entrada documentada invierte los roles de red; acciones desconocidas conservan
los extremos originales sin adivinar la dirección. ConnectionSuccess describe el
transporte y no demuestra que Network Protection permitiera la petición. AlertInfo
y AlertEvidence son alertas de origen, nunca hallazgos confirmados por el analista.

Fuentes: [tablas](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables),
[envoltura de Streaming](https://learn.microsoft.com/en-us/defender-xdr/streaming-api-event-hub),
[proceso](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table),
[red](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicenetworkevents),
[interpretación de Network Protection](https://learn.microsoft.com/en-us/defender-endpoint/network-protection).

## CrowdStrike Falcon Data Replicator

`parser-fdr` decodifica líneas JSON nativas descargadas del feed S3 de FDR, en
texto o gzip. Exporta o descarga con las herramientas del proveedor e ingiere el
fichero local; este parser no consulta CrowdStrike ni descarga objetos S3. La
[guía FDR del proveedor](https://www.crowdstrike.com/wp-content/uploads/2021/06/CrowdStrike-Falcon-Data-Replicator-Technical-Add-On-Guide.pdf)
describe el feed y sus filtros. Conserva `event_simpleName`, `timestamp`, `cid`,
`aid` y los campos originales. `timestamp` nativo usa milisegundos; los demás
instantes originales conservan su precisión.

El módulo separado `mapping-fdr` usa definiciones TOML finitas para procesos,
conexiones y escuchas IPv4/6, DNS, inicios de sesión correctos/fallidos,
PeFileWritten y cambios de registro/ASEP. Los
[dashboards FDR del proveedor](https://library.humio.com/integrations/integrations-crowdstrike-fdr-crowdstrike-fdr.html)
documentan las uniones de proceso/contexto y esos campos. Los tipos sin regla
conservan su original consultable, sin clasificación inventada; las variantes de
renombrado sin contrato confirmado quedan sin clasificar. Un valor opcional no
válido produce un aviso de cobertura. Ninguna detección confirma un hallazgo.

Los ID nativos de Falcon usan `cid` más `aid`; los PID siguen limitados al
registro y no se infiere una vida de proceso como en Sysmon. `aid` fija la
partición de host con su desbordamiento acotado; `cid` es identidad, no cuenta de
nube. En gzip no se inventan offsets físicos. Se mantienen los límites de línea,
profundidad/campos JSON, fuente y cancelación. La
[admisión de FDR comprimido](development/fdr-compressed-admission.md) describe el
techo decodificado exclusivo de FDR, la validación de CRC y la reserva de disco.

La muestra sintética de [rendimiento FDR](../development/benchmark-data/fdr-v055.json)
usa 1 GiB sin relleno en build release: 2.329.158 registros, 63,340 s y
16,167 MiB/s; la verificación posterior pasa fuera del tiempo medido. Es una
muestra local, no una comparación de aceleración. El fuzzing ASan completa
1.121.240 ejecuciones en 601 s sin fallos. Las pruebas con 1/64/1.024/1.025 hosts
mantienen el límite de 64 y conservan los valores originales en el desbordamiento.

## Exports de macOS

Exporta desde un Mac un intervalo acotado con el comando del sistema `log`.
Elige el estilo de array JSON o de registros JSON por línea. El segundo
ejemplo lee un archivo existente. Guarda el export y registra por separado el
host y el intervalo de recogida. IRMind
lee el export JSON. Los formatos binarios nativos `.logarchive` y `tracev3`
quedan fuera de la entrada del parser. [Guía de Apple para consultar Unified Log](https://developer.apple.com/documentation/os/viewing-log-messages)

```sh
log show --last 1h --timezone UTC --style ndjson > unified.ndjson
log show --archive case.logarchive --last 1h --timezone UTC --style json > unified.json
```

Consulta los nombres de eventos de Endpoint Security que admite la versión de
macOS del recolector. El analista ejecuta `eslogger` como superusuario desde una
terminal autorizada para acceso total al disco y detiene la recogida al final del
intervalo. IRMind lee el JSON guardado y conserva las versiones del esquema y del
mensaje. IRMind no ejecuta los recolectores. [Demostración de eslogger de Apple](https://developer.apple.com/videos/play/wwdc2022/110345/)

```sh
man eslogger
sudo eslogger exec fork exit open create rename unlink openssh_login openssh_logout > endpoint.ndjson
```

Las tablas incluidas interpretan notificaciones del esquema 1. Cubren inicio y
fin de procesos, actividad de ficheros, autenticación, inicio y cierre de sesión,
SSH, sudo y su, montajes, TCC, XProtect y Gatekeeper cuando el sistema emite esos
eventos. Los resultados de acceso explícitos se distinguen como éxito, fallo o
desconocido. Los PID conservan su ámbito de registro y los mensajes de Unified Log
se conservan como evidencia original. Los tipos y esquemas desconocidos
mantienen sus campos originales. Las detecciones de XProtect son hallazgos sin
confirmar. El instante conserva la precisión exportada y el resto en
nanosegundos cuando está disponible.

## Reports API de Google Workspace

Recoge un intervalo acotado con `activities.list` de la Reports API v1 del
Admin SDK, con una identidad autorizada para leer la auditoría. Guarda cada
página de respuesta como JSON. También puedes guardar las actividades
individuales como array JSON o NDJSON. Registra el intervalo, la aplicación
consultada y la paginación con los originales. IRMind lee los ficheros
guardados en local. [Referencia de la Reports API de Google](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list)

Cada actividad produce un registro por miembro de `events`, hasta un máximo
de 128. El offset apunta a la actividad original y el ordinal distingue los
registros en la fuente indexada. El ID, el actor y los arrays originales de
parámetros de cada evento quedan en la evidencia.

Los mapeos incluidos cubren resultados de login y SAML, cambios administrativos
y de cuentas, consentimientos OAuth, descargas y compartición de Drive, y
subtipos de entrega de Gmail cuando están presentes. Distingue los reenvíos
manuales (10) y automáticos (11) con el código nativo de Gmail. Los eventos
desconocidos conservan sus datos originales y se pueden buscar. [Referencia de actividad de Gmail](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gmail)

## Registros de depuración de DNS Server

Activa el [registro de depuración de paquetes](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics#debug-logging) en el Administrador de DNS. Copia como evidencia el texto de resumen de paquetes. El decodificador espera UTF-8 o ASCII y el formato inglés mes/día/año con AM/PM. Si el día inicial puede interpretarse como mes, confirma el parser tras comprobar el formato de fecha del servidor. Confirma al ingerir el año del primer paquete y el desfase UTC fijo. Para los paquetes siguientes se usa el año escrito en cada línea. Las peticiones tienen resultado desconocido y las respuestas usan los códigos DNS conocidos. El extremo remoto de un paquete recibido es el origen y el de uno enviado es el destino. Los resúmenes originales se pueden buscar. Las exportaciones EVTX del canal analítico DNS usan el parser EVTX aislado y el mapeo de consulta, respuesta y fallo de los eventos 256–258. Los campos nativos QTYPE, RCODE y los bytes del paquete permanecen en los datos originales.

Para registros de depuración grandes, conserva el original e ingiere ficheros
rotados más pequeños o copias verificadas partidas entre líneas de paquetes
completas. Cada parte necesita la cabecera de creación nativa. Confirma el
formato de fecha y el desfase horario al ingerir cada parte. Si la fuente supera
el límite de normalización, el error indica cuántos bytes se necesitaban como
mínimo en el punto donde se detuvo. IRMind rechaza el fichero completo.

## IIS W3C

(Administrador de IIS → Registro) Selecciona [el formato W3C](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/logfile/). Incluye fecha, hora, método HTTP, ruta, consulta, estado y las direcciones del cliente y del servidor. Copia los registros originales con sus directivas `#Fields`. Los registros usan UTC. Cada directiva válida define las columnas siguientes. Los campos personalizados se pueden buscar y la consulta se conserva tal como aparece.

Para registros IIS grandes, conserva el original e ingiere ficheros rotados
más pequeños o copias verificadas partidas entre registros completos. Repite
en cada parte la directiva `#Fields` aplicable. Si se supera el límite de
normalización, IRMind rechaza todo el fichero e indica los bytes mínimos
necesarios al detenerse.

## Route 53 VPC Resolver

Configura los [registros de consultas de VPC Resolver](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html) y exporta los eventos JSON originales desde el destino de los logs. Ingiere objetos, arrays o NDJSON. El decodificador conserva la precisión de `query_timestamp`. El mapeo permite filtrar por DNS y por resultado para los códigos de respuesta conocidos. Los [registros de respuesta nativos](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-example-json.html) se pueden buscar en sus campos originales. AWS proporciona tipo, clase y RDATA para cada respuesta.

## Auditoría de GitHub

Desde la auditoría de la organización o empresa, selecciona un intervalo acotado
y exporta JSON o CSV. Para el streaming, recoge los registros JSON nativos en el
destino configurado. Guarda las descargas originales y el alcance de recogida.
Descomprime una entrega comprimida antes de ingerir su NDJSON como fuente
separada. La presencia de IPs de origen y eventos de Git depende del export y
de la configuración de auditoría. [Exportación de auditoría de organización](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization) · [Exportación de auditoría de empresa](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/exporting-audit-log-activity-for-your-enterprise)

El módulo conserva el instante, actor, organización, repositorio, agente de
usuario e IP de origen cuando están presentes. Mapea cambios de roles y
accesos, tokens y claves, transferencias, visibilidad y borrados de repositorios,
descargas de Git y políticas y metadatos de secretos de Actions. Los valores
`hashed_token`, `token_scopes` y `programmatic_access_type` quedan como evidencia
original. El decodificador no llama a GitHub y mantiene las acciones desconocidas
en la búsqueda. [Referencia de eventos de auditoría de GitHub](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization)
