Traducción de docs/configuration.md en el commit f47845c5b47a86bf6f838b7fd67fdd73d2047d41; si hay diferencias, prevalece la versión en inglés.

# Configuración

Esta página es para quienes preparan una evaluación controlada. Explica el alcance de los casos, la política, los ajustes no secretos y la selección del backend. Los permisos de los conectores están en [módulos](modules.md).

## Salida del modelo

IRMind no fija un tope propio de tokens de salida para el agente principal,
subagentes, resúmenes ni compactación. Envía el máximo nativo conocido del modelo;
si es desconocido y opcional, omite el parámetro. Si la API lo exige, no inicia la
petición y explica cómo configurarlo en `/settings model`.

En la revisión de `/settings model`, **Model output profile** permite escribir el
máximo nativo y elegir si la API compatible/local exige el parámetro. Vacío
significa desconocido. Son valores no secretos firmados del módulo:
`IRMIND_MODEL_MAX_OUTPUT_TOKENS` y `IRMIND_MODEL_OUTPUT_REQUIRED` para APIs
compatibles. No sirven para introducir un presupuesto de respuesta más bajo.
Los perfiles incluidos solo se aplican al proveedor y modelo exactos, nunca a un
modelo local que reutilice el nombre. La ventana de contexto no es el máximo de
salida.

El presupuesto se comprueba entre peticiones. Con saldo positivo, la respuesta
termina aunque lo supere; se registra todo el consumo informado y la siguiente
petición queda bloqueada. `/budget` permite revisar o ampliar la asignación
firmada dentro del techo de la organización. El hijo reserva antes de empezar
la entrada acotada más el máximo conocido del modelo. Si no cabe o se desconoce,
no empieza; una respuesta en curso no se recorta para ajustarla al saldo.

Cuando el proveedor termina por `length` o `max_tokens`, se muestra **The model
reached its maximum output** y se intenta una sola continuación sin herramientas,
si caben el presupuesto y las rondas. Ambas llamadas se cobran y se muestran en
una sola respuesta continua. Un segundo corte no provoca más reintentos.
`/continue` queda para el límite de rondas o el presupuesto agotado.

Se conservan los límites de seguridad: stream de 2.000.000 bytes, entrada del
guard de 1.000.000 bytes y frame firmado de 1 MiB, contando metadatos y
codificación. Si el texto no cabe, se conserva un prefijo UTF-8 y se indica
**Truncated by IRMind's security limit**. Tokens y bytes no son equivalentes.
El resumen que recibe el principal sigue limitado a 16 KiB; la respuesta del
hijo que cabe en el frame se conserva completa en su rama. Cancelación, plazos,
protocolo inválido y fallos de recursos siguen siendo interrupciones explícitas.
Las fuentes oficiales de los perfiles figuran en la [versión inglesa](../configuration.md#model-output).

**Probar conexión** usa el borrador actual sin guardar, incluido su máximo de
salida. La prueba no guarda ajustes ni credenciales ni firma una operación de
configuración.

### Diagnóstico local de SSE

Antes de iniciar IRMind, asigna a `IRMIND_SSE_DIAGNOSTICS_FILE` la ruta de un
fichero nuevo. En PowerShell, por ejemplo, ejecuta
`$env:IRMIND_SSE_DIAGNOSTICS_FILE = "$PWD/irmind-provider.sse"` antes de abrir
la TUI. Los adaptadores compatibles con OpenAI guardan una captura cuando
finaliza o falla la primera respuesta que haya recibido bytes. Quita la
variable para desactivarlo. Si el fichero ya existe, se conserva. Elige otro
nombre para capturar una petición más.

La captura acotada conserva el orden y la forma de los frames SSE y el uso
de tokens informado. Sustituye u omite respuestas, razonamiento, argumentos,
identificadores, campos desconocidos y bytes mal formados. Los mensajes de
petición, cabeceras HTTP y credenciales quedan fuera de la captura. El fichero
es local y queda fuera del caso y su exportación. Por defecto está desactivado.

## Alcance del caso

Un caso puede ser solo local. Para permitir lecturas remotas, el formulario de caso nuevo pide fuentes, cuentas, proyectos, hosts, prefijos de objetos y una ventana UTC. Un prefijo tiene la forma `s3://bucket/AWSLogs/123/`, `gs://bucket/export/` o `az://contenedor/export/`. Añádelo con `/scope add object <URI>`; el ID de fuente también debe estar en el alcance. Los demás destinos usan `/scope add project <id>` (o `source`, `account`, `host`). Amplía la ventana con `/scope window <from> <to>`. El analista firma los cambios. Las lecturas de objetos fuera del prefijo del caso o de la organización se deniegan. La codificación para automatización está en la [referencia de la CLI](../development/cli.md).

## Archivo de política

Pasa `--policy policy.toml` o define `IRMIND_POLICY`. El archivo [policy.toml](../../policy.toml) del repositorio es un ejemplo versionado:

```toml
version = 1
max_tool_calls_per_case = 1000
max_model_rounds_per_turn = 25
max_model_result_bytes = 10000
max_model_tokens_per_case = 2000000
max_object_read_bytes = 1073741824
max_object_bytes_per_case = 536870912000
object_transfer_approval_bytes = 67108864
denied_tools = []

[scope]
sources = ["demo"]
accounts = ["123456789012"]
projects = []
hosts = []
objects = ["s3://audit-bucket/AWSLogs/123/CloudTrail/"]
from = "2026-10-23T00:00:00Z"
to = "2026-10-23T23:59:59Z"
```

La tabla opcional `[scope]` fija un techo estricto para las lecturas remotas de todos los casos. Puede contener cuentas, proyectos, hosts y prefijos de objetos, además de fuentes y una ventana UTC. Una lectura de objetos fuera del prefijo del caso o del techo de la política se deniega, incluso con aprobación. Otras lecturas fuera del caso pueden requerir aprobación; fuera del techo se deniegan. Los casos nuevos y los cambios de alcance no pueden superar el techo. Si una política nueva reduce el alcance de un caso existente, sus lecturas usan la intersección y la TUI muestra un aviso. El conector AWS actual exige una cuenta; las consultas por proyecto estarán disponibles cuando exista un conector que las admita. La política puede restringir las reglas fijas de las herramientas, pero no habilitar acciones denegadas. El enriquecimiento externo requiere aprobación firmada del analista; la contención está deshabilitada. Los campos desconocidos causan un error.

`max_model_rounds_per_turn` vale 25 por defecto si se omite y no puede superar 100. Al alcanzar el límite, IRMind pide un resumen final sin herramientas y ofrece `/continue`. Los límites de llamadas y tokens siguen aplicándose a todo el caso.

## Asignaciones y consumo del caso

Hay dos niveles. `policy.toml` fija el techo de la organización; el analista no
puede superarlo desde la TUI, mediante una aprobación ni desde una skill.
`/settings limits` elige valores por defecto firmados para los **casos futuros**.
Dentro de un caso abierto, `/budget` muestra la asignación, el techo actual y el
consumo, y permite editar los tokens, las llamadas y los bytes de nube reservados.
Los campos están rellenados: Tab cambia de campo, Enter abre la revisión y las
flechas o un número seguido de Enter confirman explícitamente la firma del
analista. Esc cancela. Aumentar la asignación exige esa confirmación. El consumo
nunca se reinicia. Un caso sellado no puede cambiar su asignación. Una política
más restrictiva reduce de inmediato el techo efectivo de una asignación existente.

Los valores por defecto son 2.000.000 de tokens y 1.000 llamadas, recortados al
techo de la organización si es menor. Los máximos absolutos siguen siendo
10.000.000 de tokens y 10.000 llamadas. Los límites de nube y las aprobaciones de
transferencia conservan sus valores. Nunca se reescriben los archivos de política
existentes. Las [mediciones](https://github.com/ns2switch/irmind/blob/a0dcfd1/docs/development/case-budget-measurements.md)
locales con el modelo guionizado cubren las 13 skills incluidas y un caso de seis
turnos; las estimaciones de planificación por bytes no son mediciones de
facturación del proveedor.

Al 80 %, la barra de estado avisa y señala `/budget`. Al agotarse el presupuesto,
el turno conserva sus resultados y termina con un resumen y los límites
consumidos y efectivos. Si quedan tokens, pide un resumen sin herramientas. Si
no quedan, o la compactación del historial no cabe en su reserva, muestra un
resumen local sin otra petición al modelo. Revisa `/budget` antes de `/continue`,
o solicita al administrador que cambie el techo si este impide el aumento. El
modelo no puede aplicar cambios de asignación.

El uso del proveedor llega después de cada petición; el último recibo puede
superar la asignación antes de detener las llamadas siguientes. Los topes de la
cuenta del proveedor siguen siendo útiles para la facturación.

Los tokens incluyen toda entrada y salida declarada por el proveedor: historial
reenviado, resultados de herramientas, texto de skills, compactación y resúmenes
finales. Si falta información de uso, se indica que no está disponible y cualquier
subtotal informado se muestra como un mínimo, nunca como un cero medido. El coste
solo aparece cuando hay información de uso y precios configurados. Las llamadas
incluyen los despachos firmados y las lecturas acotadas de skills. Los bytes de
nube son **reservas** de lecturas de objetos firmadas, incluidas las transferencias
fallidas o canceladas, como en la aplicación del límite; no representan tráfico
exacto de red.

Los valores no secretos se guardan en `config.toml`, por ejemplo:

```toml
[case_budget_defaults]
model_tokens = 2000000
tool_calls = 1000
cloud_bytes = 536870912000
```

La asignación inicial se firma atómicamente al crear el caso. Los cambios
posteriores son registros del caso firmados por el analista; cambiar los valores
por defecto no modifica casos existentes. Un caso sin asignación inicial pide
confirmarla explícitamente con `/budget` antes de iniciar trabajo con el modelo o
las herramientas. Se añade una asignación firmada y se conserva todo el consumo
anterior, sin reescribir evidencia ni reiniciar el uso. Abrir un caso o cambiar
los valores por defecto nunca inicializa su asignación en silencio.

## Ajustes no secretos

La TUI guarda los ajustes no secretos en `config.toml` dentro del [directorio de datos estándar](platforms.md#datos-y-terminal). La compilación normal incluye todos los módulos de producto actuales y ambos llaveros, pero no activa ninguno. `/settings` reúne Modelo, Conectores, Llavero, Preferencias y Límites; `/settings model` abre directamente el modelo. En Conectores, las flechas eligen un módulo, Tab elige un parámetro y Enter lo edita en un campo visible. El primer carácter escrito o pegado sustituye el valor predeterminado; Enter lo acepta y Ctrl+U lo borra. La URL se recorta y las barras repetidas de la ruta se normalizan antes de validarla. Las credenciales se escriben en campos enmascarados de Llavero. La sesión se recarga tras un cambio. La salida de datos del equipo requiere confirmación explícita y firmada. Una compilación mínima usa `--no-default-features --features keystore-file` porque siempre debe existir un backend de firma y secretos.

Para Splunk, MISP, CrowdStrike, SentinelOne y un servicio S3 compatible, `/settings connectors` admite un archivo PEM de CA opcional. IRMind muestra y firma su huella SHA-256 junto con la ruta. El PEM se añade a las raíces del sistema; la comprobación del nombre del servidor sigue activa. Al iniciar el conector se vuelve a comprobar el hash, por lo que sustituir el archivo exige otra aprobación. Borra la ruta para retirar esa CA. No guardes una clave privada en el archivo.

`resume_last_case` y `show_hints` valen `true` por defecto. Tras arrancar, la TUI reabre el último caso abierto que se usó solo si verifica su cadena de custodia. Un caso sellado o eliminado deja la pantalla de inicio; un fallo de verificación aparece allí como aviso. Usa `/settings preferences` para cambiar la reanudación, las pistas de contexto, el ratón o el tema (`auto`, `light`, `dark`). La referencia privada `last-case` se guarda junto a `config.toml` y no forma parte de la custodia. La automatización CLI no reanuda casos.

Usa **Maximum parallel workers** en `/settings preferences` para limitar la decodificación de fuentes locales y las lecturas paralelas de Parquet. Deja el campo vacío para usar un trabajador menos que las CPU lógicas disponibles, con un mínimo de uno. Un valor explícito de `max_parallel_workers` (1–256) puede usar todas las CPU disponibles. El presupuesto local de memoria puede reducir el número efectivo. La preferencia se firma y se aplica al recargar la sesión. El orden de las fuentes y los límites de cada artefacto se mantienen.

### Barra de estado declarativa

Abre **Status bar** en `/settings preferences`. Elige **Minimal**,
**Investigation** (por defecto) o **Costs**; después activa segmentos, cambia su
orden, asigna una prioridad de 0 a 100 y un color del tema, y edita el separador.
La vista previa usa valores de ejemplo identificados como tales. Solo **Save
and sign** guarda la plantilla como operación global firmada. **Restore
default** también es una vista previa hasta que guardes. Esc vuelve sin guardar.

La lista cerrada de segmentos incluye: título, severidad y estado de sello del
caso; modelo y proveedor; tokens usados, presupuesto y porcentaje; tokens leídos
y escritos en caché; llamadas y su presupuesto; bytes de nube y su presupuesto;
coste estimado; subagentes activos; aprobaciones pendientes; detecciones; fuentes
ingeridas; perfil de los llaveros de firma y secretos; directorio de datos;
versión de IRMind; reloj UTC; y actividad. La caché desconocida se indica como
no disponible y el coste sin precios se omite; nunca se presentan como cero.
Los contadores de caché solo aparecen cuando el proveedor los informa. Las
reglas de consumo y presupuesto se mantienen.

El orden de la plantilla es el de presentación. En anchos reducidos, incluidas
80 columnas, se ocultan primero los segmentos con menor prioridad; en un empate
se conserva el anterior. El último segmento se abrevia con puntos suspensivos
si hace falta. Los títulos y otros textos externos se escapan para el terminal,
los colores respetan `NO_COLOR` y los avisos de alcance y presupuesto siguen
visibles independientemente de la plantilla.

La configuración opcional `status_bar` usa `version = 1`, un separador de hasta
cuatro caracteres imprimibles y como máximo una entrada por segmento. Los colores
pertenecen al conjunto cerrado del tema: `text`, `muted`, `accent`, `warning`,
`error`, `success`. Se rechazan segmentos desconocidos, duplicados y caracteres
de control. La plantilla no ejecuta scripts, comandos de shell ni programas
externos.


Para automatización, el orden es **flag de CLI > variable de entorno > config.toml > valor por defecto**. Un override solo dura esa ejecución; la TUI no lo sustituye en silencio. El archivo contiene IDs de módulos, modelos, URLs, fuentes, índices, regiones y precios opcionales, pero nunca credenciales ni passphrases. Se rechazan los campos desconocidos o secretos. Ejemplo:

```toml
version = 1
llm_module = "llm-openai-compatible"
mouse_capture = false # opcional: permite seleccionar texto con el terminal
resume_last_case = true
show_hints = true
theme = "auto"

[modules.llm-openai-compatible.values]
IRMIND_MODEL = "modelo-local"
IRMIND_LLM_BASE_URL = "http://127.0.0.1:11434/v1/"

[modules.siem-splunk]
enabled = false

[modules.siem-splunk.values]
IRMIND_SPLUNK_URL = "https://splunk.example.invalid/"
IRMIND_SPLUNK_SOURCE_ID = "demo"
IRMIND_SPLUNK_INDEX = "security"
```

El ejemplo describe el formato guardado. Cámbialo desde la TUI. Si falta el archivo o difiere de la última versión firmada, el arranque se detiene antes de abrir casos. La TUI permite restaurar la versión aprobada o revisar los campos cambiados y firmar el archivo actual si es válido. Nunca acepta ni restaura en silencio. Siempre rechaza los campos secretos. La automatización sale con instrucciones para resolver la diferencia en la TUI.

Si un flag o una variable de entorno cambia el modelo, un destino, un conector, una fuente, un índice o una región, la TUI muestra primero el valor efectivo y el guardado. Aceptar firma los overrides de esa sesión y deja un indicador visible. Rechazar usa la configuración guardada. La CLI de automatización acepta los overrides efectivos sin diálogo y los registra en la cadena global firmada antes de ejecutarse.

Estas variables de entorno prevalecen sobre los campos públicos correspondientes. Usa solo valores acordes con el destino aprobado y el alcance del caso.

| Variable | Función |
| --- | --- |
| `IRMIND_HOME` | Directorio de datos local opcional. |
| `IRMIND_POLICY` | Ruta del archivo TOML de política. |
| `IRMIND_THEME`, `NO_COLOR` | Sobrescriben el tema de la TUI (`light` o `dark`) o desactivan el color durante la sesión. |
| `IRMIND_LLM_MODULE` | Selección explícita del módulo de modelo; alternativa a `--llm-module`. |
| `IRMIND_ENABLE_SPLUNK`, `IRMIND_ENABLE_AWS`, `IRMIND_ENABLE_CROWDSTRIKE`, `IRMIND_ENABLE_SENTINELONE`, `IRMIND_ENABLE_MISP`, `IRMIND_ENABLE_VIRUSTOTAL` | Overrides temporales para activar conectores (`true` o `false`). |
| `IRMIND_ENABLE_STORAGE_S3`, `IRMIND_ENABLE_STORAGE_GCS`, `IRMIND_ENABLE_STORAGE_AZURE` | Overrides temporales para activar lectores de objetos (`true` o `false`). |
| `IRMIND_MODEL`, `IRMIND_LLM_BASE_URL` | Modelo compatible con OpenAI y URL base opcional. |
| `IRMIND_ANTHROPIC_MODEL`, `IRMIND_DEEPSEEK_MODEL`, `IRMIND_OPENROUTER_MODEL` | IDs de modelos de esos proveedores. |
| `IRMIND_SPLUNK_URL`, `IRMIND_SPLUNK_SOURCE_ID`, `IRMIND_SPLUNK_INDEX`, `IRMIND_SPLUNK_ACCOUNT_FIELD`, `IRMIND_SPLUNK_ALERT_ID_FIELD` | Servicio Splunk, índice acotado y campo opcional del ID de alerta (por defecto `alert_id`). |
| `IRMIND_SPLUNK_EVENT_NAME_FIELD`, `IRMIND_SPLUNK_USER_FIELD`, `IRMIND_SPLUNK_SOURCE_IP_FIELD`, `IRMIND_SPLUNK_HOST_FIELD` | Nombres opcionales de los cuatro campos de búsqueda estructurada; por defecto `eventName`, `user`, `sourceIPAddress` y `host`. |
| `IRMIND_AWS_SOURCE_ID`, `IRMIND_AWS_REGION`, `IRMIND_AWS_ROLE_NAME` | Fuente, región y rol de solo lectura de AWS. |
| `IRMIND_STORAGE_S3_SOURCE_ID`, `IRMIND_STORAGE_S3_BUCKET`, `IRMIND_STORAGE_S3_REGION`, `IRMIND_STORAGE_S3_ENDPOINT` | Fuente, bucket, región y URL HTTPS opcional de S3. |
| `IRMIND_STORAGE_GCS_SOURCE_ID`, `IRMIND_STORAGE_GCS_BUCKET`, `IRMIND_STORAGE_GCS_ENDPOINT` | Fuente, bucket y URL HTTPS opcional de GCS. |
| `IRMIND_STORAGE_AZURE_SOURCE_ID`, `IRMIND_STORAGE_AZURE_ACCOUNT`, `IRMIND_STORAGE_AZURE_CONTAINER`, `IRMIND_STORAGE_AZURE_CLIENT_ID`, `IRMIND_STORAGE_AZURE_TENANT_ID`, `IRMIND_STORAGE_AZURE_ENDPOINT` | Fuente, cuenta, contenedor, identidad del principal de servicio y URL HTTPS opcional de Azure Blob. |
| `IRMIND_CROWDSTRIKE_URL`, `IRMIND_CROWDSTRIKE_SOURCE_ID` | Servicio y fuente de CrowdStrike. |
| `IRMIND_SENTINELONE_URL`, `IRMIND_SENTINELONE_SOURCE_ID`, `IRMIND_SENTINELONE_SITE_ID` | Servicio, fuente y sitio de SentinelOne. |
| `IRMIND_MISP_URL`, `IRMIND_MISP_SOURCE_ID` | Servicio y fuente interna de MISP. |
| `IRMIND_INPUT_MICROUSD_PER_MILLION`, `IRMIND_OUTPUT_MICROUSD_PER_MILLION` | Estimación opcional del precio del modelo; define ambas. |

VirusTotal no tiene ajustes no secretos. Las features y los interruptores de activación están en [módulos](modules.md).

## Backends de firma y secretos

La TUI guarda la selección explícita del primer arranque en `keystore.toml`, dentro del directorio de datos:

```toml
[keystore]
signer = "file"
secrets = "file"
analyst_key_fingerprint = "<huella mostrada por IRMind>"
```

Elige `os` o `file` por separado para cada capacidad. `os` usa Keychain, Credential Manager o Secret Service. `file` guarda ambas capacidades en `keystore.enc`, pide una passphrase sin eco una vez por sesión y funciona por SSH. Emplea Argon2id y XChaCha20-Poly1305; sigue siendo necesaria una passphrase sólida y una máquina protegida. Si el backend elegido no se abre, IRMind falla cerrado y ofrece un cambio explícito en la TUI. Nunca cambia en silencio.

Escribe `/settings keystore` para ver los backends y comprobar qué credenciales existen. Con Tab, flechas y Enter puedes añadir o borrar credenciales, cambiar la passphrase, migrar un backend o reiniciar la sesión. La migración conserva la huella pública del analista y deja un evento operativo global firmado incluso antes del primer caso. Tras cambiar una credencial, los conectores activos pueden conservar el valor anterior; elige Reiniciar sesión en esta sección. No escribas secretos en el texto del caso.

La CLI lee la passphrase del terminal sin eco o de un descriptor abierto explícitamente con `--passphrase-fd <FD>`; Windows admite actualmente solo el descriptor `0`. IRMind no acepta passphrases ni secretos por argumentos o variables de entorno. `verify-export` no necesita desbloquear ningún backend.

## Nombres de credenciales

No pongas credenciales en variables de entorno. Introdúcelas en la vista de llavero de la TUI con el nombre de campo indicado; IRMind nunca muestra su valor. Con `os`, el servicio es `irmind-module` y la cuenta es ese campo. Con `file`, cada campo queda cifrado en un registro.

| Cuenta en `irmind-module` | Uso |
| --- | --- |
| `OPENAI_API_KEY` | Solo el servicio oficial de OpenAI. |
| `IRMIND_LLM_API_KEY` | Otro servicio compatible con OpenAI. |
| `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY` | Proveedores LLM correspondientes. |
| `IRMIND_SPLUNK_TOKEN` | Token de Splunk de solo lectura. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | Credenciales de un rol AWS dedicado; token de sesión cuando corresponda. |
| `GCP_SERVICE_ACCOUNT_JSON` | Clave de la cuenta de servicio GCS del bucket autorizado. |
| `AZURE_CLIENT_SECRET` | Secreto del principal de servicio de Azure Blob para el contenedor autorizado. |
| `IRMIND_CROWDSTRIKE_CLIENT_ID`, `IRMIND_CROWDSTRIKE_CLIENT_SECRET` | Cliente API de CrowdStrike. |
| `IRMIND_SENTINELONE_API_TOKEN` | Token limitado al sitio de SentinelOne. |
| `IRMIND_MISP_API_KEY` | Clave MISP de solo lectura. |
| `VIRUSTOTAL_API_KEY` | Clave de enriquecimiento de VirusTotal. |

Con `os`, las claves de firma usan otro servicio, `irmind`: `local-analyst` y `local-agent-<id>` para una futura ejecución desatendida. Con `file`, esas mismas identidades quedan cifradas. Ambos backends mantienen dentro la clave privada; si falta el backend configurado, la firma se bloquea.

## Elegir un modelo

No se selecciona ningún proveedor por defecto. En la TUI, escribe `/settings model` para elegir un proveedor, introducir o aceptar su URL y elegir un modelo de la lista o escribir su ID. Antes de consultar modelos o probar la conexión remota con texto sintético, se pide confirmación para enviar la clave. Habilitarlo para datos del caso exige otra confirmación firmada. Usa `/settings connectors` para los ajustes públicos avanzados. Para automatización, `--llm-module` y las variables de entorno correspondientes prevalecen sobre los ajustes guardados durante esa ejecución.

Los proveedores locales preconfigurados son Ollama (`127.0.0.1:11434`), LM Studio (`127.0.0.1:1234`) y vLLM (`127.0.0.1:8000`). Los remotos son OpenAI, Anthropic, DeepSeek, OpenRouter, Mistral, Groq, Google Gemini mediante su endpoint compatible, xAI y Together. Los últimos cinco usan el módulo compatible con OpenAI existente. Si un servicio no expone una lista compatible, escribe el ID del modelo. El soporte de herramientas depende del modelo elegido; la prueba de conexión solo comprueba el acceso básico. Azure OpenAI con el parámetro `api-version` en la URL no está soportado por este formulario.

Un servicio local sin clave puede usar HTTP solo en loopback; también admite HTTPS. Los servicios remotos requieren HTTPS y una clave propia del destino. Una URL personalizada nunca hereda `OPENAI_API_KEY`. Consulta [módulos](modules.md) para elegir otros proveedores compilados. Comprueba la retención, la región de procesamiento y la clasificación de datos antes de cualquier conexión externa.

## Tiempo de fuentes syslog clásicas

El contexto temporal de RFC 3164 pertenece a cada ingesta, no a config.toml. Confirma el año, el desplazamiento UTC fijo y el cambio de año en el formulario de ingesta. Puedes aplicar la elección confirmada a todos los ficheros o elegir por separado. Los campos globales retirados necesitan una eliminación explícita y firmada al arrancar. Las fuentes ya firmadas mantienen su interpretación registrada. Consulta [parsers](parsers.md) y la [referencia para automatización](../development/cli.md).

## Almacenamiento de eventos comunes

La CLI, la TUI y la demo usan el mismo decodificador, mapeo seleccionado y escritor directo V3. No hay una preferencia para elegir el escritor. La cadena firmada registra el decodificador, el perfil de mapeo y su recibo. JSON genérico y de nube, ECS, OCSF, EVTX, Linux, syslog, salidas DFIR, red y definiciones declarativas usan esta ruta.

Un mapeo puede conservar campos y entidades consultables sin clasificar el evento. No se deducen categorías, resultados ni roles del texto. Los mapeos nuevos se aplican a ingestas nuevas. Los formatos anteriores a la 1.0 pueden cambiar sin migración: conserva la versión que creó el caso o reingiere los originales verificados en un caso nuevo. El formato no habilita ningún modelo ni conector.

## Skills locales

`/skills` gestiona las instalaciones y activaciones mediante operaciones globales firmadas, separadas de `config.toml`. La vista previa muestra el hash, las herramientas y los recursos antes de firmar. No hay descarga automática ni credenciales adicionales. Los 13 métodos incluidos se pueden inspeccionar sin modelo. Consulta la [guía de skills](skills.md).

## Confirmación de planes de subagentes

En `/settings preferences`, **Confirm all subagent plans** está desactivado por
defecto. Un plan que reserva como máximo el 25 % de los tokens y llamadas
restantes empieza después de mostrar la vista previa. Por encima de cualquiera
de esos umbrales, Start siempre exige la firma del analista. Activar la preferencia
exige Start para todos los planes. El cambio es una operación global firmada;
ninguna herramienta del modelo puede aplicarlo. Consulta
[investigaciones en paralelo](subagents.md) para cancelar tareas, compartir
presupuestos y entender las carencias de los resultados parciales.

## Auditoría del borrado de casos

`/case delete` abre la confirmación escrita y firmada por el analista de un caso
no sellado. `/cases deleted` muestra las lápidas globales y la limpieza pendiente.
No se pueden borrar casos sellados o abiertos en otro proceso. Consulta
[casos](cases.md) para propiedad, interrupciones, evidencia compartida y límites
del borrado lógico.

### Contabilidad de caché de prompts

`/budget` separa entrada ordinaria, lecturas de caché, escrituras de caché y salida.
La entrada incluye todos esos componentes una sola vez: un acierto de caché nunca
amplía el presupuesto del caso ni del hijo. Los datos ausentes figuran como no
disponibles y la cobertura parcial se indica. OpenAI y DeepSeek usan caché automática.
En Anthropic nativo solo se marcan el bloque de sistema confiable y la última
herramienta permitida, con vigencia de cinco minutos. Los endpoints compatibles y
locales no reciben controles de caché. Se mantiene un nonce nuevo por turno.

Los precios opcionales `cache_read_microusd_per_million` y
`cache_write_microusd_per_million` complementan los de entrada y salida en la
configuración firmada. El precio de escritura solo se aplica a cinco minutos.
Cada componente no nulo necesita su precio; si faltan datos, la vigencia es
incierta o alguna petición no tiene precio, el coste total no está disponible.
Los contadores son informes del proveedor, no una factura. Los segmentos de caché
muestran los valores recibidos (indicando cobertura parcial) o no disponible.

## Consultas en origen

Las consultas en origen empiezan desactivadas. La organización las configura en
la sección `[source_queries]` de la política indicada con `--policy`.
`case_ceiling` limita por separado los bytes de escaneo facturados, las filas
retenidas y los bytes retenidos. Cada entrada de `sources` fija el recurso del
proveedor, el conjunto de datos, el intervalo permitido, el umbral de aprobación
y los límites por consulta.

Las credenciales se gestionan en Settings → Keystore. Athena utiliza los campos
ya existentes de clave de acceso, clave secreta y token de sesión opcional de
AWS. BigQuery muestra `query-bigquery/<fuente>/service-account-json`. Azure Log
Analytics muestra `query-azure-log-analytics/<fuente>/tenant-id`, `client-id` y
`client-secret`. La política solo describe recursos y límites. Las credenciales
se guardan en el keystore.

El analista adopta la fuente de la organización y asigna el presupuesto al caso
mediante operaciones firmadas. Estos comandos usan identificadores sintéticos:

```sh
irmind --policy policy.toml source-query adopt synthetic-audit
irmind --policy policy.toml source-query allocate "$CASE_ID" \
  --scan-bytes 67108864 --retained-rows 2000 --retained-bytes 4194304 \
  --reason 'Revisar el intervalo de auditoría autorizado'
```

Para una asignación exclusiva de Analytics, usa `--allow-analytics`. Puedes
omitir `--scan-bytes`. `/budget` muestra los bytes de escaneo facturados,
las filas y los bytes retenidos, con los valores usados y reservados por
separado del tráfico de objetos. El perfil **Costs** de la barra de estado
incluye estos tres segmentos. Se pueden añadir o reordenar en
**Settings → Preferences → Status bar**. El segmento de escaneo aparece cuando
hay un presupuesto de escaneo asignado.

Cuando hace falta el consentimiento del
analista, revisa el alcance, los límites y la consulta traducida con
`/source-query show <id-del-plan>` y firma con
`/source-query approve <id-del-plan>`.

Usa la captura retenida para consultar la timeline, buscar texto y examinar
entidades en local. Si una captura llega al límite de filas, acota el intervalo
o añade filtros antes de proponer otra consulta remota.

Consulta la [validación manual de consultas en origen](source-query-validation.md)
para un ejercicio opcional a cargo del analista con cada proveedor.

### Athena

Usa un workgroup dedicado que haga obligatoria su configuración y tenga un
tope de escaneo por consulta. Declara el workgroup y confirma explícitamente
en la política de la fuente que el escaneo puede superar el tope antes de
cancelarse. Configura la tabla particionada de CloudTrail. Restringe la identidad
de consulta al workgroup, los datos de origen y la ubicación de resultados.
[Workgroup y bytes facturados](../../crates/modules/query-athena/README.md) · [Acciones IAM por recurso](source-queries-design.md).

### BigQuery

Crea un sink de Cloud Logging hacia un dataset dedicado de BigQuery. Declara
el diseño de tablas particionadas por instante o por día. Da a la cuenta de
servicio acceso al dataset seleccionado y permiso para crear jobs en el
proyecto de consulta. Guarda su JSON en el keystore de IRMind.
[Configuración del sink, las tablas y la cuenta de servicio](../../crates/modules/query-bigquery/README.md).

### Azure Log Analytics

Registra una aplicación Microsoft Entra de un solo tenant para el flujo de
credenciales de cliente. Guarda el ID del tenant, el ID de cliente y el secreto
en el keystore. Indica en la política la suscripción, el grupo de recursos,
el nombre y el ID del workspace y la tabla Analytics.
[Registro de la aplicación y autenticación de la API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api).

Limita los permisos de la entidad de servicio al workspace adoptado. El
adaptador necesita `Microsoft.OperationalInsights/workspaces/read` y
`Microsoft.OperationalInsights/workspaces/tables/read` para las dos
comprobaciones de metadatos. Concede
`Microsoft.OperationalInsights/workspaces/query/read` y restringe el acceso
a las tablas adoptadas con permisos por tabla o una asignación de RBAC granular.
La aplicación no necesita permisos de ingesta, cambios de roles, claves
compartidas o administración del workspace.
[Acceso al workspace y las tablas](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access) · [RBAC granular](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/granular-rbac-log-analytics) · [Permisos para el plan de tabla](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-table-plans).
