Traducción de docs/configuration.md en el commit a333bb3ffc4a9d695d1facf42461c43ce3d2dc7f; si hay diferencias, prevalece la versión en inglés.

# Configuración

La captura del ratón se puede desactivar con `mouse_capture = false` en `config.toml` para permitir la selección de texto del terminal. La TUI pide revisar y aceptar el cambio manual antes de abrir casos.

Esta página es para quienes preparan una evaluación controlada. Explica el alcance de los casos, la política, los ajustes no secretos y la selección del backend. Los permisos de los conectores están en [módulos](modules.md).

## Alcance del caso

Un caso puede ser solo local. Para permitir lecturas remotas, el formulario de caso nuevo pide fuentes, cuentas, proyectos, hosts, prefijos de objetos y una ventana UTC. Un prefijo tiene la forma `s3://bucket/AWSLogs/123/`, `gs://bucket/export/` o `az://contenedor/export/`. Añádelo con `/scope add object <URI>`; el ID de fuente también debe estar en el alcance. Los demás destinos usan `/scope add project <id>` (o `source`, `account`, `host`). Amplía la ventana con `/scope window <from> <to>`. El analista firma los cambios. Las lecturas de objetos fuera del prefijo del caso o de la organización se deniegan. La codificación para automatización está en la [referencia de la CLI](../development/cli.md).

## Archivo de política

Pasa `--policy policy.toml` o define `IRMIND_POLICY`. El archivo [policy.toml](../../policy.toml) del repositorio es un ejemplo versionado:

```toml
version = 1
max_tool_calls_per_case = 100
max_model_rounds_per_turn = 25
max_model_result_bytes = 10000
max_model_tokens_per_case = 200000
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

## Ajustes no secretos

La TUI guarda los ajustes no secretos en `config.toml` dentro del [directorio de datos estándar](platforms.md#datos-y-terminal). La compilación normal incluye todos los módulos de producto actuales y ambos llaveros, pero no activa ninguno. `/settings` reúne Modelo, Conectores, Llavero y Preferencias; `/settings model` abre directamente el modelo. En Conectores, las flechas eligen un módulo, Tab elige un parámetro y Enter lo edita en un campo visible. El primer carácter escrito o pegado sustituye el valor predeterminado; Enter lo acepta y Ctrl+U lo borra. La URL se recorta y las barras repetidas de la ruta se normalizan antes de validarla. Las credenciales se escriben en campos enmascarados de Llavero. La sesión se recarga tras un cambio. La salida de datos del equipo requiere confirmación explícita y firmada. Una compilación mínima usa `--no-default-features --features keystore-file` porque siempre debe existir un backend de firma y secretos.

Para Splunk, MISP, CrowdStrike, SentinelOne y un servicio S3 compatible, `/settings connectors` admite un archivo PEM de CA opcional. IRMind muestra y firma su huella SHA-256 junto con la ruta. El PEM se añade a las raíces del sistema; la comprobación del nombre del servidor sigue activa. Al iniciar el conector se vuelve a comprobar el hash, por lo que sustituir el archivo exige otra aprobación. Borra la ruta para retirar esa CA. No guardes una clave privada en el archivo.

`resume_last_case` vale `true` por defecto. Tras arrancar, la TUI reabre el último caso abierto que se usó solo si verifica su cadena de custodia. Un caso sellado o eliminado deja la pantalla de inicio; un fallo de verificación aparece allí como aviso. Usa `/settings preferences` para cambiar esta opción, el ratón o el tema (`auto`, `light`, `dark`). La referencia privada `last-case` se guarda junto a `config.toml` y no forma parte de la custodia. La automatización CLI no reanuda casos.

Para automatización, el orden es **flag de CLI > variable de entorno > config.toml > valor por defecto**. Un override solo dura esa ejecución; la TUI no lo sustituye en silencio. El archivo contiene IDs de módulos, modelos, URLs, fuentes, índices, regiones y precios opcionales, pero nunca credenciales ni passphrases. Se rechazan los campos desconocidos o secretos. Ejemplo:

```toml
version = 1
llm_module = "llm-openai-compatible"
resume_last_case = true
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
