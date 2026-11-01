Traducción de docs/modules.md en el commit 639cbab2c7a7db603c8ec1315435d04e84aa9a1b; si hay diferencias, prevalece la versión en inglés.

# Módulos

Esta página es para quienes eligen conectores o backends de llavero. Cada apartado explica qué hace el módulo, sus permisos, configuración y límites. Guarda las credenciales según [configuración](configuration.md); los conectores no leen el llavero ni el entorno por su cuenta.

La compilación normal incluye todos los módulos de producto actuales y ambos llaveros. Ninguno se activa automáticamente. En la TUI, usa `/settings model` para seleccionar y probar un proveedor, `/settings connectors` para activar conectores y editar campos públicos, y `/settings keystore` para las credenciales. Los cambios persisten y la sesión se recarga. Una compilación mínima usa `--no-default-features --features keystore-file`; siempre se requiere un backend de firma y secretos. Las variables y flags de la CLI ofrecen overrides temporales para automatización.

Splunk, MISP, CrowdStrike, SentinelOne y S3 compatible admiten un PEM de CA propio en `/settings connectors`. IRMind firma la huella del archivo en la configuración no secreta, la comprueba al iniciar y añade esa CA a las raíces del sistema sin desactivar la verificación del nombre del servidor. Consulta [configuración](configuration.md#ajustes-no-secretos).

## Compatible con OpenAI

**Función:** Transmite respuestas y propuestas de herramientas mediante el protocolo OpenAI Chat Completions. Admite la API oficial, servicios compatibles aprobados y servicios locales como Ollama.

**Permiso:** Acceso solo al modelo y servicio aprobados. Un servicio local sin clave puede usar HTTP en loopback o HTTPS. Los servicios remotos requieren HTTPS y una clave dedicada a su URL.

**Configuración:** Incluido en el binario estándar. Define `IRMIND_MODEL` y, si procede, `IRMIND_LLM_BASE_URL`. Selecciona `--llm-module llm-openai-compatible`. Guarda `OPENAI_API_KEY` solo para la URL oficial, o `IRMIND_LLM_API_KEY` para una URL personalizada.

**Límites:** El stream debe incluir el uso final de tokens; si está incompleto, se detiene. La redacción por patrones no garantiza eliminar todo dato sensible. Obtén la aprobación del proveedor antes de enviar datos de incidentes.

Los siguientes proveedores preconfigurados de `/settings model` usan este mismo módulo. Sus URL son valores predeterminados, no una autorización para enviar datos del caso. Sus documentos describen Chat Completions, streaming y llamadas a herramientas; el soporte real depende del modelo elegido. Los servicios locales deben estar en marcha con un modelo apto para herramientas. Si no se puede consultar la lista, introduce el ID del modelo a mano.

| Proveedor | URL base predeterminada | Documentación oficial |
| --- | --- | --- |
| OpenAI | `https://api.openai.com/v1/` | [Chat Completions](https://platform.openai.com/docs/api-reference/chat/create) |
| Mistral | `https://api.mistral.ai/v1/` | [API](https://docs.mistral.ai/api/) |
| Groq | `https://api.groq.com/openai/v1/` | [API](https://console.groq.com/docs/api-reference) |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta/openai/` | [Compatibilidad OpenAI](https://ai.google.dev/gemini-api/docs/openai/) |
| xAI | `https://api.x.ai/v1/` | [Chat Completions](https://docs.x.ai/developers/rest-api-reference/inference/chat-completions) |
| Together | `https://api.together.ai/v1/` | [Compatibilidad OpenAI](https://docs.together.ai/docs/inference/openai-compatibility) |
| Ollama | `http://127.0.0.1:11434/v1/` | [Compatibilidad OpenAI](https://docs.ollama.com/api/openai-compatibility) |
| LM Studio | `http://127.0.0.1:1234/v1/` | [Compatibilidad OpenAI](https://lmstudio.ai/docs/developer/openai-compat) |
| vLLM | `http://127.0.0.1:8000/v1/` | [Servidor compatible](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/) |

Los servicios Azure OpenAI que requieren `api-version` en la URL no están soportados por el formulario. Una URL personalizada sigue disponible si cumple los requisitos de streaming, herramientas y tamaño limitado de respuesta.

## Anthropic

**Función:** Usa la API Messages nativa y transmite texto, propuestas de herramientas y uso.

**Permiso:** Cuenta API autorizada para el modelo aprobado.

**Configuración:** Compila con `--features llm-anthropic`, define `IRMIND_ANTHROPIC_MODEL`, guarda `ANTHROPIC_API_KEY` en el backend de secretos elegido y selecciona `--llm-module llm-anthropic`.

**Límites:** El servicio remoto usa HTTPS. Comprueba región, retención y tratamiento contractual de datos antes de usarlo.

## DeepSeek

**Función:** Usa el adaptador compartido de Chat Completions para DeepSeek.

**Permiso:** Cuenta API autorizada para el modelo aprobado.

**Configuración:** Compila con `--features llm-deepseek`, define `IRMIND_DEEPSEEK_MODEL`, guarda `DEEPSEEK_API_KEY` y selecciona `--llm-module llm-deepseek`.

**Límites:** Requiere HTTPS remoto y datos finales de uso en el stream. La disponibilidad del módulo no equivale a la aprobación del proveedor.

## OpenRouter

**Función:** Usa el adaptador compartido de Chat Completions para el modelo elegido en OpenRouter.

**Permiso:** Cuenta API limitada a los modelos aprobados por tu organización.

**Configuración:** Compila con `--features llm-openrouter`, define `IRMIND_OPENROUTER_MODEL`, guarda `OPENROUTER_API_KEY` y selecciona `--llm-module llm-openrouter`.

**Límites:** El enrutamiento puede cambiar quién procesa los datos. Revisa el modelo elegido y su política de retención.

## Splunk

**Función:** Busca campos de evento permitidos en un índice configurado y obtiene una alerta por su ID exacto. Ambas operaciones devuelven evidencia acotada. El agente envía campos y valores estructurados, nunca SPL.

**Permiso:** Token dedicado de solo lectura con acceso de búsqueda solo al índice configurado. No concedas escritura de lookups, acciones de alerta ni comandos de salida externa.

**Configuración:** Compila con `--features siem-splunk`. Define `IRMIND_SPLUNK_URL`, `IRMIND_SPLUNK_SOURCE_ID`, `IRMIND_SPLUNK_INDEX` y `IRMIND_SPLUNK_ACCOUNT_FIELD`. Define `IRMIND_SPLUNK_ALERT_ID_FIELD` si el índice usa un campo distinto de `alert_id`. Los campos de búsqueda son por defecto `eventName`, `user`, `sourceIPAddress` y `host`; usa `IRMIND_SPLUNK_EVENT_NAME_FIELD`, `IRMIND_SPLUNK_USER_FIELD`, `IRMIND_SPLUNK_SOURCE_IP_FIELD` e `IRMIND_SPLUNK_HOST_FIELD` para adaptarlos al índice. Guarda `IRMIND_SPLUNK_TOKEN`, activa `--enable-splunk` e incluye fuente, cuenta y ventana UTC en el alcance del caso. En la TUI del caso, `/siem-alert <source> <account> <alert-id> <from-UTC> <to-UTC>` obtiene una alerta con la misma política y custodia que las propuestas del modelo.

**Límites:** El modelo solo puede comparar `event_name`, `user`, `source_ip` o `host` con `eq`, `not_eq` o `prefix`. Puede pedir eventos, `count_by`, `top` o `distinct` sobre uno de esos campos, con un máximo de 20 resultados. El módulo fija en el servidor el índice y una ventana máxima de 24 horas, escapa comillas y barras inversas, rechaza caracteres de control de SPL, exige HTTPS y desactiva las redirecciones. Las alertas se buscan en el índice y campo de ID configurados; no se usa una API de administración de alertas. Las aprobaciones pendientes con el antiguo argumento libre `query` se deniegan; las entradas firmadas históricas siguen verificándose.

El módulo usa el [endpoint de exportación de búsquedas de Splunk](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.0/search-endpoints/search-endpoint-descriptions) y una [búsqueda por campo y valor](https://help.splunk.com/en/splunk-cloud-platform/search/search-reference/10.6/search-commands/search) generada.

## AWS CloudTrail e IAM

**Función:** Lee eventos de CloudTrail y determinados datos de usuarios o roles de IAM. STS comprueba la cuenta y el rol reales antes de consultar.

**Permiso:** Rol dedicado con `sts:GetCallerIdentity`, `cloudtrail:LookupEvents` y solo las lecturas necesarias `iam:GetRole` o `iam:GetUser`. Limita su política de confianza.

**Configuración:** Compila con `--features cloud-aws`. Define `IRMIND_AWS_SOURCE_ID`, `IRMIND_AWS_REGION` y `IRMIND_AWS_ROLE_NAME`. Guarda `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` y, cuando haga falta, `AWS_SESSION_TOKEN`. Activa `--enable-aws` y limita la cuenta y la ventana temporal.

**Límites:** Una región configurada y consultas acotadas. El módulo no utiliza perfiles AWS del entorno ni puede cambiar recursos en la nube.

## Almacenamiento de objetos en la nube (S3, GCS y Azure Blob)

**Función:** Enumera objetos versionados bajo un prefijo autorizado por el caso y lee los logs exportados en un flujo acotado. IRMind calcula el hash de los bytes descargados y convierte los registros válidos a Parquet local. No escribe en el bucket ni en el contenedor.

**Permiso:** S3 requiere `s3:ListBucket` limitado al prefijo y `s3:GetObject`; GCS requiere `roles/storage.objectViewer` en el bucket; Azure requiere `Storage Blob Data Reader` en el contenedor. Usa identidades dedicadas y deniega escrituras también en la política de la nube. Los ETag del proveedor sirven para controlar la versión, no son hashes de evidencia.

**Configuración:** Compila con `--features storage-s3`, `storage-gcs` o `storage-azure`. En la vista de módulos de la TUI, activa cada conector y define su ID de fuente y bucket o contenedor. S3 necesita una región; Azure necesita cuenta, ID de cliente y tenant. Las URL opcionales requieren HTTPS. Incluye el prefijo y la ventana UTC en los alcances del caso y de la organización.

**Credenciales:** S3 reutiliza `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` y, si procede, `AWS_SESSION_TOKEN`. GCS usa `GCP_SERVICE_ACCOUNT_JSON`; Azure usa `AZURE_CLIENT_SECRET`. Se guardan en el backend de secretos seleccionado, nunca en `config.toml` ni en variables de entorno.

**Uso en la TUI:** Ejecuta `/objects <fuente> <s3|gs|az> <bucket-o-contenedor> <prefijo> <desde-UTC> <hasta-UTC>` para ver hasta 20 objetos y el volumen estimado. Acota una lista truncada. Ejecuta `/object-read <número>` para confirmar la versión y la transferencia. Añade `--copy-original` si quieres conservar una copia local explícita. El indicador de actividad muestra los bytes transferidos y el tiempo transcurrido; Esc o `/pause` cancela. Una segunda lectura compara el original con su manifiesto firmado.

**Límites:** La lectura exige una lista completa y firmada del objeto y su versión, un límite de bytes por objeto y el presupuesto del caso. Las páginas de listado de más de 8 MiB se rechazan antes de analizarlas. Por encima de `object_transfer_approval_bytes` exige otra aprobación firmada del analista. Las transferencias fallidas consumen la reserva. Los bytes descargados se guardan una vez bajo el directorio de datos del caso, tras comprobar el espacio libre frente al tamaño firmado, y se eliminan al terminar, fallar o cancelar. Una segunda lectura con el caso abierto compara el original firmado y puede generar costes. Para verificar sin red después del sellado, conserva una copia local explícita antes de sellar. No se usan credenciales ambientales. `object_store` expone ETags, pero no un checksum nativo portable; el manifiesto guarda el ETag como control opaco de versión y firma el SHA-256 propio de IRMind.

## CrowdStrike

**Función:** Lee el inventario de hosts y las alertas vinculadas a ellos.

**Permiso:** `hosts:read` y `Alerts: READ` para un cliente API dedicado.

**Configuración:** Compila con `--features edr-crowdstrike`. Define `IRMIND_CROWDSTRIKE_URL` y `IRMIND_CROWDSTRIKE_SOURCE_ID`. Guarda `IRMIND_CROWDSTRIKE_CLIENT_ID` y `IRMIND_CROWDSTRIKE_CLIENT_SECRET`. Activa `--enable-crowdstrike` y limita el alcance al host exacto.

**Límites:** No ofrece una API general de árbol de procesos verificada. Rechaza hosts ambiguos, alertas de otros hosts, campos de alcance ausentes, redirecciones y respuestas demasiado grandes.

## SentinelOne

**Función:** Lee detalles de endpoints, detecciones y procesos descendientes asociados a una amenaza concreta.

**Permiso:** Acceso `Endpoints.view` y `Threats.view` limitado al sitio.

**Configuración:** Compila con `--features edr-sentinelone`. Define `IRMIND_SENTINELONE_URL`, `IRMIND_SENTINELONE_SOURCE_ID` y `IRMIND_SENTINELONE_SITE_ID`. Guarda `IRMIND_SENTINELONE_API_TOKEN`. Activa `--enable-sentinelone` y limita el alcance al host exacto.

**Límites:** Los datos de procesos proceden de los eventos Explore de una amenaza verificada; no permiten una búsqueda arbitraria de procesos de un host.

## MISP

**Función:** Consulta IOCs en un servicio interno de inteligencia de amenazas.

**Permiso:** Clave API MISP de solo lectura con acceso únicamente al conjunto de eventos aprobado.

**Configuración:** Compila con `--features ti-misp`. Define `IRMIND_MISP_URL` y `IRMIND_MISP_SOURCE_ID`. Guarda `IRMIND_MISP_API_KEY`, activa `--enable-misp` e incluye esa fuente en el alcance del caso.

**Límites:** Consulta exacta y acotada. La instancia MISP debe ser interna y usar HTTPS.

## VirusTotal

**Función:** Enriquece un hash público, dominio o dirección IPv4 pública apta mediante un servicio externo.

**Permiso:** Clave API dedicada y aprobación explícita del analista para cada consulta externa.

**Configuración:** Compila con `--features ti-virustotal`, guarda `VIRUSTOTAL_API_KEY` y activa `--enable-virustotal`.

**Límites:** La consulta puede revelar a un tercero que investigas un IOC. Se rechazan direcciones internas o ambiguas; incluso los IOCs válidos requieren aprobación.

## Parser en streaming de JSON y logs de nube exportados

**Función:** Procesa JSON genérico, AWS CloudTrail, GCP Cloud Audit Logs, Azure Activity y exportaciones de inicio de sesión de Entra ID en flujos acotados. Los casos grandes se convierten en Parquet particionado. Las consultas acotadas leen solo artefactos de IRMind firmados y comprobados por hash. El parser no envía los registros a un modelo.

**Permiso:** Lectura solo del archivo local seleccionado.

**Configuración:** Compilado por defecto con `parser-json`; una compilación mínima puede omitirlo. Usa el selector `/ingest` de la TUI o el [comando de ingesta de la CLI](../development/cli.md).

**Límites:** Se rechazan el JSON muy anidado y los registros individuales demasiado grandes. Los originales se identifican por hash en su ubicación; copiarlos requiere una elección explícita. La búsqueda Parquet compara subcadenas con límites y acepta filtros de fecha, cuenta o proyecto y región. Los índices derivados anteriores requieren migrar los originales copiados antes de consultar el grafo. Otros formatos necesitarán parsers futuros.

## Parser de Elastic Common Schema

**Función:** Detecta ECS NDJSON mediante `@timestamp` y `ecs.version`, o mediante campos característicos de evento y host. Convierte evento, host, usuario, origen, destino, proceso, archivo y URL en registros y entidades con hora UTC. Los campos restantes permanecen en el registro local.

**Permiso:** Solo lectura del archivo local elegido.

**Configuración:** Compilado por defecto con `parser-ecs`. `/ingest` lo elige automáticamente solo si hay una coincidencia única de confianza alta. En los demás casos, el analista decide. La selección y versión quedan en el manifiesto firmado.

**Límites:** Experimental y probado solo con datos sintéticos. Cada registro admite hasta 4 MiB, 1.024 campos y 64 niveles; una fuente admite hasta diez millones de registros y 50 GiB. Las líneas inválidas se cuentan con muestras acotadas y escapadas, sin detener las siguientes. La hora se normaliza a segundos UTC; la fracción original queda en el registro local.

El mapeo sigue la [referencia oficial de ECS](https://www.elastic.co/docs/reference/ecs/ecs-reference).

## Parser de OCSF

**Función:** Detecta OCSF JSON, incluidos registros con formato multilínea, o NDJSON mediante `class_uid`, `category_uid` y `metadata.version`. Mapea Authentication, API Activity, Network Activity, Process Activity, File Activity y Detection Finding. También lee exportaciones OCSF Parquet, incluidas las de Security Lake, con el lector Parquet existente. Los campos desconocidos se conservan localmente.

**Permiso:** Lectura del archivo local. OCSF Parquet local se lee directamente con acceso aleatorio, sin copia creada por el parser. Los flujos de objetos en la nube usan un temporal privado dentro del directorio de datos del caso que se elimina al terminar.

**Configuración:** Compilado por defecto con `parser-ocsf`. El JSON OCSF se elige automáticamente si la confianza alta es única. La cabecera Parquet sola no demuestra el esquema y recibe confianza baja; el analista debe confirmar. La elección se firma.

**Límites:** Experimental y probado solo con datos sintéticos. Los límites de JSON son los mismos que en ECS. Cada Parquet admite hasta 2 GiB, los metadatos de cierre hasta 16 MiB, los grupos de filas hasta 256 MiB y cada fila mapeada hasta 4 MiB; un caso mayor puede usar varios archivos. Un Parquet estructuralmente dañado se rechaza como archivo porque no se puede resincronizar de forma segura; las líneas JSON inválidas se cuentan individualmente. Detection Finding no se confirma automáticamente como hallazgo del caso.

El mapeo sigue el [esquema oficial de OCSF](https://github.com/ocsf/ocsf-schema).

## Llavero del sistema

**Función:** Firma como Analyst o Agent y guarda credenciales de módulos en Keychain, Credential Manager o Secret Service.

**Permiso:** Acceso al almacén de credenciales del usuario actual. En Linux, Secret Service suele necesitar una sesión D-Bus.

**Configuración:** Se compila por defecto con `keystore-os`. Elige `os` explícitamente para `signer`, `secrets` o ambos en el primer arranque. Usa `/settings keystore` para gestionar credenciales sin mostrar sus valores.

**Límites:** Una sesión SSH sin entorno gráfico puede no tener el llavero desbloqueado. Si este backend está seleccionado y no funciona, IRMind se detiene; la selección o migración a `file` debe ser explícita.

## Archivo cifrado

**Función:** Firma como Analyst o Agent y guarda credenciales en un archivo local cifrado.

**Permiso:** Escritura en el directorio privado de datos del usuario; no requiere red ni sesión gráfica.

**Configuración:** Se compila por defecto con `keystore-file`. Elige `file` explícitamente para `signer`, `secrets` o ambos. La TUI pide la passphrase sin eco; la CLI admite `--passphrase-fd`. Usa `/settings keystore` para cambiar la passphrase o migrar.

**Límites:** Argon2id y XChaCha20-Poly1305 protegen el archivo en reposo, pero una passphrase débil o una sesión comprometida pueden exponerlo desbloqueado. Conserva fuera de la máquina la huella pública. La migración queda en la cadena operativa global firmada y requiere reiniciar la sesión para activarse.

## Contrato de proveedores

Para añadir un módulo, consulta la [guía de arquitectura](../development/architecture.md) y la suite de contratos compartida de `irmind-testkit`. No actives un proveedor por defecto.
