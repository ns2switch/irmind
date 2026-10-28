Traducción de docs/modules.md en el commit 6a6259ec56f1e8598e693f3593f38320b3d8bb0c; si hay diferencias, prevalece la versión en inglés.

# Módulos

Esta página es para quienes eligen conectores o backends de llavero. Cada apartado explica qué hace el módulo, sus permisos, configuración y límites. Guarda las credenciales según [configuración](configuration.md); los conectores no leen el llavero ni el entorno por su cuenta.

Los módulos se compilan dentro del binario. En la TUI, pulsa `m` para seleccionar un módulo compilado, editar sus campos públicos y activarlo; pulsa `k` para sus credenciales. Los cambios persisten y la sesión se recarga dentro de la TUI. Las variables de entorno y los interruptores de la CLI indicados abajo son overrides temporales para automatización. Ninguno se selecciona automáticamente.

## Compatible con OpenAI

**Función:** Transmite respuestas y propuestas de herramientas mediante el protocolo OpenAI Chat Completions. Admite la API oficial, servicios compatibles aprobados y servicios locales como Ollama.

**Permiso:** Acceso solo al modelo y servicio aprobados. Un servicio local sin clave puede usar HTTP en loopback o HTTPS. Los servicios remotos requieren HTTPS y una clave dedicada a su URL.

**Configuración:** Incluido en el binario estándar. Define `IRMIND_MODEL` y, si procede, `IRMIND_LLM_BASE_URL`. Selecciona `--llm-module llm-openai-compatible`. Guarda `OPENAI_API_KEY` solo para la URL oficial, o `IRMIND_LLM_API_KEY` para una URL personalizada.

**Límites:** El stream debe incluir el uso final de tokens; si está incompleto, se detiene. La redacción por patrones no garantiza eliminar todo dato sensible. Obtén la aprobación del proveedor antes de enviar datos de incidentes.

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

## Parser JSON y CloudTrail

**Función:** Indexa registros locales JSON y CloudTrail en la cronología y el grafo DuckDB sin enviarlos a un modelo.

**Permiso:** Lectura solo del archivo local seleccionado.

**Configuración:** Incluido y activo en todos los binarios. Usa el selector `/ingest` de la TUI o el [comando de ingesta de la CLI](../development/cli.md).

**Límites:** Cada archivo se carga con un límite de 50 MB; después, los registros se procesan en streaming y se indexan en lotes acotados. Se rechazan el JSON muy anidado, un número excesivo de registros y los registros con más de 2.048 términos de búsqueda distintos. La búsqueda en el grafo exige que coincidan todas las palabras, no busca subcadenas. Las palabras buscables tienen entre 2 y 64 bytes. Otros formatos necesitarán parsers futuros.

## Llavero del sistema

**Función:** Firma como Analyst o Agent y guarda credenciales de módulos en Keychain, Credential Manager o Secret Service.

**Permiso:** Acceso al almacén de credenciales del usuario actual. En Linux, Secret Service suele necesitar una sesión D-Bus.

**Configuración:** Se compila por defecto con `keystore-os`. Elige `os` explícitamente para `signer`, `secrets` o ambos en el primer arranque. Pulsa `k` para gestionar credenciales sin mostrar sus valores.

**Límites:** Una sesión SSH sin entorno gráfico puede no tener el llavero desbloqueado. Si este backend está seleccionado y no funciona, IRMind se detiene; la selección o migración a `file` debe ser explícita.

## Archivo cifrado

**Función:** Firma como Analyst o Agent y guarda credenciales en un archivo local cifrado.

**Permiso:** Escritura en el directorio privado de datos del usuario; no requiere red ni sesión gráfica.

**Configuración:** Se compila por defecto con `keystore-file`. Elige `file` explícitamente para `signer`, `secrets` o ambos. La TUI pide la passphrase sin eco; la CLI admite `--passphrase-fd`. Pulsa `k` para cambiar la passphrase o migrar.

**Límites:** Argon2id y XChaCha20-Poly1305 protegen el archivo en reposo, pero una passphrase débil o una sesión comprometida pueden exponerlo desbloqueado. Conserva fuera de la máquina la huella pública. La migración queda en la cadena operativa global firmada y requiere reiniciar la sesión para activarse.

## Contrato de proveedores

Para añadir un módulo, consulta la [guía de arquitectura](../development/architecture.md) y la suite de contratos compartida de `irmind-testkit`. No actives un proveedor por defecto.
