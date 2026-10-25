Traducción de docs/modules.md en el commit 332d190657f969d89689b9ae150900b5c7b35723; si hay diferencias, prevalece la versión en inglés.

# Módulos

Esta página es para quienes eligen conectores. Cada apartado indica qué consulta el módulo, los permisos mínimos, cómo activarlo y sus límites. Guarda las credenciales según [configuración](configuration.md); los crates de módulos no leen el llavero ni el entorno.

Los módulos se compilan dentro del binario. Una feature de Cargo incluye un módulo opcional; un interruptor de la CLI activa un conector en la sesión. El modelo se elige con `--llm-module`. Ninguno se selecciona automáticamente.

## Compatible con OpenAI

**Función:** Transmite respuestas y propuestas de herramientas mediante el protocolo OpenAI Chat Completions. Admite la API oficial, servicios compatibles aprobados y servicios locales como Ollama.

**Permiso:** Acceso solo al modelo y servicio aprobados. Un servicio local sin clave puede usar HTTP en loopback o HTTPS. Los servicios remotos requieren HTTPS y una clave dedicada a su URL.

**Configuración:** Incluido en el binario estándar. Define `IRMIND_MODEL` y, si procede, `IRMIND_LLM_BASE_URL`. Selecciona `--llm-module llm-openai-compatible`. Guarda `OPENAI_API_KEY` solo para la URL oficial, o `IRMIND_LLM_API_KEY` para una URL personalizada.

**Límites:** El stream debe incluir el uso final de tokens; si está incompleto, se detiene. La redacción por patrones no garantiza eliminar todo dato sensible. Obtén la aprobación del proveedor antes de enviar datos de incidentes.

## Anthropic

**Función:** Usa la API Messages nativa y transmite texto, propuestas de herramientas y uso.

**Permiso:** Cuenta API autorizada para el modelo aprobado.

**Configuración:** Compila con `--features llm-anthropic`, define `IRMIND_ANTHROPIC_MODEL`, guarda `ANTHROPIC_API_KEY` en el llavero y selecciona `--llm-module llm-anthropic`.

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

**Función:** Busca eventos en un índice configurado y devuelve evidencia acotada. El agente envía un término literal, no SPL libre.

**Permiso:** Token dedicado de solo lectura con acceso de búsqueda solo al índice configurado. No concedas escritura de lookups, acciones de alerta ni comandos de salida externa.

**Configuración:** Compila con `--features siem-splunk`. Define `IRMIND_SPLUNK_URL`, `IRMIND_SPLUNK_SOURCE_ID`, `IRMIND_SPLUNK_INDEX` y `IRMIND_SPLUNK_ACCOUNT_FIELD`. Guarda `IRMIND_SPLUNK_TOKEN`, activa `--enable-splunk` e incluye fuente, cuenta y ventana UTC en el alcance del caso.

**Límites:** El módulo fija el índice y la ventana temporal en el servidor, limita los resultados, exige HTTPS y rechaza consultas inseguras o ambiguas. No ofrece SPL general.

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

**Límites:** El parseo actual es acotado y en memoria. Rechaza archivos demasiado grandes, JSON muy anidado y demasiados registros. Otros formatos necesitan parsers futuros.

## Contrato de proveedores

Para añadir un módulo, consulta la [guía de arquitectura](../development/architecture.md) y la suite de contratos compartida de `irmind-testkit`. No actives un proveedor por defecto.
