Traducción de docs/configuration.md en el commit 095cd1db66e6dec2b51c6115d4fd44de6981e6a4; si hay diferencias, prevalece la versión en inglés.

# Configuración

Esta página es para quienes preparan una evaluación controlada. Explica el alcance de los casos, la política, los ajustes no secretos y la selección del backend. Los permisos de los conectores están en [módulos](modules.md).

## Alcance del caso

Un caso puede ser solo local. Para permitir lecturas remotas, define una fuente, un objetivo y una ventana UTC explícitos. El formato actual es:

```text
v1;sources=splunk-demo;accounts=000000000000;hosts=demo-host;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z
```

Separa con comas los valores de `sources`, `accounts` y `hosts`. El formulario de caso nuevo y el comando `/scope` de la TUI cambian el alcance; el cambio queda firmado. Las consultas fuera del alcance requieren aprobación o se deniegan. Un alcance heredado de texto libre no permite acceso remoto. Este formato aún no admite IDs de proyecto.

## Archivo de política

Pasa `--policy policy.toml` o define `IRMIND_POLICY`. El archivo [policy.toml](../../policy.toml) del repositorio es un ejemplo versionado:

```toml
version = 1
max_tool_calls_per_case = 100
max_model_result_bytes = 10000
max_model_tokens_per_case = 200000
denied_tools = []
```

La política puede restringir las reglas fijas de las herramientas, pero no habilitar acciones denegadas. Las lecturas deben estar dentro del alcance; el enriquecimiento externo requiere aprobación firmada del analista; la contención está deshabilitada. Los campos desconocidos causan un error.

## Ajustes no secretos

La raíz de composición lee estas variables de entorno. Usa solo valores acordes con el destino aprobado y el alcance del caso.

| Variable | Función |
| --- | --- |
| `IRMIND_HOME` | Directorio de datos local opcional. |
| `IRMIND_POLICY` | Ruta del archivo TOML de política. |
| `IRMIND_LLM_MODULE` | Selección explícita del módulo de modelo; alternativa a `--llm-module`. |
| `IRMIND_MODEL`, `IRMIND_LLM_BASE_URL` | Modelo compatible con OpenAI y URL base opcional. |
| `IRMIND_ANTHROPIC_MODEL`, `IRMIND_DEEPSEEK_MODEL`, `IRMIND_OPENROUTER_MODEL` | IDs de modelos de esos proveedores. |
| `IRMIND_SPLUNK_URL`, `IRMIND_SPLUNK_SOURCE_ID`, `IRMIND_SPLUNK_INDEX`, `IRMIND_SPLUNK_ACCOUNT_FIELD` | Servicio Splunk y fuente de búsqueda acotada. |
| `IRMIND_AWS_SOURCE_ID`, `IRMIND_AWS_REGION`, `IRMIND_AWS_ROLE_NAME` | Fuente, región y rol de solo lectura de AWS. |
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

Pulsa `k` en la pantalla de inicio para ver los backends, comprobar qué credenciales existen, añadir o sustituir (`a`), eliminar (`d`), cambiar la passphrase (`p`) o migrar una capacidad (`s` o `x`). La migración conserva la huella pública del analista y deja un evento operativo global firmado incluso antes del primer caso. Tras cambiar una credencial, los conectores activos pueden conservar el valor anterior: pulsa `r` para reiniciar la sesión. No escribas secretos en el texto del caso.

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
| `IRMIND_CROWDSTRIKE_CLIENT_ID`, `IRMIND_CROWDSTRIKE_CLIENT_SECRET` | Cliente API de CrowdStrike. |
| `IRMIND_SENTINELONE_API_TOKEN` | Token limitado al sitio de SentinelOne. |
| `IRMIND_MISP_API_KEY` | Clave MISP de solo lectura. |
| `VIRUSTOTAL_API_KEY` | Clave de enriquecimiento de VirusTotal. |

Con `os`, las claves de firma usan otro servicio, `irmind`: `local-analyst` y `local-agent-<id>` para una futura ejecución desatendida. Con `file`, esas mismas identidades quedan cifradas. Ambos backends mantienen dentro la clave privada; si falta el backend configurado, la firma se bloquea.

## Elegir un modelo

No se selecciona ningún proveedor por defecto. El módulo compatible con OpenAI viene compilado, pero debes elegirlo:

```sh
IRMIND_MODEL=YOUR_LOCAL_MODEL IRMIND_LLM_BASE_URL=http://127.0.0.1:11434/v1/ \
  ./target/release/irmind --llm-module llm-openai-compatible
```

Un servicio local sin clave puede usar HTTP solo en loopback; también admite HTTPS. Los servicios remotos requieren HTTPS y una clave propia del destino. Una URL personalizada nunca hereda `OPENAI_API_KEY`. Consulta [módulos](modules.md) para elegir otros proveedores compilados. Comprueba la retención, la región de procesamiento y la clasificación de datos antes de cualquier conexión externa.
