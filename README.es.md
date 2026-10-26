Traducción de README.md en el commit 7407ca6aedfc764c944d0f525b27b505c7115b0e; si hay diferencias, prevalece la versión en inglés.

# IRMind — Respuesta asistida a incidentes

Cliente de IA en terminal para investigaciones de seguridad, con llamadas a herramientas sujetas a política y cadena de custodia firmada.

> [!WARNING]
> IRMind está en desarrollo. Todavía no lo uses con incidentes reales ni datos sensibles.
> Los ejemplos de este repositorio son sintéticos.

## Qué puedes hacer

- Abrir un caso, definir su alcance e investigar una alerta desde la terminal.
- Ingerir evidencia local y consultar la cronología y el grafo de entidades.
- Pedir a un modelo seleccionado que proponga consultas de investigación.
- Revisar y firmar aprobaciones antes de un enriquecimiento externo.
- Ver la evidencia original mientras el modelo recibe una copia limitada y redactada.
- Verificar, sellar, exportar y volver a verificar un paquete de caso.

## Cómo funciona

El modelo propone una llamada. La política comprueba la herramienta, los argumentos, el alcance del caso, el modo de ejecución y los límites. Los conectores autorizados devuelven evidencia que permanece en local; el modelo ve una copia protegida. La auditoría firmada registra propuestas, decisiones, resultados y cambios del caso.

```text
Analista → TUI → caso + política → conector autorizado → evidencia local
                  ↑       ↓
                modelo  cadena de auditoría firmada
```

Consulta el [modelo de seguridad](docs/es/security-model.md) para conocer las garantías y límites.

## Instalación

Para una evaluación interna, se recomienda compilar desde el código:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
./target/release/irmind
```

La ejecución diaria de CI en `main` publica binarios sin firma para Linux, macOS y Windows cuando hubo cambios de código en las 24 horas anteriores. Verifica `SHA256SUMS` antes de ejecutarlos. La [guía de plataformas](docs/es/platforms.md) explica las comprobaciones, los almacenes de claves y el uso por SSH.

## Primer caso en la TUI

1. Ejecuta `irmind` sin subcomando. Elige el llavero del sistema o el archivo cifrado para las firmas y los secretos. El archivo funciona por SSH sin sesión gráfica. Guarda la huella de la clave pública del analista fuera de este equipo.
2. Pulsa `n` para crear un caso. Indica título, severidad y ventana temporal. Deja vacías las fuentes remotas para trabajar solo con evidencia local.
3. Abre el caso y escribe `/ingest`. Selecciona [examples/cloudtrail-alert.json](examples/cloudtrail-alert.json), que contiene únicamente datos sintéticos.
4. Elige un modelo explícitamente. Para un servicio local compatible con OpenAI, como Ollama, configura `IRMIND_MODEL` con un modelo instalado y `IRMIND_LLM_BASE_URL=http://127.0.0.1:11434/v1/`; después inicia `irmind --llm-module llm-openai-compatible`. También admite HTTPS. Para un proveedor remoto, sigue [configuración](docs/es/configuration.md) y aprueba antes su tratamiento de datos.
5. Vuelve a abrir el caso, describe la alerta sintética y revisa las llamadas propuestas. `/help` y `Ctrl+K` muestran acciones; `/pause` cancela una tarea.
6. Revisa la cronología y la evidencia. Usa `/verify`, `/report`, `/seal` y `/export`. El sellado y la exportación muestran el hash y la huella de la clave antes de confirmar.

Ningún LLM está habilitado por defecto. Puedes ingerir y verificar evidencia local sin uno.

## Módulos

Una feature de Cargo incluye el módulo en el binario; activarlo es un paso distinto. Todos siguen siendo experimentales.

| Módulo | Tipo | Feature | Estado | Configuración |
| --- | --- | --- | --- | --- |
| Compatible con OpenAI y Ollama local | LLM | incluida | experimental | [Módulos](docs/es/modules.md) |
| Anthropic | LLM | `llm-anthropic` | experimental | [Módulos](docs/es/modules.md) |
| DeepSeek | LLM | `llm-deepseek` | experimental | [Módulos](docs/es/modules.md) |
| OpenRouter | LLM | `llm-openrouter` | experimental | [Módulos](docs/es/modules.md) |
| Splunk | SIEM | `siem-splunk` | experimental | [Módulos](docs/es/modules.md) |
| AWS CloudTrail e IAM | nube | `cloud-aws` | experimental | [Módulos](docs/es/modules.md) |
| CrowdStrike | EDR | `edr-crowdstrike` | experimental | [Módulos](docs/es/modules.md) |
| SentinelOne | EDR | `edr-sentinelone` | experimental | [Módulos](docs/es/modules.md) |
| MISP | TI interna | `ti-misp` | experimental | [Módulos](docs/es/modules.md) |
| VirusTotal | enriquecimiento externo | `ti-virustotal` | experimental | [Módulos](docs/es/modules.md) |
| Parser JSON y CloudTrail | parser local | incluido | experimental | [Módulos](docs/es/modules.md) |
| Llavero del sistema | firma y secretos | `keystore-os` (por defecto) | experimental | [Módulos](docs/es/modules.md#llavero-del-sistema) |
| Archivo cifrado | firma y secretos | `keystore-file` (por defecto) | experimental | [Módulos](docs/es/modules.md#archivo-cifrado) |

## Seguridad

- Los puertos externos solo aceptan llamadas autorizadas; el modo desatendido solo permite lecturas dentro del alcance.
- El enriquecimiento externo necesita una aprobación firmada del analista; la contención está deshabilitada.
- La evidencia original queda en local; el contexto del modelo se limita, protege y redacta.
- La auditoría se encadena por hash y se firma; un paquete sellado se puede comprobar en otro equipo. Las migraciones de llavero entran en una cadena global firmada.
- La redacción puede pasar datos por alto. Un firmante local puede reescribir una cadena completa si su huella no está fijada fuera del equipo. Esta versión no es apta para producción.

Lee [security-model.md](docs/es/security-model.md) antes de conectar un proveedor.

## Más información

- [Inicio](docs/es/getting-started.md) · [Configuración](docs/es/configuration.md) · [Módulos](docs/es/modules.md)
- [Plataformas](docs/es/platforms.md) · [Seguridad](docs/es/security-model.md)
- [Arquitectura](docs/development/architecture.md) y [CLI](docs/development/cli.md), solo en inglés
- [Contribuciones](CONTRIBUTING.md) · [Reporte privado de vulnerabilidades](SECURITY.md) · [Licencias](LICENSE-MIT)

Licencia dual **MIT OR Apache-2.0**; consulta [LICENSE-MIT](LICENSE-MIT) y [LICENSE-APACHE](LICENSE-APACHE).
