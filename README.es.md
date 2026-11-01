Traducción de README.md en el commit eb6637f06b3af70cbc6c7bb8242883b612d13894; si hay diferencias, prevalece la versión en inglés.

# IRMind — Respuesta asistida a incidentes

Cliente de IA en terminal para investigaciones de seguridad, con llamadas a herramientas sujetas a política y cadena de custodia firmada.

IRMind es un asistente agéntico de terminal para respuesta a incidentes y análisis forense: el analista conversa con un agente que investiga evidencia local y remota, carga skills forenses cuando hacen falta y delega trabajo acotado en subagentes paralelos. El modelo propone, la política decide y todo queda firmado.

![Demostración sintética de IRMind: caso reanudado, comandos, ingesta, respuesta en streaming y aprobación numerada](docs/assets/demo.gif)

*La demostración usa evidencia sintética y una clave efímera. El modelo guionizado no necesita red ni cuenta.*

> [!WARNING]
> IRMind 0.1.2 es una versión preliminar para evaluar con datos sintéticos. No ha superado la validación manual con un modelo ni con conectores reales. No la uses para incidentes reales ni datos sensibles.

## Qué puedes hacer

- Abrir un caso, definir su alcance e investigar una alerta desde la terminal.
- Ingerir evidencia local y consultar la cronología y el grafo de entidades.
- Pedir a un modelo seleccionado que proponga consultas de investigación.
- Revisar y firmar aprobaciones antes de un enriquecimiento externo.
- Consultar registros indexados y originales disponibles mientras el modelo recibe datos limitados y redactados.
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

La [versión preliminar v0.1.2](https://github.com/ns2switch/irmind/releases/tag/v0.1.2) ofrece bundles Sigstore sin claves permanentes, procedencia de GitHub, un SBOM y hashes. Descarga el binario y `SHA256SUMS`, verifica sus hashes y la identidad exacta del firmante con cosign 3.1.3 o posterior y comprueba `gh attestation verify`. La [guía de plataformas](docs/es/platforms.md) da los comandos. Tras verificar una copia descargada de [install.sh](install.sh) o [install.ps1](install.ps1), el instalador puede hacer esas comprobaciones.

```sh
# Tras descargar el binario, SHA256SUMS y ambos bundles .sigstore.json:
tag=v0.1.2; binary=irmind-linux-x86_64
for file in "$binary" SHA256SUMS; do
  cosign verify-blob "$file" --bundle "$file.sigstore.json" --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/$tag" --certificate-oidc-issuer https://token.actions.githubusercontent.com
done
awk -v name="$binary" '$2 == name { print }' SHA256SUMS | sha256sum -c -
gh attestation verify "$binary" -R ns2switch/irmind
```

## Pruébalo en cinco minutos

Ejecuta `irmind demo` desde una compilación verificada o escribe `/demo` en el inicio. IRMind abre un caso temporal y firmado con un episodio sintético de HuntEval. Crea un llavero cifrado con una passphrase aleatoria, sin pedírtela, y borra toda la demo al salir. Si un modelo de Ollama local declara soporte de herramientas, puedes elegirlo con las flechas; en caso contrario, usa el modelo guionizado, claramente identificado y sin conexión. Nunca se utiliza un proveedor remoto.

Pregunta «¿Qué ocurrió en este episodio sintético?» para ver una búsqueda local, un hallazgo propuesto y una consulta de enriquecimiento que sigue requiriendo aprobación firmada. El resultado externo es simulado y no hace llamadas de red. Confirma un hallazgo y escribe `/demo check` para compararlo localmente con las respuestas incluidas. Estas nunca entran en el contexto del modelo. Al salir, usa `/new` y `/settings` para empezar un caso real.

## Primer caso en la TUI

1. Ejecuta `irmind`. El asistente configura los backends de firma y secretos; si eliges el archivo cifrado, introduce y confirma la passphrase en campos enmascarados. Guarda la huella de la clave del analista fuera del equipo. Elige un modelo en el asistente o escribe `/settings model` después. Ningún modelo está seleccionado por defecto.
2. Escribe `/new`, introduce un título y elige la severidad con las flechas. Enter crea un caso local; el segundo paso del formulario permite añadir un alcance remoto opcional.
3. En el caso, escribe `/ingest` y selecciona [el ejemplo sintético de CloudTrail](examples/cloudtrail-alert.json). IRMind calcula su hash en la ubicación original; la copia es opcional y explícita.
4. Pregunta qué sugiere la asunción de rol sintética y pulsa Enter. La respuesta aparece de forma incremental. También puedes conversar sin iniciar una investigación.
5. Revisa la llamada propuesta. Una consulta externa espera una aprobación firmada; elige una opción numerada con las flechas y Enter. Escribe `/` para ver comandos, `Ctrl+K` para la paleta, `/pause` para cancelar o `/continue` después de un límite del modelo.
6. Usa `/verify <directorio-origen>` para comprobar el original; revisa `/report` antes de `/seal` y `/export`. Estas dos acciones muestran el hash del caso y la huella de la clave antes de confirmar.

Ningún LLM está habilitado por defecto. Puedes ingerir y verificar evidencia local sin uno.
En los siguientes arranques, IRMind verifica y reabre el último caso abierto que usaste. Usa `/home` para volver a la lista o `/settings preferences` para desactivar esta opción. `/settings` también reúne conectores, credenciales, ratón y tema. `/help` enumera los comandos y las teclas reservadas: Enter, Esc, flechas, Tab/Shift+Tab, PgUp/PgDn, Ctrl+C, Ctrl+K y Ctrl+O. Los caracteres imprimibles, incluido `/`, se escriben en el campo de formulario que tiene el foco; el pegado también funciona allí.

## Módulos

La compilación normal incluye todos los módulos de producto actuales y ambos llaveros. Ninguno se activa hasta seleccionarlo y configurarlo. Una compilación mínima usa `--no-default-features --features keystore-file` porque siempre se necesita firma y un backend de secretos. Todos siguen siendo experimentales.

`/settings model` también ofrece LM Studio y vLLM locales, y Mistral, Groq, Google Gemini, xAI y Together remotos. Usan el módulo compatible con OpenAI; consulta [URL y límites](docs/es/modules.md#compatible-con-openai).

| Módulo | Tipo | Feature | Estado | Configuración |
| --- | --- | --- | --- | --- |
| Compatible con OpenAI y Ollama local | LLM | incluida | experimental | [Módulos](docs/es/modules.md) |
| Anthropic | LLM | `llm-anthropic` | experimental | [Módulos](docs/es/modules.md) |
| DeepSeek | LLM | `llm-deepseek` | experimental | [Módulos](docs/es/modules.md) |
| OpenRouter | LLM | `llm-openrouter` | experimental | [Módulos](docs/es/modules.md) |
| Splunk | SIEM | `siem-splunk` | experimental | [Módulos](docs/es/modules.md) |
| AWS CloudTrail e IAM | nube | `cloud-aws` | experimental | [Módulos](docs/es/modules.md) |
| Almacenamiento S3 | almacenamiento en nube | `storage-s3` | experimental | [Objetos](docs/es/modules.md#almacenamiento-de-objetos-en-la-nube-s3-gcs-y-azure-blob) |
| Almacenamiento GCS | almacenamiento en nube | `storage-gcs` | experimental | [Objetos](docs/es/modules.md#almacenamiento-de-objetos-en-la-nube-s3-gcs-y-azure-blob) |
| Almacenamiento Azure Blob | almacenamiento en nube | `storage-azure` | experimental | [Objetos](docs/es/modules.md#almacenamiento-de-objetos-en-la-nube-s3-gcs-y-azure-blob) |
| CrowdStrike | EDR | `edr-crowdstrike` | experimental | [Módulos](docs/es/modules.md) |
| SentinelOne | EDR | `edr-sentinelone` | experimental | [Módulos](docs/es/modules.md) |
| MISP | TI interna | `ti-misp` | experimental | [Módulos](docs/es/modules.md) |
| VirusTotal | enriquecimiento externo | `ti-virustotal` | experimental | [Módulos](docs/es/modules.md) |
| Parser JSON y logs de nube exportados | parser local | `parser-json` (por defecto) | experimental | [Módulos](docs/es/modules.md) |
| Parser de Elastic Common Schema | parser local | `parser-ecs` (por defecto) | experimental | [ECS](docs/es/modules.md#parser-de-elastic-common-schema) |
| Parser de OCSF JSON y Parquet | parser local | `parser-ocsf` (por defecto) | experimental | [OCSF](docs/es/modules.md#parser-de-ocsf) |
| Parser de Velociraptor | parser local | `parser-velociraptor` (por defecto) | experimental | [Velociraptor](docs/es/modules.md#parser-de-velociraptor) |
| Parser de Hayabusa | parser local | `parser-hayabusa` (por defecto) | experimental | [Hayabusa](docs/es/modules.md#parser-de-hayabusa) |
| Parser de Chainsaw | parser local | `parser-chainsaw` (por defecto) | experimental | [Chainsaw](docs/es/modules.md#parser-de-chainsaw) |
| Parser de plaso | parser local | `parser-plaso` (por defecto) | experimental | [plaso](docs/es/modules.md#parser-de-plaso) |
| Parser de EZTools | parser local | `parser-eztools` (por defecto) | experimental | [EZTools](docs/es/modules.md#parser-de-eztools) |
| Llavero del sistema | firma y secretos | `keystore-os` (por defecto) | experimental | [Módulos](docs/es/modules.md#llavero-del-sistema) |
| Archivo cifrado | firma y secretos | `keystore-file` (por defecto) | experimental | [Módulos](docs/es/modules.md#archivo-cifrado) |

## Seguridad

- Los puertos externos solo aceptan llamadas autorizadas; el modo desatendido solo permite lecturas dentro del alcance.
- El enriquecimiento externo necesita una aprobación firmada del analista; la contención está deshabilitada.
- La evidencia original queda en local; el contexto del modelo se limita, protege y redacta.
- La auditoría se encadena por hash y se firma; un paquete sellado se puede comprobar en otro equipo. Las migraciones de llavero entran en una cadena global firmada.
- La redacción puede pasar datos por alto. Un firmante local puede reescribir una cadena completa si su huella no está fijada fuera del equipo. Esta versión no es apta para producción.

Lee [security-model.md](docs/es/security-model.md) antes de conectar un proveedor.

## Hoja de ruta

- **v0.1.x:** Estabilizar la versión preliminar, validar un modelo y un conector, y añadir firma nativa por plataforma.
- **v0.2:** Añadir parsers modulares y conectores SIEM con consultas estructuradas.
- **v0.3:** Añadir skills forenses firmadas y de carga progresiva.
- **v0.4:** Añadir subagentes paralelos acotados y eventos en streaming.
- **Lanzamiento público:** Publicar la demo, el benchmark y el catálogo inicial de skills.
- **v0.5:** Añadir consultas en origen con presupuestos.
- **v0.6:** Añadir detecciones locales, informes exportables, extensiones controladas y una API del motor.
- **1.0:** Estabilizar formatos firmados y completar revisiones externas de seguridad y conectores.

La [hoja de ruta pública](docs/es/roadmap.md) describe intenciones, sin compromisos de publicación.

## Más información

- [Inicio](docs/es/getting-started.md) · [Configuración](docs/es/configuration.md) · [Módulos](docs/es/modules.md)
- [Plataformas](docs/es/platforms.md) · [Seguridad](docs/es/security-model.md)
- [Arquitectura](docs/development/architecture.md) y [CLI](docs/development/cli.md), solo en inglés
- [Hoja de ruta](docs/es/roadmap.md)
- [Contribuciones](CONTRIBUTING.es.md) · [Código de conducta](CODE_OF_CONDUCT.es.md) · [Reporte privado de vulnerabilidades](SECURITY.md) · [Licencias](LICENSE-MIT)

Licencia dual **MIT OR Apache-2.0**; consulta [LICENSE-MIT](LICENSE-MIT) y [LICENSE-APACHE](LICENSE-APACHE).
