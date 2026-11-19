Traducción de README.md en el commit df9a8bff2dfb803a6ce692b9ad5713f540b45057; si hay diferencias, prevalece la versión en inglés.

# IRMind — investigaciones en terminal con registro firmado

IRMind es un asistente de terminal de software libre para analistas DFIR que evalúan flujos de respuesta a incidentes. Investiga evidencia local y remota mediante una conversación, carga **skills** forenses cuando hacen falta y delega tareas acotadas en **subagentes** paralelos. El modelo propone, la **política** decide y la **custodia firmada** conserva lo ocurrido.


**Pre-1.0 · software para evaluación; no validado para incidentes reales.** Un analista ha probado una investigación de varios turnos con un modelo DeepSeek real y un dataset público de CloudTrail, incluida una skill y la confirmación de hallazgos. Es una [validación parcial](docs/es/manual-validation.md#investigación-parcial-con-modelo-real-2026-11-17); siguen pendientes las pruebas del conector real y de verificación.

## Prueba la demo sin conexión en dos minutos

Después de [instalar una release verificada](docs/es/platforms.md#verificar-una-versión-antes-de-instalar), ejecuta:

```sh
irmind demo
```

Sin configurar modelos, claves de API, cuentas ni coste. La interfaz real investiga datos sintéticos con un modelo identificado como guionizado; la demo no hace peticiones de red. Enter avanza, Espacio pausa y Esc sale. Al salir se borran la evidencia y las claves temporales. El recorrido narrado completo dura más; puedes explorar los primeros resultados inmediatamente.

![Presentación automática de IRMind con narración a todo el ancho, evidencia sintética, respuesta en streaming, aprobación firmada y verificación de custodia](docs/assets/demo.gif)

*Grabada con IRMind v0.5.3. La presentación completa usa el producto real con evidencia sintética, claves efímeras y un modelo guionizado sin red. Enter avanza; Espacio pausa; Esc sale.*

> [!WARNING]
> Antes de 1.0, cada versión menor puede cambiar los formatos de casos, exportaciones y definiciones sin migración. Conserva la versión de IRMind que creó un caso para abrirlo, verificarlo o exportarlo, o reingiere los originales verificados en un caso nuevo.

## Qué puedes hacer

- Abrir un caso, definir su alcance e investigar una alerta desde la terminal.
- Ingerir evidencia local y consultar la cronología y el grafo de entidades.
- Pedir a un modelo seleccionado que proponga consultas y cargue una [skill](docs/es/skills.md) forense firmada.
  Las skills incluidas se mantienen en [ns2switch/irmind-skills](https://github.com/ns2switch/irmind-skills), donde cualquiera puede proponer mejoras o skills nuevas sin escribir Rust. Las del núcleo llegan con cada release de IRMind; las del catálogo se instalarán con `/skills install catalog:<nombre>`.
- Revisar planes acotados, seguir tareas paralelas con `/subagents` y cancelarlas sin descartar lo ya terminado.
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

En macOS se recomienda la instalación binaria con el [tap de Homebrew](https://github.com/ns2switch/homebrew-irmind):

```sh
brew install ns2switch/irmind/irmind
brew upgrade ns2switch/irmind/irmind
```

La fórmula instala el binario y el auxiliar EVTX desde GitHub Releases con SHA-256 fijados, sin compilar IRMind. La [guía de plataformas](docs/es/platforms.md#homebrew) explica la confianza y cómo conservar la versión que creó un caso antes de actualizar.

Consulta [Code signing policy — Política de firma de código](CODE_SIGNING.md)
([versión en español](CODE_SIGNING.es.md)): verificación actual, roles del equipo,
privacidad y estado de la firma nativa por plataforma.
La firma Authenticode de Windows sigue pendiente; se reevaluará SignPath
Foundation tras el lanzamiento público. No hay patrocinio de firma vigente.

Empieza por [la instalación verificada](docs/es/platforms.md#verificar-una-versión-antes-de-instalar): descarga y verifica el instalador antes de ejecutarlo, sin pasar scripts de red directamente a una shell. Compilar desde código es opcional para [contribuir](CONTRIBUTING.es.md).



La [versión preliminar v0.5.4](https://github.com/ns2switch/irmind/releases/tag/v0.5.4) ofrece bundles Sigstore sin claves permanentes, procedencia de GitHub, un SBOM y hashes. Descarga el binario y `SHA256SUMS`, verifica sus hashes y la identidad exacta del firmante con cosign 3.1.3 o posterior y comprueba `gh attestation verify`. La [guía de plataformas](docs/es/platforms.md) da los comandos. Tras verificar una copia descargada de [install.sh](install.sh) o [install.ps1](install.ps1), el instalador puede hacer esas comprobaciones.

Conserva la versión exacta de IRMind que creó el caso. La versión 0.5.4 usa el marcador de caso 4 y export V8; consulta la [nota de formatos](CHANGELOG.md). La [política de versiones](docs/development/decisions.md#pre-10-format-policy) explica cómo conservar el ejecutable creador o reingerir los originales verificados.

```sh
# Tras descargar el binario, SHA256SUMS y ambos bundles .sigstore.json:
tag=v0.5.4; binary=irmind-linux-x86_64
for file in "$binary" SHA256SUMS; do
  cosign verify-blob "$file" --bundle "$file.sigstore.json" --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/$tag" --certificate-oidc-issuer https://token.actions.githubusercontent.com
done
awk -v name="$binary" '$2 == name { print }' SHA256SUMS | sha256sum -c -
gh attestation verify "$binary" -R ns2switch/irmind
```

## Explora la demo guiada

Ejecuta `irmind demo` o escribe `/demo` en el inicio. El producto teclea comandos y realiza una investigación de diez pasos por ti. Un panel de narración grande explica la evidencia, las consultas locales, la respuesta en streaming, la aprobación firmada y las comprobaciones de custodia. No necesitas clave de API, passphrase, cuenta ni red. El caso temporal aislado y las claves se borran al salir.

Usa **Enter** para avanzar, **Retroceso** para revisar un paso, **Espacio** para pausar o reanudar y **Esc** para salir. La demo admite **80 × 24 celdas**; se recomiendan **100 × 40**. PgUp/PgDn desplaza la narración compacta y pausa la reproducción. La consulta externa simulada pasa por la política y se aprueba con la clave temporal del analista; no sale ninguna petición del equipo. Al terminar puedes explorar el caso sellado, aprender a crear uno propio o salir. La [guía de primeros pasos](docs/es/getting-started.md#pruébalo-en-cinco-minutos) muestra las diez escenas.

## Primer caso en la TUI

1. Ejecuta `irmind`. El asistente configura los backends de firma y secretos; si eliges el archivo cifrado, introduce y confirma la passphrase en campos enmascarados. Guarda la huella de la clave del analista fuera del equipo. Elige un modelo en el asistente o escribe `/settings model` después. Ningún modelo está seleccionado por defecto.
2. Escribe `/new`, introduce un título y elige la severidad con las flechas. Enter crea un caso local; el segundo paso del formulario permite añadir un alcance remoto opcional.
3. En el caso, escribe `/ingest` y selecciona [el ejemplo sintético de CloudTrail](examples/cloudtrail-alert.json). IRMind calcula su hash en la ubicación original; la copia es opcional y explícita.
4. Pregunta qué sugiere la asunción de rol sintética y pulsa Enter. La respuesta aparece de forma incremental. También puedes conversar sin iniciar una investigación.
5. Revisa la llamada propuesta. Una consulta externa espera una aprobación firmada; elige una opción numerada con las flechas y Enter. Escribe `/` para ver comandos, `Ctrl+K` para la paleta, `/pause` para cancelar o `/continue` después de un límite del modelo.
6. Usa `/verify <directorio-origen>` para comprobar el original; revisa `/report` antes de `/seal` y `/export`. Estas dos acciones muestran el hash del caso y la huella de la clave antes de confirmar.

Ningún LLM está habilitado por defecto. Puedes ingerir y verificar evidencia local sin uno.
En los siguientes arranques, IRMind verifica y reabre el último caso abierto que usaste. Usa `/home` para volver a la lista o `/settings preferences` para desactivar esta opción. `/settings` también reúne conectores, credenciales, ratón y tema. `/help` enumera los comandos y las teclas reservadas: Enter, Esc, flechas, Tab/Shift+Tab, PgUp/PgDn, Ctrl+C, Ctrl+K y Ctrl+O. Ctrl+O o `/expand` despliega o pliega la tarjeta seleccionada o la última plegable sin salir del campo de entrada. Los caracteres imprimibles, incluido `/`, se escriben en el campo de formulario que tiene el foco; el pegado también funciona allí.

Usa `/skills` para inspeccionar y gestionar los 15 métodos incluidos de nube, Windows, Linux, red y Kubernetes. Invoca `/windows-triage`, `/linux-triage` o `/aws-credential-compromise` dentro de un caso. El modelo los carga cuando hacen falta; no amplían permisos. Consulta la [guía de skills](docs/es/skills.md).

## Módulos

La versión 0.5 usa una única cadena decodificador de origen → mapeo identificado → escritor V3 en la CLI, la TUI y la demo. Solo lee CaseCreated versión 4 y la exportación V8. [Los casos anteriores necesitan su versión creadora o una ingesta nueva](docs/development/case-migration.md).

La compilación normal incluye todos los módulos de producto actuales y ambos llaveros. Los modelos remotos y conectores permanecen desactivados hasta seleccionarlos y configurarlos. Los parsers locales se eligen por detección del contenido. Una compilación mínima usa `--no-default-features --features keystore-file` porque siempre se necesita firma y un backend de secretos. Todos siguen siendo experimentales.

`/settings model` también ofrece LM Studio y vLLM locales, y Mistral, Groq, Google Gemini, xAI y Together remotos. Usan el módulo compatible con OpenAI; consulta [URL y límites](docs/es/modules.md#compatible-con-openai).

| Módulo | Tipo | Feature | Estado | Configuración |
| --- | --- | --- | --- | --- |
| Compatible con OpenAI y Ollama local | LLM | incluida | experimental | [Módulos](docs/es/modules.md) |
| Anthropic | LLM | `llm-anthropic` | experimental | [Módulos](docs/es/modules.md) |
| DeepSeek | LLM | `llm-deepseek` | experimental | [Módulos](docs/es/modules.md) |
| OpenRouter | LLM | `llm-openrouter` | experimental | [Módulos](docs/es/modules.md) |
| Elastic | SIEM | `siem-elastic` | experimental | [Elastic](docs/es/modules.md#elasticsearch-y-elastic-security) |
| Google SecOps | SIEM | `siem-chronicle` | experimental | [Google SecOps](docs/es/modules.md#google-secops-chronicle) |
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
| Mapeo de eventos comunes de CloudTrail | mapeo local | `mapping-cloudtrail` | experimental | [Mapeos](docs/es/mappings.md) |
| Mapeo de eventos comunes Windows | mapeo local | `mapping-evtx` | experimental | [Mapeos](docs/es/mappings.md#registro-de-eventos-de-windows) |
| Mapeo de eventos comunes ECS | mapeo local | `mapping-ecs` | experimental | [Mapeos](docs/es/mappings.md) |
| Mapeo OCSF de eventos comunes | mapeo local | `mapping-ocsf` | experimental | [Mapeos](docs/es/mappings.md) |
| Parser de Elastic Common Schema | parser local | `parser-ecs` (por defecto) | experimental | [ECS](docs/es/modules.md#parser-de-elastic-common-schema) |
| Parser de OCSF JSON y Parquet | parser local | `parser-ocsf` (por defecto) | experimental | [OCSF](docs/es/modules.md#parser-de-ocsf) |
| Parser de Velociraptor | parser local | `parser-velociraptor` (por defecto) | experimental | [Velociraptor](docs/es/modules.md#parser-de-velociraptor) |
| Parser de Hayabusa | parser local | `parser-hayabusa` (por defecto) | experimental | [Hayabusa](docs/es/modules.md#parser-de-hayabusa) |
| Parser de Chainsaw | parser local | `parser-chainsaw` (por defecto) | experimental | [Chainsaw](docs/es/modules.md#parser-de-chainsaw) |
| Parser de plaso | parser local | `parser-plaso` (por defecto) | experimental | [plaso](docs/es/modules.md#parser-de-plaso) |
| Zeek | Parser | `parser-zeek` | experimental | [Configuración](docs/es/modules.md#parser-de-zeek) |
| Suricata EVE | Parser | `parser-suricata` | experimental | [Configuración](docs/es/modules.md#parser-de-suricata-eve) |
| Parser declarativo | parser local | `parser-declarative` (por defecto) | experimental | [Formatos propios](docs/es/parsers.md) |
| GCP Cloud Audit / GKE | parser y mapeo locales | `parser-gcp-audit` (por defecto) | experimental | [GCP y GKE](docs/es/parsers.md#cloud-audit-logs-de-gcp-y-gke) |
| Microsoft Entra ID | parser y mapeo locales | `parser-entra` (por defecto) | experimental | [Entra](docs/es/parsers.md#microsoft-entra-id) |
| Microsoft 365 audit | parser y mapeo locales | `parser-m365` (por defecto) | experimental | [M365](docs/es/parsers.md) |
| Okta System Log | parser y mapeo locales | `parser-okta` (por defecto) | experimental | [Okta](docs/es/parsers.md) |
| Depuración de DNS Server de Windows | parser y mapeo locales | `parser-windows-dns`, `mapping-windows-dns` (por defecto) | experimental | [Windows DNS](docs/es/parsers.md#registros-de-depuración-de-dns-server) |
| Accesos IIS W3C | parser y mapeo locales | `parser-iis-w3c`, `mapping-iis-w3c` (por defecto) | experimental | [IIS W3C](docs/es/parsers.md#iis-w3c) |
| Route 53 Resolver (DNS de red) | parser y mapeo locales | `parser-route53`, `mapping-route53` (por defecto) | experimental | [Route 53 Resolver](docs/es/parsers.md#route-53-vpc-resolver) |
| Auditoría de GitHub | parser y mapeo locales | `parser-github-audit`, `mapping-github-audit` (por defecto) | experimental | [Auditoría de GitHub](docs/es/parsers.md#auditoría-de-github) |
| Reports API de Google Workspace | parser y mapeo locales | `parser-google-workspace`, `mapping-google-workspace` (por defecto) | experimental | [Google Workspace](docs/es/parsers.md#reports-api-de-google-workspace) |
| Unified Log y eslogger de macOS | parser y mapeo locales | `parser-macos`, `mapping-macos` (por defecto) | experimental | [Exports de macOS](docs/es/parsers.md#exports-de-macos) |
| CrowdStrike FDR | parser y mapeo locales | `parser-fdr`, `mapping-fdr` (por defecto) | experimental | [FDR](docs/es/parsers.md#crowdstrike-falcon-data-replicator) |
| Exports de Microsoft Defender | parser y mapeo locales | `parser-defender`, `mapping-defender` (por defecto) | experimental | [Defender](docs/es/parsers.md#exports-de-microsoft-defender) |
| Exportaciones de correo | parser y mapeo local | `parser-email`, `mapping-email` (por defecto) | experimental | [Correo](docs/es/parsers.md#exportaciones-de-correo) |
| AWS GuardDuty | parser y mapeo locales | `parser-guardduty` (por defecto) | experimental | [GuardDuty](docs/es/parsers.md#exports-de-guardduty) |
| AWS VPC Flow Logs | parser y mapeo local | `parser-vpc-flow`, `mapping-cloud-flow` (por defecto) | experimental | [Flujos de nube](docs/es/parsers.md#exportaciones-de-flujos-de-red-en-la-nube) |
| Azure VNet/NSG flow logs | parser y mapeo local | `parser-azure-flow`, `mapping-cloud-flow` (por defecto) | experimental | [Flujos de nube](docs/es/parsers.md#exportaciones-de-flujos-de-red-en-la-nube) |
| GCP VPC Flow Logs | parser y mapeo local | `parser-gcp-flow`, `mapping-cloud-flow` (por defecto) | experimental | [Flujos de nube](docs/es/parsers.md#exportaciones-de-flujos-de-red-en-la-nube) |
| Auditoría Kubernetes | parser y mapeo locales | `parser-kubernetes` (por defecto) | experimental | [Contexto de clúster](docs/es/parsers.md#interpretación-de-kubernetes-y-falco) |
| Falco | parser y mapeo locales | `parser-falco` (por defecto) | experimental | [Alertas de origen](docs/es/parsers.md#interpretación-de-kubernetes-y-falco) |
| Logs de Linux | parser local | `parser-linux` (por defecto) | experimental | [Linux](docs/es/modules.md#logs-de-linux) |
| Windows EVTX | parser local aislado | `parser-evtx` (por defecto) | experimental | [EVTX](docs/es/modules.md#windows-evtx) |
| Parser Syslog | parser local | `parser-syslog` (por defecto) | experimental | [Syslog](docs/es/modules.md#parser-syslog) |
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
- **v0.2 (entregada):** Parsers modulares, artefactos precisos y auxiliar EVTX aislado.
- **v0.3:** Eventos comunes tipados, decodificadores y mapeos separados, solo escritura V3, ingesta multinúcleo y conectores SIEM experimentales.
- **v0.4:** Añadir skills forenses firmadas y de carga progresiva.
- **v0.5 (entregada):** Subagentes paralelos acotados, ramas firmadas y eventos en streaming.
- **Lanzamiento público:** Publicar la demo, el benchmark y el catálogo inicial de skills.
- **v0.6:** Añadir consultas en origen con presupuestos.
- **v0.7:** Añadir detecciones locales, informes exportables, extensiones controladas y una API del motor.
- **1.0:** Estabilizar formatos firmados y completar revisiones externas de seguridad y conectores.

La [hoja de ruta pública](docs/es/roadmap.md) describe intenciones, sin compromisos de publicación.

## Contribuir

Una de las formas más sencillas de colaborar es hacerlo en [el repositorio de skills](https://github.com/ns2switch/irmind-skills): mejorar metodologías, describir las fuentes necesarias y los falsos positivos, o aportar episodios sintéticos de evaluación. No hace falta escribir Rust. Consulta la [guía para contribuir skills](https://github.com/ns2switch/irmind-skills/blob/main/CONTRIBUTING.es.md).

Consulta [CONTRIBUTING.es.md](CONTRIBUTING.es.md) para las reglas de DCO y datos sintéticos.

## Más información

- [Inicio](docs/es/getting-started.md) · [Configuración](docs/es/configuration.md) · [Módulos](docs/es/modules.md)
- [Investigaciones en paralelo](docs/es/subagents.md) · [Skills forenses](docs/es/skills.md) · [Repositorio de skills](https://github.com/ns2switch/irmind-skills)
- [Plataformas](docs/es/platforms.md) · [Seguridad](docs/es/security-model.md)
- [Arquitectura](docs/development/architecture.md) y [CLI](docs/development/cli.md), solo en inglés
- [Hoja de ruta](docs/es/roadmap.md)
- [Contribuciones](CONTRIBUTING.es.md) · [Código de conducta](CODE_OF_CONDUCT.es.md) · [Reporte privado de vulnerabilidades](SECURITY.md) · [Licencias](LICENSE-MIT)

Licencia dual **MIT OR Apache-2.0**; consulta [LICENSE-MIT](LICENSE-MIT) y [LICENSE-APACHE](LICENSE-APACHE).
