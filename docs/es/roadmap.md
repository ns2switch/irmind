Traducción de docs/development/roadmap.md en el commit a2c7c28ebeb8503d16523e7f0f5744f80b5896df; si hay diferencias, prevalece la versión en inglés.

# Hoja de ruta

IRMind es un asistente agéntico de terminal para respuesta a incidentes y análisis forense: el analista conversa con un agente que investiga evidencia local y remota, carga skills forenses cuando hacen falta y delega trabajo acotado en subagentes paralelos. El modelo propone, la política decide y cada acción queda firmada.

Esta página es para quienes contribuyen o evalúan el proyecto. Expresa intenciones, sin comprometer fechas. La [versión inglesa](../development/roadmap.md) prevalece y el [modelo de seguridad](security-model.md) explica los límites actuales.

## Entregado en 0.1.0 y 0.1.1

Las versiones preliminares incluyen la TUI para casos, conectores sujetos a política, custodia firmada, conversaciones protegidas, consultas acotadas sobre Parquet, demo sintética, registro de detección de parsers, instaladores verificados y binarios firmados y atestados con Sigstore. El [registro de cambios](../../CHANGELOG.md) detalla lo entregado. H5 está hecha por decisión del analista; siguen pendientes de registro los pasos no descritos y la validación de un conector real.

## v0.1.x: estabilizar la versión preliminar

- H5 está hecha por decisión del analista tras probar un saludo con DeepSeek real. Registrar los pasos restantes y probar un conector en un entorno real. Consulta el [registro de validación](manual-validation.md#registro-de-resultados).
- Mantener la firma Sigstore sin claves, las atestaciones de GitHub y el SBOM entregados en v0.1.1.
- Firmar los binarios de macOS con Developer ID, hardened runtime y notarización mediante `notarytool`, desde un entorno de release protegido que solo se ejecuta para tags. La persona mantenedora debe proporcionar el certificado y la clave de App Store Connect antes de implementarlo.
- Solicitar acceso al programa SignPath Foundation para firmar Windows con Authenticode. Publicar `CODE_SIGNING.md` con la política de firma, aprobación de releases y procedencia de builds. La solicitud corresponde a la persona mantenedora.
- Mantener instaladores que verifican checksums y el binario Linux aarch64. Homebrew, AUR, Nix, winget y Scoop quedan abiertos a empaquetadores de la comunidad.
- Reducir el espacio del artefacto de co-observación, mejorar `entity_lookup` y acotar el peor caso de `path` de tres saltos ([issue #37](https://github.com/ns2switch/irmind/issues/37)).

## v0.2: parsers y conectores

Syslog y las exportaciones de Linux están disponibles como módulos experimentales. Linux cubre autenticación, correlación acotada de auditd, journald JSON y logs HTTP common/combined. [La cobertura y selección de parsers](parsers.md) describe sus límites actuales.

- Ampliar el registro de detección: cada parser es un módulo Cargo que se activa cuando reconoce el log. Una coincidencia ambigua requiere que el analista elija; una elección forzada queda auditada.
- Añadir parsers experimentales de EVTX; syslog; autenticación, auditd, journald, nginx y Apache en Linux; ECS; OCSF; Velociraptor; Hayabusa; Chainsaw; plaso; EZTools; Zeek; Suricata EVE; y un formato declarativo definido por el usuario.
- Añadir conectores experimentales `siem-elastic` y `siem-chronicle`, con consultas estructuradas, permisos mínimos de lectura, contratos sintéticos y evidencia firmada.
- Mantener los formatos restantes como [issues de entrada](https://github.com/ns2switch/irmind/issues?q=is%3Aissue+label%3A%22good+first+issue%22).

Los artefactos binarios de Windows (registro, `$MFT`, Prefetch, LNK, SRUM y Amcache) se cubren mediante las exportaciones procesadas de EZTools, Velociraptor y plaso. Consulta [la cobertura actual de Windows](parsers.md#cobertura-de-windows) para los formatos admitidos. Los [futuros parsers nativos de registro y `$MFT`](https://github.com/ns2switch/irmind/issues/159) dependerán de la demanda y deberán seguir el mismo modelo de proceso auxiliar aislado aprobado para EVTX, sin incorporar decodificadores binarios al proceso principal.

## v0.3: skills forenses

- Aprobar `docs/development/skills-design.md` antes de implementar: formato, carga progresiva, instalación firmada, confianza y relación con la política.
- Una skill es una carpeta con `SKILL.md` que describe una metodología, más plantillas de consulta, reglas Sigma o mapeos opcionales. Los métodos iniciales también cubren ransomware en Windows, persistencia en Linux y BEC en M365.
- Incluir [**Windows triage**](https://github.com/ns2switch/irmind/issues/157): guiar una colección sintética y acotada con KAPE o Velociraptor de logs de eventos, registro y sus logs de transacciones, `$MFT`, Prefetch, LNK, SRUM y Amcache. Ingerir primero timelines de Hayabusa derivados de EVTX o CSV de EvtxECmd (EVTX directo cuando exista el auxiliar aislado), y después las exportaciones de PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd, LECmd, RECmd batch y SrumECmd. Investigar en orden: inicio de sesión → ejecución → persistencia → movimiento lateral → exfiltración. Correlacionar fuentes independientes y confirmar hallazgos con evidencia. El analista ejecuta las herramientas externas; una skill no concede permisos de ejecución.
- Incluir **Linux triage** para autenticación, ejecución y persistencia, y **AWS credential compromise** para CloudTrail, actividad de roles y sesiones, y cambios en IAM.
- El modelo recibe primero nombre y descripción y carga el contenido completo solo cuando lo necesita. Las skills pueden venir incluidas, de una organización o instaladas por un analista.
- La instalación se firma y el caso registra el hash de la versión usada. Una skill declara herramientas necesarias, pero no amplía permisos. El contenido de terceros sigue sin ser de confianza hasta que lo firma el analista.
- `/skills` permite listar, instalar, inspeccionar y deshabilitar. Las skills invocables aparecen como comandos. El catálogo comunitario vive en otro repositorio.

## v0.4: subagentes y trabajo paralelo

- Aprobar `docs/development/subagents-design.md` antes de implementar: tipos, límites, clave Agent, aprobaciones, ramas de eventos y fusión determinista.
- El agente principal delega tareas acotadas a subagentes paralelos con contexto propio. Habrá tipos de triage, nube, endpoint, red e inteligencia de amenazas, y tipos comunitarios definidos en archivo.
- Los subagentes heredan el alcance del caso, no pueden ampliarlo ni aprobar llamadas. Sus solicitudes van al analista, firman con la clave Agent y su salida vuelve como contenido no confiable.
- Aplicar límites de concurrencia, rondas y tokens por subagente y un presupuesto total por turno. La TUI muestra la actividad y permite cancelarla.
- Cada subagente usa una rama de eventos que se fusiona de forma determinista con la cadena firmada del caso. La TUI pasa a consumir el flujo de eventos del motor.

## Lanzamiento público

Publicar un artículo, un vídeo de demostración con datos sintéticos, publicaciones comunitarias, un benchmark público de modelos con HuntEval y un catálogo inicial de skills. El lanzamiento sigue a v0.4 e incluye el repositorio comunitario de skills.

## v0.5: consultas en origen

Consultas estructuradas y con presupuesto en Athena, CloudTrail Lake, Security Lake, BigQuery, Cloud Logging Log Analytics, Azure Data Explorer y Azure Log Analytics. Los resultados se firman y las fuentes originales en la nube se pueden volver a verificar tras sellar. Consulta el [diseño](../development/cloud-query-design.md).

## v0.6: detección, informes, extensibilidad y API del motor

- Ejecutar reglas Sigma sobre Parquet local sin LLM.
- Exportar informes Markdown y PDF que citan solo evidencia confirmada.
- Evaluar IRMind como deployment completo con el protocolo HuntEval.
- Permitir hooks locales firmados antes o después de llamadas a herramientas.
- Ofrecer un cliente MCP opcional y desactivado por defecto, con modelo de amenazas. Cada herramienta declara riesgo, pasa por política y devuelve contenido no confiable.
- Aprobar el diseño de una API del motor antes de añadir el futuro subcomando `serve` de `irmind`. El protocolo versionado transmite eventos por stdio, socket Unix o named pipe de Windows, sin TCP abierto por defecto. Las claves permanecen en IRMind: el cliente solicita aprobación, el analista confirma e IRMind firma.

## Criterios para 1.0

- Formatos firmados estables para casos, manifiestos, skills, subagentes y protocolo del motor, con migraciones probadas.
- Confirmar antes de 1.0 una política de compatibilidad de parsers: desde 1.0, conservar una versión obsoleta para reconstrucción y verificación durante al menos dos versiones menores posteriores, o un periodo equivalente. Anunciar su retirada con antelación en el CHANGELOG y ofrecer un procedimiento de migración. Esta propuesta no recupera lectores retirados anteriores a 1.0.
- Revisión externa de seguridad.
- Al menos tres conectores validados en entornos reales de pruebas.
- Binarios de release firmados en Linux, macOS y Windows.
- Modelo de amenazas revisado para skills, subagentes, MCP y API del motor.

## Fuera de este repositorio

Una interfaz gráfica para trabajo multiagente, el gateway desatendido y los watches vivirán en otro repositorio que consumirá la API del motor de IRMind.

## Fuera del alcance actual

La contención (`RiskLevel::Contain`) y el anclaje externo de sellos quedan aplazados. Ningún LLM ni conector se activa por defecto.
