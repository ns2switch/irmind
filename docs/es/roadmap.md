Traducción de docs/development/roadmap.md en el commit 3a60c444c467f58b832eb99f83b111eaec8b79fa; si hay diferencias, prevalece la versión en inglés.

# Hoja de ruta

IRMind es un asistente agéntico de terminal para respuesta a incidentes y análisis forense: el analista conversa con un agente que investiga evidencia local y remota, carga skills forenses cuando hacen falta y delega trabajo acotado en subagentes paralelos. El modelo propone, la política decide y cada acción queda firmada.

Esta página es para quienes contribuyen o evalúan el proyecto. Expresa intenciones, sin comprometer fechas. La [versión inglesa](../development/roadmap.md) prevalece y el [modelo de seguridad](security-model.md) explica los límites actuales.

## Entregado en 0.1.0 y 0.1.1

Las versiones preliminares incluyen la TUI para casos, conectores sujetos a política, custodia firmada, conversaciones protegidas, consultas acotadas sobre Parquet, demo sintética, registro de detección de parsers, instaladores verificados y binarios firmados y atestados con Sigstore. El [registro de cambios](../../CHANGELOG.md) detalla lo entregado. Siguen pendientes las pruebas manuales con un modelo y un conector reales.

## v0.1.x: estabilizar la versión preliminar

- Validar H5 manualmente con DeepSeek y probar un conector en un entorno real de pruebas.
- Mantener la firma Sigstore sin claves, las atestaciones de GitHub y el SBOM entregados en v0.1.1.
- Firmar los binarios de macOS con Developer ID, hardened runtime y notarización mediante `notarytool`, desde un entorno de release protegido que solo se ejecuta para tags. La persona mantenedora debe proporcionar el certificado y la clave de App Store Connect antes de implementarlo.
- Solicitar acceso al programa SignPath Foundation para firmar Windows con Authenticode. Publicar `CODE_SIGNING.md` con la política de firma, aprobación de releases y procedencia de builds. La solicitud corresponde a la persona mantenedora.
- Mantener instaladores que verifican checksums y el binario Linux aarch64. Homebrew, AUR, Nix, winget y Scoop quedan abiertos a empaquetadores de la comunidad.
- Reducir el espacio del artefacto de co-observación, mejorar `entity_lookup` y acotar el peor caso de `path` de tres saltos ([issue #37](https://github.com/ns2switch/irmind/issues/37)).

## v0.2: parsers y conectores

- Ampliar el registro de detección: cada parser es un módulo Cargo que se activa cuando reconoce el log. Una coincidencia ambigua requiere que el analista elija; una elección forzada queda auditada.
- Añadir parsers experimentales de EVTX; syslog; autenticación, auditd, journald, nginx y Apache en Linux; ECS; OCSF; Velociraptor; Hayabusa; Chainsaw; plaso; EZTools; Zeek; Suricata EVE; y un formato declarativo definido por el usuario.
- Añadir conectores experimentales `siem-elastic` y `siem-chronicle`, con consultas estructuradas, permisos mínimos de lectura, contratos sintéticos y evidencia firmada.
- Mantener los formatos restantes como [issues de entrada](https://github.com/ns2switch/irmind/issues?q=is%3Aissue+label%3A%22good+first+issue%22).

## v0.3: skills forenses

- Aprobar `docs/development/skills-design.md` antes de implementar: formato, carga progresiva, instalación firmada, confianza y relación con la política.
- Una skill es una carpeta con `SKILL.md` que describe una metodología, más plantillas de consulta, reglas Sigma o mapeos opcionales. Las primeras cubrirán ransomware en Windows, compromiso de credenciales AWS, persistencia en Linux y BEC en M365.
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
- Revisión externa de seguridad.
- Al menos tres conectores validados en entornos reales de pruebas.
- Binarios de release firmados en Linux, macOS y Windows.
- Modelo de amenazas revisado para skills, subagentes, MCP y API del motor.

## Fuera de este repositorio

Una interfaz gráfica para trabajo multiagente, el gateway desatendido y los watches vivirán en otro repositorio que consumirá la API del motor de IRMind.

## Fuera del alcance actual

La contención (`RiskLevel::Contain`) y el anclaje externo de sellos quedan aplazados. Ningún LLM ni conector se activa por defecto.
