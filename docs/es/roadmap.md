Traducción de docs/development/roadmap.md en el commit fd58c3a30349977056f5e39ba18a3b9f8715d5cf; si hay diferencias, prevalece la versión en inglés.

# Hoja de ruta

IRMind es un asistente agéntico de terminal para respuesta a incidentes y análisis forense: el analista conversa con un agente que investiga evidencia local y remota, carga skills forenses cuando hacen falta y delega trabajo acotado en subagentes paralelos. El modelo propone, la política decide y cada acción queda firmada.

Esta página es para quienes contribuyen o evalúan el proyecto. Expresa intenciones, sin comprometer fechas. La [versión inglesa](../development/roadmap.md) prevalece y el [modelo de seguridad](security-model.md) explica los límites actuales.

Política anterior a 1.0: las versiones menores pueden cambiar formatos sin migración. V3 es el único formato de v0.3; las notas de compatibilidad de versiones publicadas describen solo aquellas versiones históricas.

## Entregado en 0.1.0 y 0.1.1

Las versiones preliminares incluyen la TUI para casos, conectores sujetos a política, custodia firmada, conversaciones protegidas, consultas acotadas sobre Parquet, demo sintética, registro de detección de parsers, instaladores verificados y binarios firmados y atestados con Sigstore. El [registro de cambios](../../CHANGELOG.md) detalla lo entregado. H5 está hecha por decisión del analista; siguen pendientes de registro los pasos no descritos y la validación de un conector real.

## v0.1.x: estabilizar la versión preliminar

- H5 está hecha por decisión del analista tras probar un saludo con DeepSeek real. Registrar los pasos restantes y probar un conector en un entorno real. Consulta el [registro de validación](manual-validation.md#registro-de-resultados).
- Mantener la firma Sigstore sin claves, las atestaciones de GitHub y el SBOM entregados en v0.1.1.
- Firmar los binarios de macOS con Developer ID, hardened runtime y notarización mediante `notarytool`, desde un entorno de release protegido que solo se ejecuta para tags. La persona mantenedora debe proporcionar el certificado y la clave de App Store Connect antes de implementarlo.
- Solicitar acceso al programa SignPath Foundation para firmar Windows con Authenticode. Publicar `CODE_SIGNING.md` con la política de firma, aprobación de releases y procedencia de builds. La solicitud corresponde a la persona mantenedora.
- Mantener instaladores que verifican checksums y el binario Linux aarch64. Homebrew, AUR, Nix, winget y Scoop quedan abiertos a empaquetadores de la comunidad.
- Reducir el espacio del artefacto de co-observación, mejorar `entity_lookup` y acotar el peor caso de `path` de tres saltos ([issue #37](https://github.com/ns2switch/irmind/issues/37)).

## v0.2: parsers y artefactos precisos

Syslog y las exportaciones de Linux están disponibles como módulos experimentales. Linux cubre autenticación, correlación acotada de auditd, journald JSON y logs HTTP common/combined. [La cobertura y selección de parsers](parsers.md) describe sus límites actuales.

- Ampliar el registro de detección: cada parser es un módulo Cargo que se activa cuando reconoce el log. Una coincidencia ambigua requiere que el analista elija; una elección forzada queda auditada.
- Añadir parsers experimentales de EVTX; syslog; autenticación, auditd, journald, nginx y Apache en Linux; ECS; OCSF; Velociraptor; Hayabusa; Chainsaw; plaso; EZTools; Zeek; Suricata EVE; y un formato declarativo definido por el usuario.
- Mantener los formatos restantes como [issues de entrada](https://github.com/ns2switch/irmind/issues?q=is%3Aissue+label%3A%22good+first+issue%22).

Los artefactos binarios de Windows (registro, `$MFT`, Prefetch, LNK, SRUM y Amcache) se cubren mediante las exportaciones procesadas de EZTools, Velociraptor y plaso. Consulta [la cobertura actual de Windows](parsers.md#cobertura-de-windows) para los formatos admitidos. Los [futuros parsers nativos de registro y `$MFT`](https://github.com/ns2switch/irmind/issues/159) dependerán de la demanda y deberán seguir el mismo modelo de proceso auxiliar aislado aprobado para EVTX, sin incorporar decodificadores binarios al proceso principal.

Zeek y Suricata no se distribuyeron en v0.1.x. Los módulos recuperados conservan microsegundos y usan particiones por host en V2. La migración de precisión V1 → V2 pertenecía a v0.2. La versión actual no conserva esos lectores ni comandos; abrir un caso nunca lo migra.

## v0.3: eventos comunes, una sola cadena y conectores SIEM

La cadena actual separa la decodificación acotada del formato del mapeo
identificado y validado. CLI, TUI y demo usan artefactos V3 y exportación V6.
La versión 0.3 no lee casos de 0.2: conserva el ejecutable creador o
[reingiere los originales verificados en un caso nuevo](../development/case-migration.md).

- Los tipos validados y códigos fijos permiten filtrar por categoría, tipo, resultado y rol mediante las herramientas acotadas existentes.
- Hay mapeos semánticos de EVTX, autenticación/auditd/HTTP de Linux, CloudTrail, ECS y OCSF. Las exportaciones DFIR, syslog, journald, Zeek, Suricata y los formatos declarativos conservan campos originales y extracción consultable sin inventar clasificaciones. Los mapeos semánticos comunitarios siguen abiertos.
- Cada parser compilado tiene un decodificador de campos originales. Los conjuntos de origen, perfiles y recibos vinculan la interpretación con los artefactos firmados; la reconstrucción usa esas identidades exactas.
- El auxiliar EVTX aislado decodifica bloques independientes en paralelo con salida idéntica entre números de trabajadores. Se mantiene el aislamiento nativo; Windows usa un único testigo de red verificado por sesión.
- La ingesta multinúcleo usa las CPU disponibles y un presupuesto de memoria. Se paralelizan el framing independiente, la preparación pura de registros y la finalización de particiones; la cadena firmada y el orden siguen siendo deterministas. Las fuentes ordenadas usan colas acotadas y las desordenadas conservan la ordenación dentro del caso.
- Los conectores experimentales Elastic y Google SecOps usan consultas estructuradas, credenciales explícitas del llavero, TLS completo, contratos sintéticos y evidencia firmada. Ningún conector ni modelo se activa por defecto; sigue pendiente la validación con servicios reales. Chronicle filtra por cuenta de evento por defecto; el alcance explícito de instancia exige confirmación, techo de organización y contexto firmado del caso, con un aviso persistente en la TUI.
- Se mantienen las mediciones release de los nueve escenarios de 15 GB y los plazos de consultas ordinarias. Las mejoras de entidades densas, ordenación de estrés y co-observación se siguen por separado de los controles de seguridad.

## v0.4: skills forenses

La versión preliminar 0.4.2 incluye 15 skills firmadas y de carga progresiva,
presupuestos de caso firmados, ingesta nativa de Kubernetes audit/Falco y
cobertura semántica de Entra, GCP y red. Cada skill pasa un caso sintético con
modelo guionizado, hallazgos confirmados y exportación verificada de forma
independiente. Siguen pendientes la validación de un conector real, las
colecciones Windows más amplias y la publicación del catálogo comunitario.

- El [diseño aprobado](../development/skills-design.md), el [contrato de instalación](../development/skills-installation-contract.md) y el [contrato de recibos y exportación V7](../development/skills-case-format-contract.md) definen la implementación 0.4. Consulta la [guía de uso](skills.md).
- Una skill es una carpeta con `SKILL.md` que describe una metodología, más plantillas de consulta, reglas Sigma o mapeos opcionales. El núcleo cubre AWS, Azure, GCP, Windows, Linux, red y Kubernetes. Windows triage, Linux triage y AWS credential compromise son los tres métodos iniciales; ransomware de Windows y otros nueve llegaron en 0.4.1, y dos métodos de Kubernetes en 0.4.2. BEC de M365 sigue como posible ampliación comunitaria.
- Incluir [**Windows triage**](https://github.com/ns2switch/irmind/issues/157): guiar una colección sintética y acotada con KAPE o Velociraptor de logs de eventos, registro y sus logs de transacciones, `$MFT`, Prefetch, LNK, SRUM y Amcache. Ingerir primero timelines de Hayabusa derivados de EVTX o CSV de EvtxECmd (EVTX directo si el auxiliar aislado está disponible), y después las exportaciones de PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd, LECmd, RECmd batch y SrumECmd. Investigar en orden: inicio de sesión → ejecución → persistencia → movimiento lateral → exfiltración. Correlacionar fuentes independientes y confirmar hallazgos con evidencia. El analista ejecuta las herramientas externas; una skill no concede permisos de ejecución.
- Incluir **Linux triage** para autenticación, ejecución y persistencia, y **AWS credential compromise** para CloudTrail, actividad de roles y sesiones, y cambios en IAM.
- `/budget` muestra consumo y asignaciones firmadas; `/settings limits` fija los valores para casos nuevos por debajo del techo de la organización. La identidad del clúster se confirma explícitamente; el lector de origen permite consultar hechos originales verificados sin proyectar cuerpos completos de peticiones.
- El modelo recibe primero nombre y descripción y carga el contenido completo solo cuando lo necesita. Las skills pueden venir incluidas, de una organización o instaladas por un analista.
- La instalación se firma y el caso registra el hash de la versión usada. Una skill declara herramientas necesarias, pero no amplía permisos. La firma admite los bytes exactos del paquete; su contenido sigue siendo no confiable tras la admisión y nunca llega al rol system.
- `/skills` permite listar, instalar, inspeccionar y deshabilitar. Las skills invocables aparecen como comandos. El catálogo comunitario vive en otro repositorio.

## v0.5: subagentes y trabajo paralelo

- Aprobar `docs/development/subagents-design.md` antes de implementar: tipos, límites, clave Agent, aprobaciones, ramas de eventos y fusión determinista.
- El agente principal delega tareas acotadas a subagentes paralelos con contexto propio. Habrá tipos de triage, nube, endpoint, red, Kubernetes e inteligencia de amenazas, y tipos comunitarios definidos en archivo.
- Los subagentes heredan el alcance del caso, no pueden ampliarlo ni aprobar llamadas. Sus solicitudes van al analista, firman con la clave Agent y su salida vuelve como contenido no confiable.
- Aplicar límites de concurrencia, rondas y tokens por subagente y un presupuesto total por turno. La TUI muestra la actividad y permite cancelarla.
- Cada subagente usa una rama de eventos que se fusiona de forma determinista con la cadena firmada del caso. La TUI pasa a consumir el flujo de eventos del motor.

## Lanzamiento público

Publicar un artículo, un vídeo de demostración con datos sintéticos, publicaciones comunitarias, un benchmark público de modelos con HuntEval y un catálogo inicial de skills. El lanzamiento sigue a v0.5 e incluye el repositorio comunitario de skills.

## v0.6: consultas en origen

Consultas estructuradas y con presupuesto en Athena, CloudTrail Lake, Security Lake, BigQuery, Cloud Logging Log Analytics, Azure Data Explorer y Azure Log Analytics. Los resultados se firman y las fuentes originales en la nube se pueden volver a verificar tras sellar. Consulta el [diseño](../development/cloud-query-design.md).

## v0.7: detección, informes, extensibilidad y API del motor

- Ejecutar reglas Sigma sobre Parquet local sin LLM.
- Exportar informes Markdown y PDF que citan solo evidencia confirmada.
- Evaluar IRMind como deployment completo con el protocolo HuntEval.
- Permitir hooks locales firmados antes o después de llamadas a herramientas.
- Ofrecer un cliente MCP opcional y desactivado por defecto, con modelo de amenazas. Cada herramienta declara riesgo, pasa por política y devuelve contenido no confiable.
- Aprobar el diseño de una API del motor antes de añadir el futuro subcomando `serve` de `irmind`. El protocolo versionado transmite eventos por stdio, socket Unix o named pipe de Windows, sin TCP abierto por defecto. Las claves permanecen en IRMind: el cliente solicita aprobación, el analista confirma e IRMind firma.

## Criterios para 1.0

- Formatos firmados estables para casos, manifiestos, skills, subagentes y protocolo del motor, con migraciones probadas.
- Decidir la retención de versiones de parsers y la compatibilidad estable al estabilizar los formatos, previsiblemente en v0.6–v0.7 y antes de 1.0. Hasta entonces, una versión menor puede cambiar los formatos de casos, exportaciones y definiciones sin migración: conserva el ejecutable creador o reingiere los originales verificados.
- Revisión externa de seguridad.
- Al menos tres conectores validados en entornos reales de pruebas.
- Binarios de release firmados en Linux, macOS y Windows.
- Modelo de amenazas revisado para skills, subagentes, MCP y API del motor.

## Fuera de este repositorio

Una interfaz gráfica para trabajo multiagente, el gateway desatendido y los watches vivirán en otro repositorio que consumirá la API del motor de IRMind.

## Fuera del alcance actual

La contención (`RiskLevel::Contain`) y el anclaje externo de sellos quedan aplazados. Ningún LLM ni conector se activa por defecto.
