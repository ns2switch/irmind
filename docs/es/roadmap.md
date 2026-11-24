Traducción de docs/development/roadmap.md en el commit df9a8bff2dfb803a6ce692b9ad5713f540b45057; si hay diferencias, prevalece la versión en inglés.

# Hoja de ruta

IRMind es un asistente agéntico de terminal para respuesta a incidentes y análisis forense: el analista conversa con un agente que investiga evidencia local y remota, carga skills forenses cuando hacen falta y delega trabajo acotado en subagentes paralelos. El modelo propone, la política decide y cada acción queda firmada.

Esta página es para quienes contribuyen o evalúan el proyecto. Expresa intenciones, sin comprometer fechas. La [versión inglesa](../development/roadmap.md) prevalece y el [modelo de seguridad](security-model.md) explica los límites actuales.

Política anterior a 1.0: las versiones menores pueden cambiar formatos sin migración. V3 es el único formato de v0.3; las notas de compatibilidad de versiones publicadas describen solo aquellas versiones históricas.

Preparación del lanzamiento: [validación real](real-validation.md), [evaluación de modelos](hunteval-model-benchmark.md) y [firma nativa](native-signing.md). Son procedimientos, no validaciones reales ya completadas.

## Entregado hasta v0.5.x

El [registro de cambios](../../CHANGELOG.md) detalla versiones y formatos. Estas
son capacidades entregadas, no afirmaciones de validación con incidentes reales.

- Casos en terminal, conversaciones protegidas, herramientas sujetas a política,
  custodia firmada, consultas Parquet acotadas, instaladores verificados y demo
  sintética sin red.
- Parsers experimentales modulares con detección, confirmación ante ambigüedad y
  EVTX aislado. Los binarios de Windows se cubren mediante salidas de EZTools,
  Velociraptor y plaso; futuros parsers nativos de registro y `$MFT` requieren
  auxiliares aislados. Consulta la [cobertura](parsers.md).
- Esquema común con decodificadores y mapeos identificados separados. Artefactos
  V3, conjuntos de fuentes, perfiles y recibos firmados; consultas por categoría,
  resultado y rol con los mismos límites. Ingesta multinúcleo con orden y bytes
  deterministas.
- Elastic y Google SecOps experimentales: consultas estructuradas de solo lectura,
  credenciales explícitas en el llavero, TLS completo y resultados firmados.
  La validación real sigue correspondiendo al analista. El modo de instancia de
  Chronicle exige confirmación, techo de organización y aviso permanente.
- Veintitrés skills de carga progresiva para investigar Windows, Linux, macOS,
  nube, identidad, correo, web, red y Kubernetes. Los métodos del núcleo viven
  en [irmind-skills](https://github.com/ns2switch/irmind-skills), junto al catálogo
  firmado de paquetes instalables de la comunidad.
- La versión 0.5.5 amplía la decodificación y el mapeo local de identidad y
  correo, hallazgos y flujos de nube, endpoint y macOS, DNS y accesos web.
  La guía de parsers describe cada exportación y su cobertura experimental.
- Seis tipos de subagente acotados, con contexto propio, ramas, checkpoints,
  fusión determinista, export V8 y planes visibles/cancelables. Reservar más del
  25% de tokens o llamadas restantes exige firma; una preferencia permite pedir
  confirmación para todos los planes.
- Presupuestos de caso bajo el techo organizativo. Se usa el máximo nativo de
  salida del modelo y se comprueba saldo entre peticiones, conservando uso real
  y deuda. La configuración del modelo se guarda conjunta y la prueba usa el
  borrador sin guardarlo.
- Borrado lógico firmado de casos sin sellar y barra de estado declarativa con
  prioridades integrados para v0.5.2. El borrado conserva lápidas, respeta bloqueos
  y recupera interrupciones; no garantiza eliminación física segura.

- La versión 0.5.3 añade contabilidad de caché del proveedor, marcadores del
  prefijo confiable de Anthropic, recuperación explícita de planes protegida entre
  procesos y paquetes macOS Intel. Mantiene el nonce por turno y el cargo de todos
  los tokens. Las demás propuestas de contexto quedan para después del lanzamiento.

Skills e hijos no amplían permisos ni alcance, los hijos no aprueban, y datos
externos o del modelo nunca pasan a system confiable. Ningún modelo ni conector
se activa por defecto. Los diseños históricos no prometen compatibilidad del
binario actual.

## v0.5.x: estabilización y preparación para evaluación

- Medir la reutilización real de caché con la primera contabilidad. Mantener el
  nonce por turno y el cargo de todos los tokens; aplazar las demás propuestas
  de contexto hasta después del lanzamiento. Sin precalentamiento ni cambios
  automáticos de ruta.
- Ensayar la [validación real](real-validation.md) con Elasticsearch local, TLS,
  CA y modelo local. Registrar resultados, fallos y tiempos observados; no
  sustituye la validación del analista con su modelo y conector.
- Repetir PTY bajo carga con sincronización por eventos: arranque, presentación,
  expansión y borrado.
- Publicar Homebrew verificado. Mantener macOS Intel nativo y Linux aarch64,
  instaladores, Sigstore con identidad de tag, provenance y SBOM. AUR, Nix,
  winget y Scoop quedan abiertos a empaquetadores comunitarios.
- Activar Developer ID, hardened runtime y notarización preparados solo tras
  aportar el entorno protegido y aprobar la activación. La firma Authenticode de
  Windows sigue pendiente; se reevaluará SignPath Foundation tras el lanzamiento
  público, junto a opciones de pago. Elegir proveedor y activar corresponde al
  mantenedor; Sigstore no sustituye la firma nativa ni la reputación del SO.
- Registrar los pasos pendientes de H5, un conector en un entorno real y EVTX
  experimental en Windows 11. No deducirlos de pruebas sintéticas scripted.
- Medir y mejorar estrés, consultas de entidades densas y disco de co-observación
  sin alterar límites de consulta ni controles para mejorar una cifra.

## Lanzamiento público

Publicar un artículo, un vídeo de demostración con datos sintéticos, publicaciones comunitarias y un catálogo inicial de skills. El lanzamiento público es el siguiente hito tras estabilizar v0.5.x. Publicar
solo afirmaciones medidas: firma nativa, validaciones del analista y catálogo
son elementos explícitos de la lista, no garantías implícitas.

## v0.6: consultas en origen

Consultas estructuradas y con presupuesto para CloudTrail en Athena, Cloud
Audit Logs en BigQuery y las tablas admitidas de Azure Log Analytics en el
plan Analytics. El resultado se firma y se conserva como evidencia derivada
para el análisis local. Las consultas desde subagentes, la reverificación
de originales en la nube se prevén para v0.8. Los demás conjuntos de datos y
proveedores quedan para más adelante. Consulta el [diseño](source-queries-design.md) y el
[contrato de implementación](source-queries-format-contract.md).

## v0.7: identidades de mapeo, detección e informes

- Acotar las identidades de mapeo nativo a sus dependencias de producción para
  conservar la reconstrucción cuando cambien dependencias ajenas al mapeo.
  [Diseño](../development/native-mapping-build-identity.md).
- Ejecutar reglas Sigma sobre Parquet local sin LLM.
- Generar informes firmados en Markdown y PDF a partir de hallazgos
  confirmados con citas.
- Diseñar los hooks locales firmados, el cliente MCP y la API del motor para v0.8.

## v0.8: extensibilidad, API del motor y validación

- Añadir hooks locales firmados alrededor de las llamadas a herramientas,
  incluido un script de la barra de estado admitido expresamente por el analista.
- Ofrecer un cliente MCP opcional y desactivado por defecto. Cada herramienta
  declara su riesgo, pasa por la política y devuelve contenido no confiable.
- Ofrecer un protocolo del motor versionado para `serve` por stdio,
  socket Unix o named pipe de Windows. El cliente solicita la aprobación, el
  analista confirma e IRMind firma. TCP queda desactivado por defecto.
- Añadir consultas en origen para subagentes y reverificación remota de los
  objetos originales en la nube.
- Evaluar IRMind como sistema completo con HuntEval y publicar las mediciones
  comparativas de los modelos.

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
