Traducción de docs/development/roadmap.md en el commit 49d3419a622da753aa38efa0f6b0454b27e9b015; si hay diferencias, prevalece la versión en inglés.

# Hoja de ruta

IRMind es un asistente agéntico de terminal para respuesta a incidentes y análisis forense: el analista conversa con un agente que investiga evidencia local y remota, carga skills forenses cuando hacen falta y delega trabajo acotado en subagentes paralelos. El modelo propone, la política decide y cada acción queda firmada.

Esta página es para quienes contribuyen o evalúan el proyecto. Expresa intenciones, sin comprometer fechas. La [versión inglesa](../development/roadmap.md) prevalece y el [modelo de seguridad](security-model.md) explica los límites actuales.

Según la política anterior a 1.0, una versión menor puede cambiar los formatos
de caso, exportación y definiciones sin migración. Conserva el ejecutable que
creó el caso o reingiere los originales verificados.

## Entregado

El [CHANGELOG](../../CHANGELOG.md) recoge las versiones publicadas y los cambios
de formato. Esta sección resume las capacidades incluidas en esas versiones.

### v0.7.x

- Las identidades de mapeo nativo usan el manifiesto V2 de dependencias de
  producción. Los cambios en dependencias ajenas al cierre del mapeo mantienen
  su identidad. [Diseño de identidad](../development/native-mapping-build-identity.md).
- Sigma local evalúa reglas acotadas sobre Parquet autenticado sin usar un
  modelo. Cada ejecución firmada conserva las correspondencias de campos,
  las filas exactas y la cobertura. [Guía de Sigma](sigma.md).
- Los informes firmados en Markdown y PDF citan la evidencia de los hallazgos
  confirmados por el analista y documentan las limitaciones. El marcador de
  caso 6 y el export V10 incluyen las pruebas de Sigma e informes.
  [Casos y exportaciones](cases.md).
- Las entregas CloudTrail en gzip se detectan por contenido. Se ingieren los
  logs y se identifican y omiten los digests de integridad con un aviso.
  [Cobertura de parsers](parsers.md).

### v0.6.x

- Consultas en origen con presupuesto para CloudTrail en Athena, Cloud Audit
  Logs en BigQuery y las tablas admitidas del plan Analytics de Azure Log
  Analytics. Vienen desactivadas por defecto. Las capturas firmadas se guardan
  como evidencia derivada para el análisis local. Los tres adaptadores se
  probaron con simuladores.
  [Diseño](source-queries-design.md) · [Contrato de formato](source-queries-format-contract.md).
- Compilaciones reproducibles del ejecutable principal y del auxiliar aislado
  EVTX en los cinco destinos de release. El fichero firmado
  `BUILD-ENVIRONMENT.json` registra las versiones exactas de las herramientas
  usadas en cada destino. [Guía de reproducibilidad](reproducible-builds.md).

### Entregado hasta v0.5.x

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
  los tokens. La versión 0.5.4 añade paquetes Homebrew verificados y la
  verificación de la firma del catálogo.

Skills e hijos no amplían permisos ni alcance, los hijos no aprueban, y datos
externos o del modelo nunca pasan a system confiable. Ningún modelo ni conector
se activa por defecto. Los diseños históricos no prometen compatibilidad del
binario actual.

## Lanzamiento público

Publicar el artículo de presentación, un vídeo de la demo con datos sintéticos
y publicaciones para la comunidad. Comunicar la validación observada y
documentar las comprobaciones pendientes. [Registro manual](manual-validation.md).

## v0.7.x: cobertura de Sigma, paquetes de reglas e ingesta

1. Ampliar la cobertura de Sigma. Empezar por la compilación por clase de
   fuente y ampliar después las correspondencias revisadas para campos de
   Sysmon, `image_load` y `registry`, tablas de nube con `requestParameters` y
   `responseElements`, y los `logsource` de webserver y DNS. Medir por familia
   la admisión y la compilación exacta con la misma release de SigmaHQ fijada
   por hash. [Línea base de SigmaHQ](../development/benchmarks/sigmahq-v070-admission.md).
2. Diseñar paquetes de reglas Sigma instalables con el mismo modelo de
   instalación explícita de las skills. Antes de implementar, aprobar un
   contrato que compare el uso del catálogo y la clave de irmind-skills con un
   catálogo separado y una clave propia generada por el mantenedor.

   - Firmar el índice del catálogo, fijar las versiones por hash y rechazar
     retrocesos de versión.
   - Ofrecer `/sigma list`, `/sigma info`, `/sigma install`, `/sigma update` y
     `/sigma remove`. Mostrar en `/sigma info` la cobertura del paquete frente
     a las fuentes del caso y, al actualizar, las diferencias antes de firmar.
   - Instalar explícitamente desde el catálogo o un fichero local, con las
     mismas reglas de verificación, vista previa y admisión firmada por el
     analista que `/skills install`. Quitar un paquete instalado conserva las
     pruebas ya referenciadas en ejecuciones firmadas.
   - La instalación no concede permisos ni ejecuta reglas. Cada ejecución
     pasa por la admisión firmada del caso y la política. Las skills pueden
     recomendar un paquete bajo esa misma política.
   - Referenciar las releases de SigmaHQ por URL oficial y SHA-256, con
     atribución a Detection Rule License (DRL) 1.1. El catálogo no redistribuye
     las reglas de SigmaHQ. Los paquetes de la comunidad declaran su licencia.
   - Validar en la CI del catálogo la admisión, compilación, licencia y
     cobertura de fuentes de cada paquete.
3. Verificar la cadena de digests de CloudTrail como prueba de integridad
   de los logs. [#428](https://github.com/ns2switch/irmind/issues/428).
4. Perfilar la ingesta de FDR, Unified Log y eslogger y diseñar una
   normalización compacta para DNS debug de Windows e IIS W3C de gran tamaño.
   [Perfil de ingesta #344](https://github.com/ns2switch/irmind/issues/344) ·
   [Almacenamiento compacto #355](https://github.com/ns2switch/irmind/issues/355).

## v0.8: extensibilidad, API del motor y validación

- Añadir hooks locales firmados alrededor de las llamadas a herramientas,
  incluido un script de la barra de estado admitido expresamente por el analista.
- Ofrecer un cliente MCP opcional y desactivado por defecto. Cada herramienta
  declara su riesgo, pasa por la política y devuelve contenido no confiable.
- Ofrecer un protocolo del motor versionado para `serve` por stdio, socket Unix
  o named pipe de Windows. El cliente solicita la aprobación, el analista
  confirma dentro de IRMind e IRMind firma. TCP queda desactivado por defecto.
  [Diseños de extensibilidad](https://github.com/ns2switch/irmind/pull/391).
- Añadir consultas en origen para subagentes y reverificación remota de los
  objetos originales en la nube.
- Evaluar IRMind como sistema completo con HuntEval y publicar las mediciones
  comparativas de los modelos. [#95](https://github.com/ns2switch/irmind/issues/95).
- Validación del mantenedor: ejecutar consultas en origen contra Athena,
  BigQuery y Azure Log Analytics, validar Elastic con TLS y una CA propia y
  comprobar la ingesta aislada de EVTX en Windows 11. Registrar las pruebas de
  H5 pendientes para citas de hash, `/verify` y verificación del export.
  [Procedimiento de validación](real-validation.md) ·
  [Registro manual](manual-validation.md) ·
  [Elastic #63](https://github.com/ns2switch/irmind/issues/63) ·
  [Windows 11 #189](https://github.com/ns2switch/irmind/issues/189) ·
  [H5 #340](https://github.com/ns2switch/irmind/issues/340).

## v0.9: evidencia nativa de Windows, detección e intercambio

- Añadir decodificadores nativos aislados para el registro de Windows, `$MFT`,
  Prefetch, LNK, Amcache y SRUM.
- Añadir escaneo local con YARA y admisión y evaluación acotadas de reglas,
  siguiendo el modelo de Sigma.
- Exportar líneas temporales con citas verificables para Timesketch y en CSV
  de super timeline compatible con plaso. Exportar indicadores de compromiso
  (IOC) con procedencia en formatos STIX y MISP.
- Ampliar Sigma local a reglas de correlación.
- Evaluar proyecciones acotadas sobre un mismo elemento para `authorizationInfo`
  de GCP y `targetResources` y `modifiedProperties` de Entra. La auditoría fijada
  estima una regla adicional para GCP y tres para Azure. [Auditoría y alcance](../development/sigma-azure-result-type-contract.md).
- Ingerir salidas de Volatility 3. [#158](https://github.com/ns2switch/irmind/issues/158).
- Decidir cuándo estabilizar los formatos firmados y cuánto tiempo mantener
  las versiones de parsers.

## Decisiones abiertas

- Decidir si se admiten imágenes de disco (E01 o raw) y definir, si procede,
  las operaciones admitidas y su modelo de custodia.
- Definir el trabajo entre varios analistas, incluido el traspaso del caso,
  un segundo firmante y la revisión.

## Trabajo sin versión asignada

- Planificar el trabajo aplazado sobre coste de contexto y medir la reutilización
  de caché con proveedores reales tras el lanzamiento.
  [Diseño de coste de contexto](../development/context-cost-design.md).
- Configurar Apple Developer ID y aprobar la notarización. Elegir proveedor
  para Authenticode en Windows y reevaluar SignPath Foundation tras el
  lanzamiento. [Firma nativa](native-signing.md).
- Seguir midiendo el estrés de ingesta, las consultas de entidades densas y el
  almacenamiento de co-observaciones con los límites vigentes.
  [Benchmarks](../development/benchmarks.md). La comunidad puede contribuir
  con otros formatos de paquete.

## Criterios para 1.0

- Formatos firmados estables para casos, manifiestos, skills, subagentes y protocolo del motor, con migraciones probadas.
- Confirmar antes de 1.0 la decisión de v0.9 sobre retención de versiones de parsers y compatibilidad estable. Hasta entonces, una versión menor puede cambiar los formatos de casos, exportaciones y definiciones sin migración: conserva el ejecutable creador o reingiere los originales verificados.
- Revisión externa de seguridad.
- Al menos tres conectores validados en entornos reales de pruebas.
- Binarios de release firmados en Linux, macOS y Windows.
- Modelo de amenazas revisado para skills, subagentes, MCP y API del motor.

## Fuera de este repositorio

Una interfaz gráfica para trabajo multiagente, el gateway desatendido y los watches vivirán en otro repositorio que consumirá la API del motor de IRMind.

## Fuera del alcance actual

La contención (`RiskLevel::Contain`) y el anclaje externo de sellos quedan aplazados. Ningún LLM ni conector se activa por defecto.
