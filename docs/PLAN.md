# IRMind — Plan de referencia

## Principios
1. El modelo solo propone; la política del dominio decide. Ningún puerto externo se ejecuta sin AuthorizedCall.
2. Solo lectura por defecto: Read se permite, Enrich requiere aprobación firmada del analista y Contain se deniega.
3. Trazabilidad: todo evento va a un log append-only, encadenado por hash y firmado (Ed25519).
4. Mínimo dato hacia el modelo: guard, redacción y envoltorio como dato no confiable. La evidencia original se guarda intacta.
5. Fallar cerrado ante cualquier error de política, auditoría, firma, guard o redacción.
6. Las credenciales nunca llegan al modelo ni a los módulos: se leen del llavero en la raíz de composición.
7. irmind-security siempre se carga. Todo contenido externo es no confiable y sus valores son Tainted<T>.
8. Cada producto es un módulo que implementa un puerto; añadir uno no toca el núcleo.
9. Arquitectura limpia: dominio ← aplicación ← adaptadores / seguridad / TUI ← bin. Las dependencias solo apuntan hacia dentro, y un test de CI lo verifica.

## Hitos y criterio de "hecho"
H0 Esqueleto: workspace, lints, CI, cargo-deny y test de dirección de dependencias. Hecho cuando: el test falla con una arista inversa introducida a propósito.
H1 Dominio: ids, RiskLevel, ProposedCall, AuthorizedCall, Decision, ExecutionMode, Actor, Tainted<T>; política por alcance (cuentas, hosts, ventana) y cuotas en TOML; entidades Caso, Evento, Evidencia, IOC, Hipótesis y Técnica ATT&CK; lógica de la cadena de hashes. Hecho cuando: hay tests para cada regla y cada fallo de cadena.
H2 Aplicación: puertos async y cancelables (LlmPort con un único método y streaming, SiemPort, EdrPort, CloudAuditPort, ThreatIntelPort, EventParser, EvidenceGraph, Repository, EvidenceStore, AuditLog, Signer, ContentGuard); casos de uso Investigate, ApproveCall, GenerateReport (solo con entidades confirmadas), Seal, Verify e Ingest; despacho genérico de toda AuthorizedCall desde el registro de módulos; suites de contrato por puerto en testkit. Hecho cuando: hay un test de extremo a extremo por familia de puerto con aprobación firmada, y nada sin redactar llega al LLM falso.
H3 Seguridad: aislamiento con nonce, normalización, detección, contención por procedencia (Tainted), salida segura, autotest de arranque y evento InjectionDetected. Hecho cuando: el LLM falso obediente no consigue ejecutar nada sin aprobación, y una regla rota bloquea el arranque.
H4 Almacenamiento firmado: SQLite en WAL, evidencias por SHA-256, claves Analyst y Agent en el llavero persistente; verify, seal, export y verify-export con huella de clave esperada. Hecho cuando: verify detecta la manipulación de la base de datos y de las evidencias.
H5 Proveedor LLM: streaming, tool calling, contexto construido desde el estado del caso, y límite de tokens y coste por caso. Hecho cuando: hay tests con respuestas grabadas y una prueba manual documentada.
H6 TUI (crate irmind-tui): conversación, paneles del caso, diálogo de aprobación, /scope, /evidence y /pause cancelable, e indicador de detecciones. Hecho cuando: se puede llevar un caso completo con módulos falsos.
H7 Grafo de evidencias (DuckDB): ingesta con hash, parsers en streaming (CloudTrail y JSON), extracción determinista, aristas agregadas, búsqueda de texto completo, y herramientas Read con budget de tokens. Hecho cuando: hay un benchmark con al menos 1 GB sintético.
H8 Integraciones: cloud, SIEM, EDR y TI, cada módulo pasando la suite de su puerto. Hecho cuando: cada módulo tiene tests con respuestas grabadas y una guía de configuración.

## Modo gateway (posterior; no implementar)
Ya respetado: identidades Analyst y Agent, ExecutionMode (en Unattended solo Read dentro del alcance), aprobaciones solo con firma del analista, y casos de uso aptos para ejecutarse como servicio.

## Decisiones aceptadas
- ProposedCall sin risk: el riesgo lo determina Tool.
- El grafo usa DuckDB.
- Actor firma como Analyst o Agent; la procedencia va en un campo aparte.
- Ningún proveedor LLM se habilita por defecto; solo datos sintéticos hasta la aprobación de compliance.
