# IRMind

> [!WARNING]
> IRMind está en desarrollo. Todavía no es apto para investigar incidentes reales ni para procesar datos sensibles. Los ejemplos usan identidades ficticias.

Cliente local en Rust para investigar incidentes con evidencia firmada y llamadas a herramientas sujetas a política. Este repositorio contiene una primera implementación funcional del núcleo local.

## Arranque

```bash
cargo build --release
./target/release/irmind case new "Alerta CloudTrail" --severity high --scope "cuenta 123456789012; 2026-10-23"
./target/release/irmind case scope <CASE_ID> 'v1;sources=splunk-demo;accounts=123456789012;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z'
./target/release/irmind ingest <CASE_ID> cloudtrail.json
./target/release/irmind ingest <CASE_ID> ./evidence-directory
./target/release/irmind timeline <CASE_ID>
./target/release/irmind graph <CASE_ID>
./target/release/irmind entity <CASE_ID> ip 203.0.113.8
./target/release/irmind neighbors <CASE_ID> ip 203.0.113.8 --limit 10
./target/release/irmind entity-timeline <CASE_ID> ip 203.0.113.8 --limit 10
./target/release/irmind graph-path <CASE_ID> ip 203.0.113.8 user alice
./target/release/irmind text-search <CASE_ID> AssumeRole --limit 10
./target/release/irmind raw-records <CASE_ID> <SHA256> 0
./target/release/irmind verify <CASE_ID>
./target/release/irmind verify-graph <CASE_ID>
./target/release/irmind graph-rebuild <CASE_ID>
./target/release/irmind approvals <CASE_ID>
./target/release/irmind approve <CASE_ID> <REQUEST_ID>
./target/release/irmind deny <CASE_ID> <REQUEST_ID> "fuera de alcance"
./target/release/irmind edit-approval <CASE_ID> <REQUEST_ID> '{"ioc":"example.com"}'
./target/release/irmind --policy policy.toml --llm-module llm-openai-compatible ask <CASE_ID> "Investiga esta alerta"
./target/release/irmind add-finding <CASE_ID> ioc "203.0.113.8" <EVIDENCE_HASH>
./target/release/irmind confirm-finding <CASE_ID> <FINDING_ID>
./target/release/irmind dismiss-finding <CASE_ID> <FINDING_ID> "motivo"
./target/release/irmind report <CASE_ID>
cargo build --release --features ti-virustotal
./target/release/irmind --enable-virustotal approve <CASE_ID> <REQUEST_ID>
cargo build --release --features siem-splunk
IRMIND_SPLUNK_URL=https://splunk.example:8089 IRMIND_SPLUNK_SOURCE_ID=splunk-demo IRMIND_SPLUNK_INDEX=cloudtrail IRMIND_SPLUNK_ACCOUNT_FIELD=recipientAccountId ./target/release/irmind --llm-module llm-openai-compatible --enable-splunk ask <CASE_ID> "Investiga esta alerta"
cargo build --release --features ti-misp
IRMIND_MISP_URL=https://misp.example/ IRMIND_MISP_SOURCE_ID=misp-internal ./target/release/irmind --llm-module llm-openai-compatible --enable-misp ask <CASE_ID> "Enriquece este IOC internamente"
cargo build --release --features cloud-aws
IRMIND_AWS_SOURCE_ID=aws-demo IRMIND_AWS_REGION=eu-west-1 IRMIND_AWS_ROLE_NAME=IRMindReadOnly ./target/release/irmind --llm-module llm-openai-compatible --enable-aws ask <CASE_ID> "Consulta AssumeRole en CloudTrail"
cargo build --release --features edr-crowdstrike,edr-sentinelone
IRMIND_CROWDSTRIKE_URL=https://api.eu-1.crowdstrike.com IRMIND_CROWDSTRIKE_SOURCE_ID=falcon-demo ./target/release/irmind --llm-module llm-openai-compatible --enable-crowdstrike ask <CASE_ID> "Consulta el host"
IRMIND_SENTINELONE_URL=https://console.example.com IRMIND_SENTINELONE_SOURCE_ID=s1-demo IRMIND_SENTINELONE_SITE_ID=123456789 ./target/release/irmind --llm-module llm-openai-compatible --enable-sentinelone ask <CASE_ID> "Consulta el host"
```

La base SQLite de casos y auditoría, los archivos DuckDB del grafo, los sellos y las evidencias se guardan en el directorio de datos local estándar del sistema. Cada caso tiene su grafo en `graph/<CASE_ID>.duckdb` dentro de ese directorio; al abrir datos anteriores se migran las tablas de grafo de SQLite. `--home <ruta>` cambia ese directorio. Las claves del analista y de cada agente se guardan en entradas distintas del llavero del sistema; no se permite reutilizar la clave del analista. En Linux el backend persistente del llavero está habilitado por defecto y requiere un servicio de secretos disponible. La recuperación de claves todavía no está implementada. Consulte [PLATFORMS.md](docs/PLATFORMS.md) para instalación y verificación de artefactos.

Los valores de configuración no secretos (`IRMIND_*_URL`, fuente, región y modelo) se leen en la raíz de composición. Las credenciales se leen exclusivamente del llavero del sistema: servicio `irmind-module`, cuenta igual al nombre del campo secreto del manifiesto. Por ejemplo, la cuenta `IRMIND_SPLUNK_TOKEN` contiene el token de Splunk. El binario falla cerrado si falta una entrada requerida; no acepta secretos de variables de entorno.

Ningún módulo LLM se habilita por defecto. El módulo compatible con OpenAI de Chat Completions se selecciona explícitamente con `--llm-module llm-openai-compatible` o `IRMIND_LLM_MODULE`. Configure `IRMIND_MODEL` como variable no secreta y guarde `OPENAI_API_KEY` o `IRMIND_LLM_API_KEY` en el llavero con servicio `irmind-module` y cuenta igual al nombre del campo. Para otro endpoint, configure `IRMIND_LLM_BASE_URL` y su propia entrada `IRMIND_LLM_API_KEY` en el llavero; la clave `OPENAI_API_KEY` nunca se reutiliza para una URL distinta. Se permite HTTP sin clave solo en loopback (`localhost`, `127.0.0.1`, `::1`); los endpoints remotos requieren HTTPS y clave propia. El endpoint debe soportar streaming SSE, tool calling y el bloque final `stream_options.include_usage`; un stream incompleto se rechaza. También hay módulos opcionales para Anthropic, DeepSeek y OpenRouter, con claves y modelos independientes. Consulte [Módulos LLM](docs/llm-modules.md) para compilarlos, configurarlos y añadir otro proveedor. El catálogo común de herramientas se construye en la aplicación y solo anuncia las capacidades cuyos conectores están activos. `irmind ask <CASE_ID> "<alerta>"` ejecuta un turno; `irmind tui <CASE_ID>` abre la interfaz. La TUI muestra la respuesta completa al terminar el turno. Revise la clasificación y la política de datos antes de enviar una alerta real al endpoint configurado.

```bash
./target/release/irmind seal <CASE_ID>
./target/release/irmind export <CASE_ID> caso.irmind.json
./target/release/irmind verify-export caso.irmind.json --expected-key <HUELLA_SHA256>
```

`verify-export` no necesita la base local. Guarde la huella SHA-256 de la clave pública del analista por un canal confiable y pásela con `--expected-key`: un paquete reescrito y firmado con otra clave sería internamente válido. El sello local tampoco demuestra que el analista no haya reescrito todo el caso con su propia clave; requiere anclaje externo para esa garantía.

## Implementado

- Workspace Rust 2024 con dominio independiente de I/O, casos de uso, guard obligatorio, adaptadores de almacenamiento, parser JSON/CloudTrail y adaptador LLM separado. Los productos compilados implementan `Module`, publican manifiesto con puertos, herramientas y campos de configuración, y se registran en la raíz de composición; el registro admite varios LLM y EDR sin alterar el motor. Cada investigación firma la huella de los módulos activos, el identificador del modelo y el hash del endpoint elegido.
- Casos con severidad tipada, ingesta de archivos o directorios de evidencia original por SHA-256, timeline con referencias a registros de origen, índice local de entidades en DuckDB para archivos JSON/CloudTrail y resultados JSON de Splunk/CloudTrail, búsqueda acotada, grafo resumido, TUI básica y exportación verificable. La CLI recorre directorios en orden estable, rechaza enlaces simbólicos y límites excesivos, y omite hashes que ya tienen un evento `GraphIndexed` firmado.
- Consultas locales de entidad, vecinos coobservados y relaciones explícitas de CloudTrail (`assumed_role`, sesión emitida por rol, IP de origen y claves de acceso usadas o creadas), con límites de resultados y punteros `hash#registro`. El agente accede a ellas como herramientas `Read` sujetas a política.
- Caminos de hasta tres saltos de coobservación, búsqueda literal en todos los campos del JSON original indexado, y lectura de un registro JSON original por puntero. Las consultas tienen límites y pasan por política, guard y auditoría cuando las propone el modelo.
- Auditoría con serialización binaria canónica, encadenamiento SHA-256, firmas Ed25519, protección append-only de SQLite y sello del estado final.
- El evento firmado `GraphIndexed` registra la versión del parser y del constructor DuckDB. El archivo DuckDB es un índice derivado: el paquete exportado conserva el original y la auditoría, no una copia del índice.
- `verify-graph` vuelve a parsear las evidencias firmadas y compara registros, texto, observaciones y nodos con DuckDB. `graph-rebuild` reconstruye el índice en una transacción a partir de los originales, incluso para un caso sellado, sin añadir eventos al log. Los índices de versiones anteriores necesitan reconstrucción para buscar en todos los campos.
- Riesgo derivado del tipo de herramienta. Las consultas de evidencia del caso son de lectura; las propuestas de enriquecimiento externo se registran como pendientes y no se ejecutan. Argumentos desconocidos se rechazan.
- Las solicitudes pendientes se recuperan del log firmado, con la herramienta y los argumentos exactos. El analista puede listarlas, aprobarlas, denegarlas o editar sus argumentos desde la CLI y la pestaña `Approvals` de la TUI (`↑`/`↓` para elegir, `a` para aprobar, `d` para introducir un motivo, `e` para introducir argumentos JSON; también `/approvals`, `/approve <id>`, `/deny <id> <motivo>`, `/edit <id> <JSON>`). La edición valida la llamada nueva, deniega la anterior con firma y crea otra solicitud pendiente; no ejecuta herramientas. Aprobar y denegar firman retos distintos con la clave del analista; una solicitud solo se resuelve una vez. Un caso no se sella con solicitudes abiertas.
- `--policy` carga reglas TOML versionadas con esquema estricto: herramientas denegadas, cuota de llamadas autorizadas por caso y máximo de bytes de cada resultado enviado al modelo. La huella SHA-256 del fichero queda en el log de cada investigación. Sin fichero se aplica la misma política restrictiva integrada.
- La política limita también los tokens del modelo por caso. La respuesta comercial aporta el recuento firmado en la auditoría; la TUI muestra el total. Para ver una estimación de coste, configure conjuntamente `IRMIND_INPUT_MICROUSD_PER_MILLION` y `IRMIND_OUTPUT_MICROUSD_PER_MILLION` con las tarifas corporativas del modelo en uso.
- El alcance remoto explícito usa `v1;sources=splunk-demo;accounts=123456789012;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z`. El dominio valida fuente, objetivo y ventana; los alcances de texto libre de casos anteriores son solo locales.
- `case scope <id> <alcance>` y `/scope <alcance>` en la TUI modifican el alcance en una transacción SQLite junto con un evento firmado. La verificación y la exportación reproducen estos cambios y detectan alteraciones del alcance guardado. Una consulta SIEM limitada por cuenta no queda autorizada automáticamente si el alcance exige también un host.
- `siem_search` usa el alcance explícito para autorizar lecturas desatendidas dentro de la fuente, cuenta y ventana declaradas. Fuera de alcance queda pendiente de firma del analista. El módulo Splunk construye una búsqueda SPL a partir de un término literal, fija índice y campo de cuenta, limita la ventana a 24 horas y la respuesta a 5 MB. Requiere un token de un rol de solo lectura y HTTPS válido. Los resultados JSON se indexan como eventos del caso tras guardarlos como evidencia.
- `ti_lookup_internal` usa MISP cuando está compilado, activado y su ID de fuente figura en el alcance. Envía una búsqueda exacta de IOC a `/attributes/restSearch` con límite de 20; guarda y redacta el resultado igual que las demás herramientas. Use una clave MISP de solo lectura y TLS válido.
- `cloud_audit_events` usa AWS CloudTrail `LookupEvents` cuando está compilado y activado. STS comprueba que la cuenta real de las credenciales coincide con la cuenta del alcance y que se usa el rol dedicado configurado, antes de buscar por nombre exacto de evento; la ventana máxima es de 24 horas y devuelve hasta 20 eventos. `cloud_identity` consulta un rol o usuario concreto con IAM `GetRole`/`GetUser` bajo los mismos controles. Configure el rol dedicado y la región. La raíz de composición lee `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` y, si procede, `AWS_SESSION_TOKEN` del llavero; el SDK recibe esas credenciales explícitas y no consulta la cadena ambiental de perfiles.
- El puerto EDR y las herramientas `edr_host_info`, `edr_process_tree` y `edr_detections` aceptan solo `AuthorizedCall`. El dominio comprueba la fuente, el host y, para detecciones, la ventana del caso; el motor deniega una fuente sin conector o sin esa capacidad. Los módulos opcionales CrowdStrike y SentinelOne son independientes y pueden activarse juntos. CrowdStrike aporta inventario y alertas; SentinelOne añade eventos descendientes de un proceso asociado a una amenaza. Los resultados se conservan como evidencia y se indexan en DuckDB antes de mostrar una copia redactada al modelo. Consulte [Módulos EDR](docs/edr-modules.md).
- `irmind-testkit` aporta un EDR falso en memoria y una suite de contrato HTTP común que pasan CrowdStrike y SentinelOne. Comprueba filtros de host y tiempo, respuestas ambiguas o fuera de alcance, errores, límites, redirecciones y capacidades declaradas. La prueba de aplicación comprueba el hash firmado de la evidencia y que el modelo solo recibe la copia redactada.
- Hallazgos locales vinculados a un hash de evidencia: IOC, hipótesis, técnica ATT&CK, impacto y recomendación. El modelo o agente puede proponerlos mediante `case_add_finding`; solo el analista puede confirmarlos o descartarlos. El informe determinista incluye solo hallazgos confirmados y el timeline indexado; cada punto enlaza a su evidencia.
- La TUI muestra los hallazgos en una pestaña y permite `/add <tipo> <hash> <valor>`, `/confirm <id>`, `/dismiss <id> <motivo>`, `/findings` y `/report`.
- El adaptador VirusTotal es una feature opcional y requiere activación explícita y clave en el llavero. Solo acepta hashes, dominios ASCII y ciertas IPv4 públicas; bloquea indicadores internos o ambiguos. La aprobación firmada precede a la solicitud HTTP; el resultado completo se conserva como evidencia y la siguiente sesión recibe una copia acotada y redactada. VirusTotal advierte que los IOCs consultados pueden incorporarse a su conjunto de datos: use la aprobación con ese efecto en mente.
- `Actor` tipado (`Analyst` o `Agent`) en cada entrada firmada, con procedencia del evento separada. `ExecutionMode` se entrega a la política: en modo desatendido solo se autorizan consultas locales de lectura. Un `PendingApproval` vincula caso, secuencia y argumentos y su resolución exige verificar una firma de la clave del analista.
- Casos de uso sin estado global y `Send + Sync`; bloqueo de archivo por caso entre procesos, SQLite en WAL para casos y auditoría, y un DuckDB por caso para el grafo. La ejecución desatendida y el gateway local aún no están expuestos como comandos.
- Redacción de patrones conocidos de secretos, correos y teléfonos; normalización Unicode y neutralización de varias formas de inyección y secuencias de terminal. El original permanece local. El arranque ejecuta un corpus de inyecciones de logs, CSV, HTML, Unicode, base64 y escapes de terminal; su huella se incluye en el identificador firmado del guard.

## Límites actuales

- Splunk es el único conector SIEM, AWS CloudTrail el único de nube y MISP el único de inteligencia interna. Los módulos LLM agregan el stream antes de devolverlo a la TUI; falta conectar la salida incremental a la interfaz. Proveedores locales con diferencias de protocolo y Qwen aún no tienen módulos propios.
- El alcance remoto se usa en Splunk, AWS CloudTrail, MISP y los dos EDR; faltan GCP y Azure. El árbol de procesos general de CrowdStrike no está implementado. No hay edición de los valores de hallazgos desde la TUI. La estimación de coste no contempla descuentos por caché ni recargos del proveedor.
- Sin la feature y la activación de VirusTotal, `ti_lookup_external` no se anuncia ni se despacha. El modo desatendido no está activado en el binario. Las solicitudes anteriores al formato estructurado siguen recuperándose desde su reto firmado.
- El parseo JSON se hace en memoria. Faltan relaciones de otros productos y un índice FTS acelerado. `text-search` hace una búsqueda literal sobre el JSON indexado. Las relaciones de `neighbors` y `graph-path` indicadas como coobservación no prueban causalidad. Los índices creados con parsers anteriores a `json-cloudtrail-v4` se deben reconstruir con `graph-rebuild` para incluir las nuevas relaciones. Los resúmenes derivados no son evidencia original.
- La redacción basada en patrones no detecta toda PII ni todos los secretos; la detección de inyecciones tampoco es completa. Los casos con datos regulados requieren pruebas adicionales y revisión de la política de salida antes de activar el proveedor.
- La firma local detecta cambios en el log y en los archivos presentes, pero una cadena entera puede sustituirse si la clave de confianza no está fijada fuera de la máquina. No hay anclaje externo.

## Desarrollo

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features --locked --test-threads 1
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml check
cargo audit --ignore RUSTSEC-2026-0370 --ignore RUSTSEC-2026-0371 --ignore RUSTSEC-2026-0372
```

El flujo de CI ejecuta estas puertas con todas las features habilitadas y Clippy con `-D warnings`.

La prueba de extremo a extremo usa un modelo falso que intenta enviar datos a inteligencia externa; comprueba que la llamada queda pendiente, que el dato completo sigue local y que la alteración de la evidencia rompe la verificación.

DuckDB se enlaza en el binario mediante la feature `bundled`; la primera compilación compila su biblioteca C++ y necesita bastante tiempo y espacio de disco.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in IRMind by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions. See [CONTRIBUTING.md](CONTRIBUTING.md) for the required DCO sign-off.
