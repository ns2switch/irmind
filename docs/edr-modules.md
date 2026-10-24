# Módulos EDR de IRMind

Cada EDR es un crate independiente que implementa `EdrPort`. El modelo solo propone `edr_host_info`, `edr_detections` o `edr_process_tree`; el dominio comprueba fuente, host y ventana, y el motor ejecuta únicamente llamadas autorizadas. El resultado completo se guarda como evidencia firmada antes de que una copia redactada llegue al modelo.

| Módulo | Feature | Activación | Variables requeridas | Capacidades |
| --- | --- | --- | --- | --- |
| CrowdStrike Falcon | `edr-crowdstrike` | `--enable-crowdstrike` | `IRMIND_CROWDSTRIKE_URL`, `IRMIND_CROWDSTRIKE_SOURCE_ID`, `IRMIND_CROWDSTRIKE_CLIENT_ID`, `IRMIND_CROWDSTRIKE_CLIENT_SECRET` | Host, alertas |
| SentinelOne | `edr-sentinelone` | `--enable-sentinelone` | `IRMIND_SENTINELONE_URL`, `IRMIND_SENTINELONE_SOURCE_ID`, `IRMIND_SENTINELONE_SITE_ID`, `IRMIND_SENTINELONE_API_TOKEN` | Host, amenazas, eventos descendientes de proceso en una amenaza |

Compile las features por separado o juntas:

```bash
cargo build --release --features edr-crowdstrike,edr-sentinelone
IRMIND_CROWDSTRIKE_URL=https://api.eu-1.crowdstrike.com \
IRMIND_CROWDSTRIKE_SOURCE_ID=falcon-prod \
IRMIND_CROWDSTRIKE_CLIENT_ID=... IRMIND_CROWDSTRIKE_CLIENT_SECRET=... \
IRMIND_SENTINELONE_URL=https://console.example.com \
IRMIND_SENTINELONE_SOURCE_ID=s1-prod IRMIND_SENTINELONE_SITE_ID=123456789 \
IRMIND_SENTINELONE_API_TOKEN=... \
./target/release/irmind --enable-crowdstrike --enable-sentinelone ask <CASE_ID> "Investiga este host"
```

El alcance del caso debe incluir la fuente y el host exacto. Por ejemplo, `v1;sources=falcon-prod,s1-prod;accounts=;hosts=host-1.example;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z`. Las detecciones admiten como máximo 24 horas y 20 registros por llamada. Si hay varios registros de agente para el mismo nombre de host, el módulo falla cerrado. Use credenciales dedicadas de solo lectura: CrowdStrike requiere `hosts:read` y `Alerts: READ`; SentinelOne requiere `Endpoints.view` y `Threats.view`, con token restringido al sitio configurado. Los dos clientes exigen HTTPS, no siguen redirecciones y limitan cada respuesta a 5 MB.

CrowdStrike busca hosts en `/devices/combined/devices/v1` y alertas en `/alerts/combined/alerts/v1`. La búsqueda de alertas usa `agent_id` y `created_timestamp` en FQL y vuelve a comprobar que cada registro pertenece al agente y a la ventana. El filtro exacto de Alert puede variar según el esquema de la consola: compruebe en la API Reference de su tenant que `agent_id` está disponible antes de usar esta herramienta. Si la API rechaza el filtro o no devuelve los campos de alcance, IRMind deniega el resultado. `edr_process_tree` no se anuncia para CrowdStrike porque este módulo no tiene una API de árbol de procesos general verificada.

SentinelOne consulta `/web/api/v2.1/agents` y `/web/api/v2.1/threats`, siempre con `siteIds` y, para amenazas, `agentIds` y ventana. `edr_process_tree` usa `/threats/{threat_id}/explore/events`; su `process_id` debe tener el formato `<threat_id>:<event_id>`, donde `event_id` es la clave de proceso de la vista Explore de esa amenaza. El módulo verifica primero que la amenaza pertenece al agente y al sitio. Esta capacidad cubre eventos descendientes de procesos asociados a una amenaza, no una búsqueda arbitraria de procesos en el host.

## Añadir otro EDR

1. Cree `crates/modules/edr-<producto>/`, añádalo al workspace y aplique la edición y los lints comunes con `#![forbid(unsafe_code)]`.
2. Publique un `ModuleManifest` con `ModulePort::Edr`, solo las herramientas implementadas y los campos de configuración; marque las credenciales como secretas. `ModuleRegistry` incorpora el manifiesto a la huella firmada y rechaza IDs y fuentes duplicadas.
3. Implemente `Module::register` con `registry.add_edr(self)` e implemente `EdrPort`. Si una capacidad no existe, indique `false` en `supports` y devuelva error en su método. El catálogo solo anunciará la capacidad si algún EDR activo la soporta; al despachar se verifica también la fuente concreta.
4. Cada método debe comprobar el `Tool` y `source` de `AuthorizedCall`. Traduce únicamente los argumentos autorizados a filtros de API acotados; valide nombres, IDs, host y ventana antes de componer consultas. Verifique que todos los registros devueltos pertenecen al host y al ámbito configurado. Falla cerrado ante ambigüedad, truncación, respuesta incompleta o campos de alcance ausentes.
5. Obtenga credenciales del entorno o llavero en `SecretString`. Exija HTTPS para destinos remotos, desactive redirecciones, limite bytes y tiempo, y no registre cuerpos de error ni secretos. Devuelva bytes de evidencia al puerto: la aplicación se ocupa de firmar, indexar y redactar.
6. Añada una dependencia opcional y una feature en `crates/bin/Cargo.toml`, y la activación explícita en `crates/bin/src/main.rs`. Añadir un EDR no requiere cambiar el dominio ni la política.
7. Añada `irmind-testkit` como dependencia de desarrollo e implemente `EdrFixture` en las pruebas del módulo. Ejecute `run_edr_contract(&Fixture)` para pasar la misma suite que CrowdStrike y SentinelOne. El fixture construye el adaptador con un servidor HTTP local, define las respuestas de cada escenario y comprueba los métodos, rutas, credenciales de prueba y filtros enviados. Ejecute `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` y `cargo test --workspace --all-features`.

## Contrato EDR automatizado

[`irmind-testkit`](../crates/testkit/src/lib.rs) prueba para cada adaptador: lectura autorizada dentro del alcance, aprobación fuera del host o la ventana, rechazo de otra fuente y de otra herramienta antes de tocar la red, ventana superior a 24 horas, host distinto o ambiguo, campos de alcance ausentes, detección de otro host o sitio, detección fuera de tiempo, error HTTP, respuesta superior a 5 MB y redirección. Comprueba también `edr_process_tree` según la capacidad declarada; SentinelOne debe restringir la amenaza al host antes de consultar eventos y CrowdStrike no debe hacer ninguna solicitud para una capacidad no anunciada.

La suite usa respuestas simuladas en `127.0.0.1`, credenciales ficticias y ningún archivo temporal. La prueba de extremo a extremo en `irmind-infra` usa el `FakeEdr` del mismo crate: verifica que el resultado original queda guardado por hash, que hay una entrada firmada anterior a la respuesta final del modelo, que el modelo recibe una copia redactada y que `verify` y `verify-graph` aceptan el caso. Estas pruebas no sustituyen la validación posterior contra los tenants de cada producto.

Referencias: [CrowdStrike Hosts](https://developer.crowdstrike.com/api-reference/collections/hosts/), [CrowdStrike Alerts](https://developer.crowdstrike.com/api-reference/collections/alerts/), [SentinelOne Management Console API](https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/mgmt-console-api/references/tags/Agents.md), [SentinelOne Threats API](https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/mgmt-console-api/references/tags/Threats.md).
