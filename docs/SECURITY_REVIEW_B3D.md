# Revisión de seguridad B3d — 2026-10-25

## Alcance y adversarios

Se revisaron los crates del workspace y sus rutas de composición. Adversarios: quien escribe los registros investigados; un proveedor o una red comprometida; y otro proceso con los permisos del usuario del analista. Este último puede acceder al llavero del usuario y a sus archivos: la firma local no ofrece no repudio frente a él sin anclaje externo.

## Modelo STRIDE por componente

| Componente | Amenazas STRIDE plausibles | Control actual y límite |
| --- | --- | --- |
| TUI y CLI | Suplantación de contenido, manipulación del terminal, divulgación (S/T/I) | Mensajes, paneles y entrada visible pasan por `ContentGuard`; argumentos de aprobación y nombres de archivo de la CLI se muestran con `Debug` escapado. Un terminal modificado por el mismo usuario queda fuera de la garantía del proceso. |
| Motor y política | Elevación por propuesta falsa, repudio de aprobación, denegación por cuota (E/R/D) | Solo `evaluate` o `PendingApproval::resolve` construyen `AuthorizedCall`; la firma del analista cubre caso, secuencia, argumentos y caducidad; cuotas auditadas. |
| Guard | Instrucciones ocultas en evidencia y evasión por formato (S/T/E) | Normalización, corpus de arranque, aislamiento y redacción; la detección no sustituye a la política. |
| Módulos remotos | Proveedor/red falsos, respuesta maliciosa, fuga de credenciales, agotamiento (S/T/I/D) | TLS con raíces nativas, redirecciones desactivadas, `SecretString`, tiempos y tamaños máximos; una CA corporativa comprometida puede suplantar el destino. |
| SQLite, evidencias y firma | Alteración, repudio, borrado, firma con clave del usuario (T/R/D) | WAL, log encadenado, Ed25519, evidencia por hash, ACL; el proceso con acceso al llavero puede reescribir y volver a firmar una cadena completa sin ancla externa. |
| Grafo DuckDB | Consulta inyectada, manipulación de índice derivado, saturación (T/I/D) | SQL parametrizado y reconstrucción desde originales firmados; la ingesta actual materializa JSON y queda limitada a 50 MB por archivo. |
| Ingesta | Path traversal, symlink, JSON profundo, bomba comprimida, TOCTOU (T/I/D) | Ruta auditada relativa con `/`, enlaces finales sin seguimiento, máximo 50 MB/archivo, 1 GB y 1000 archivos/directorio; no se descomprime. Los componentes superiores de la ruta aún pueden cambiar entre recorrido y apertura. |
| Exportación | Paquete falso, ruta maliciosa, deserialización masiva (S/T/D) | JSON sin extracción de rutas, firma separada del sello, huella esperada y límite 128 MiB. |
| Importación/verificación | Firma ajena, datos enormes o recursivos (S/T/D) | Solo `verify-export` de paquete JSON; no se importa en el almacén. Verifica cadena, firmas, evidencia, sello y huella esperada. |

S, T, R, I, D y E representan suplantación, manipulación, repudio, divulgación, denegación de servicio y elevación de privilegios.

## Invariante de despacho remoto

`Engine::execute_authorized` es el único punto de ejecución de herramientas. Recibe `&AuthorizedCall`, audita antes del despacho, y después llama a los puertos SIEM, cloud, EDR y TI mediante `dispatch_siem`, `dispatch_cloud`, `dispatch_edr` y `dispatch_internal_intel`, o al puerto TI externo. Esos cinco puntos invocan `port.execute(call, cancel)` con el mismo token autorizado. `execute_proposal` obtiene el token desde `evaluate_tainted`; `resolve_approval_unlocked` lo obtiene desde `PendingApproval::resolve` tras firma de analista. El `LlmPort::complete` es la llamada al modelo que inicia la propuesta, no una herramienta; su entrada pasa por guard y redacción. Las llamadas directas de suites de contrato crean tokens mediante la política en testkit.

## SPL y alcance

La herramienta SIEM acepta un término literal; el adaptador Splunk genera `search index=<configurado> <campo>=<cuenta> "<término>" | head 20`. El índice no viene del modelo; `earliest_time` y `latest_time` se envían como parámetros separados después de comparar fuente, cuenta y ventana con el alcance del caso. El analizador deniega los comandos `outputlookup`, `outputcsv`, `collect`, `sendemail`, `sendalert`, `script`, `run`, `rest`, `map`, `delete`, `tscollect` y `meventcollect`. Cubren escritura local, emisión de alertas/correo, ejecución o delegación de búsquedas y acceso privilegiado. Cualquier carácter o sintaxis fuera del literal pasa a `NeedsApproval` mostrando el texto exacto, pero el adaptador sigue rechazando SPL arbitrario tras aprobación. Por tanto, **todos** los comandos de SPL quedan fuera del dialecto ejecutable del MVP, incluidos los que no figuran en la lista explícita.

## SQL dinámico

SQLite usa consultas constantes con `params!`. La única composición de SQL en tiempo de ejecución está en `migrate_legacy_graphs`: `DELETE FROM {table} WHERE case_id=?1`, donde `table` procede únicamente de cuatro literales de código (`graph_observations`, `graph_nodes`, `graph_events`, `graph_index`); `case_id` sigue parametrizado. DuckDB usa consultas constantes y parámetros para valores y límites; los nombres de índices se eligen de dos literales de código. No se concatena ningún argumento del modelo en SQL.

## Secretos, HTTP y recursos

`ModuleConfig` no deriva `Debug`; las credenciales son `SecretString`. `Debug` de entradas de auditoría, datos tainted, propuestas, aprobaciones y mensajes del modelo omite valores sensibles. Los errores de transporte HTTP, llavero y DuckDB se redujeron a mensajes sin valores de proveedor ni evidencia. El motor reduce además cualquier error de puerto remoto antes de auditarlo o mostrarlo. Los clientes desactivan redirecciones y fijan timeout; AWS tiene límites de conexión, lectura, intento y operación. Streaming LLM se limita a 2 MB y resultados remotos a 5 MB. El parser rechaza más de 50 MB, 100 000 registros y JSON más profundo que el límite de `serde_json`. El motor tiene presupuesto de tokens y coste por caso. El cliente OpenAI compatible permite HTTP exclusivamente en loopback para Ollama local y acepta HTTPS en el mismo destino; los servicios remotos requieren TLS. Es una excepción explícita aprobada por el usuario: un proceso local con permisos del usuario puede observar o suplantar el endpoint HTTP.

## Fuzzing local

Los cinco objetivos versionados (`guard`, `parsers`, `canonical`, `spl` y `export`) corrieron al menos 600 segundos cada uno el 2026-10-25 y terminaron con código 0, sin artefactos de fallo. Los cuatro primeros usaron el sanitizador predeterminado de `cargo-fuzz`; `export` usó `--sanitizer none` y optimización 0 para limitar el coste de compilar DuckDB en esta máquina sin swap. `export` recibió una semilla sintética válida firmada y otra malformada. El corpus temporal, los artefactos y el árbol de compilación de fuzzing se borraron tras la ejecución.

## Cadena de suministro y `unsafe`

`libsqlite3-sys` compila SQLite bundled mediante `build.rs`; `libduckdb-sys` incluye `duckdb.tar.gz` y compila C++ bundled; `libdbus-sys` es transitiva de `dbus`/Secret Service en Linux. La ruta bundled de DuckDB no descarga la biblioteca precompilada. La frontera Windows propia usa `windows-sys` oficial y es el único `unsafe` permitido en código de IRMind. Conteo estático aproximado de bloques `unsafe {` en fuentes directas críticas instaladas: `ed25519-dalek` 0; `keyring` 13; `rusqlite` 231; `duckdb` 359; `dbus` 156; `windows-sys` 8925 (bindings generados). El conteo no equivale a vulnerabilidades; estos crates tienen superficies FFI distintas y deben seguir sujetos a advisories y actualizaciones.

La revisión encontró que el SID del token debía comprobar su longitud completa antes de llamar a `IsValidSid`. La frontera ahora verifica cabecera, recuento máximo de subautoridades y tamaño dentro del búfer, y exige que `GetLengthSid` coincida. El módulo y sus tests compilan para `x86_64-pc-windows-msvc`; la ejecución real queda en el job de Windows.

| Dependencia de seguridad | Versión fijada observada | Mantenimiento y revisión |
| --- | --- | --- |
| `ed25519-dalek`, `sha2`, `rand` | 2.2.0, 0.10.9/0.11.1, 0.8.8/0.10.3 | Primitivas de firma, hash y generación de claves; `cargo audit` sin aviso en la ruta activa. Revisar cambios de RustCrypto trimestralmente. |
| `keyring`, `dbus`, `libdbus-sys` | 3.6.3, 0.9.12, 0.2.7 | Custodia nativa; tres avisos de mantenimiento afectan solo al backend `secret-service` no activado. Revisar backend y advisories el 2027-01-24. |
| `windows-sys` | 0.61.2 directo; otras versiones transitivas | Bindings oficiales de Microsoft, frontera propia con `unsafe` acotado; ejecutar ACL real en Windows y revisar cambios de API al actualizar. |
| `rusqlite`, `libsqlite3-sys` | 0.32.1, 0.30.1 | SQLite bundled con C y FFI; revisar advisories y versión de SQLite incluida antes de cada distribución. |
| `duckdb`, `libduckdb-sys` | 1.10506.1 | DuckDB bundled con C++; mayor coste de compilación y superficie nativa. Revisar tarball, licencia y advisories antes de cada distribución. |
| `reqwest`, `rustls`, `secrecy` | 0.12.28, 0.23.46, 0.10.3 | HTTP/TLS y secretos; audit sin aviso activo, raíces nativas con límite documentado. Revisar TLS y certificados corporativos en matriz real. |
| `aws-config`, SDKs AWS, `aws-smithy-*` | 1.13.0 y versiones fijadas en Cargo | Credenciales, firma AWS y transporte; feature set mínimo, timeouts explícitos y tests grabados. Revisar SDK y advisories trimestralmente. |
| `fs4`, `serde_json`, `tokio` | 0.13.1, 1.0.154, 1.54.1 | Bloqueos, deserialización y cancelación; pruebas de límites y concurrencia, más audit/deny en cada push. |

La revisión de mantenimiento se basa en versiones bloqueadas y `cargo audit`/`cargo deny` locales; no demuestra que una dependencia futura siga mantenida. Los tres avisos permitidos y sus fechas están detallados en `docs/AUDIT_WARNINGS.md`.

## Riesgos residuales

- Proceso del mismo usuario: puede acceder al llavero y volver a firmar una cadena completa; requiere anclaje externo del sello en una fase posterior.
- La apertura sin seguir el enlace final no impide la sustitución concurrente de un directorio superior; requiere recorrido basado en descriptores relativos.
- El SDK AWS limita los resultados tras deserializar la respuesta; un endpoint AWS comprometido podría forzar memoria antes del límite de 5 MB. El timeout reduce la duración, pero falta un límite de cuerpo en su transporte.
- Las referencias de GitHub Actions están fijadas a hashes de commit completos; revisar sus actualizaciones antes de cambiarlas.
- El guard no reconoce todas las instrucciones adversarias, por lo que la política y la revisión humana siguen siendo barreras obligatorias.
- No se ha ejecutado aún la matriz remota de macOS y Windows; la prueba local no acredita el comportamiento de ACL ni terminal en esos sistemas.
