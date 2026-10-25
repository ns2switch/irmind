# Decisiones de arquitectura aceptadas

`docs/PLAN.md` define los hitos H0–H8 y sus criterios de cierre. Estas decisiones precisan las desviaciones aceptadas.

## ProposedCall no incluye risk

El nivel de riesgo lo determina `Tool` en el dominio. Así, una propuesta del modelo no puede rebajar el riesgo de la herramienta que solicita. La política evalúa el riesgo derivado del tipo de herramienta.

## DuckDB para el grafo

El grafo derivado de evidencias usa DuckDB para consultas analíticas locales sobre registros y relaciones. SQLite conserva los casos y el log firmado; el grafo se puede reconstruir desde las evidencias originales.

## Actor y procedencia separados

`Actor` identifica al firmante, `Analyst` o `Agent`, con claves distintas. La procedencia concreta del evento se registra aparte en `origin`. Esto permite verificar quién firmó cada acción sin confundir identidad criptográfica con el origen lógico del dato o la operación.

## Puertos locales síncronos

Los puertos de SQLite, DuckDB, evidencias, firma, verificación, guard y parser conservan operaciones síncronas para mantener transacciones y contratos simples. Los casos de uso async las ejecutan en `tokio::task::spawn_blocking`, y las tareas largas comprueban la cancelación entre lotes. Los puertos remotos siguen siendo async y cancelables. Decisión: 2026-10-24.

`Tainted<T>` permite inspección local mediante una visita que no devuelve el valor. La transferencia del valor en propiedad requiere aprobación firmada y evento de auditoría. La visita es una frontera de confianza del código: un adaptador local con acceso al dato podría copiarlo deliberadamente dentro de la visita; los tests de tipos protegen contra la extracción directa, no convierten al adaptador en un sandbox.

## Multiplataforma

macOS, Linux y Windows deben ofrecer las mismas garantías de custodia, política y protección de datos. La portabilidad forma parte del criterio de aceptación, no se limita a que el código compile. Decisión: 2026-10-24.

## Distribución sin firma de binarios

Por ahora no se firman los binarios, ni se aplica notarización en macOS o Authenticode en Windows. Para uso interno se prioriza la compilación desde el código y la verificación de checksums de los artefactos de CI. Esta decisión no altera las firmas Ed25519 de evidencias y auditoría. Decisión: 2026-10-24. Revisión: 2027-04-24 o antes de distribuir a terceros, lo que ocurra primero.

## Respaldo del llavero

No habrá respaldo del llavero. Si Secret Service, Keychain o Credential Manager no están disponibles, IRMind falla cerrado. Decisión: 2026-10-25.

## Raíces TLS nativas

Los clientes HTTP usan rustls con raíces del almacén del sistema mediante `rustls-tls-native-roots`; el SDK AWS usa su almacén nativo por defecto. Esto permite CA corporativas instaladas por el administrador. Frente a `rustls-platform-verifier`, la carga de raíces no reproduce todas las decisiones del verificador del sistema, como desconfianza explícita y revocación en algunas plataformas. Decisión: 2026-10-25.

## Licencia MPL-2.0 para directorios estándar

Se permite MPL-2.0 en `cargo-deny` para usar la versión actual de `directories`; su dependencia `option-ext` usa esa licencia. La licencia no cambia las reglas de política ni custodia de IRMind. Decisión: 2026-10-25.

## Sello recuperable

La transacción de SQLite deja una intención de sellado pendiente antes de crear el archivo. El archivo se escribe con un nombre temporal privado, se sincroniza, se renombra y en Unix se sincroniza el directorio; Windows usa `MOVEFILE_WRITE_THROUGH`. Al abrir la base, solo se recuperan intenciones pendientes cuya firma de sello, cadena firmada, manifiesto y evidencias se verifican; un sello existente que no coincide nunca se sobrescribe. Sin firma de sello persistida, la intención sigue pendiente y `verify` informa la inconsistencia. Decisión: 2026-10-25.

## Dos operaciones de auditoría

`append` conserva una forma breve para eventos que no modifican el caso; delega en `transact` con mutación nula. Los cambios del caso usan `transact` para escribir estado y evento en una transacción. Decisión: 2026-10-25.

## Windows MSVC en CI

Los tests de Windows se compilan y ejecutan con `x86_64-pc-windows-msvc`; los tests de ACL no se excluyen ni se sustituyen por compilación cruzada. Decisión: 2026-10-25.

## Frontera Win32 auditada

Se autoriza una excepción `unsafe` limitada al módulo `windows_security` de infraestructura, que usa `windows-sys` oficial para leer el SID del token, fijar y comprobar la ACL y renombrar el sello con `MOVEFILE_WRITE_THROUGH`. El resto de los crates conserva `forbid(unsafe_code)`; la infraestructura usa `deny(unsafe_code)` y solo permite esta frontera. Se retiraron `stellar-agent-windows-identity` y `windows-permissions`, sin mantenimiento desde 2021. Windows no ofrece un `fsync` de directorio equivalente a Unix; el renombrado durable se combina con intención pendiente y reconciliación. Decisión autorizada por el usuario: 2026-10-25.

Antes de llamar a `IsValidSid` o `EqualSid`, la frontera Win32 comprueba que el SID declarado por el ACE cabe por completo en `AceSize`, además de comprobar el tipo, los permisos y el SID esperado. Esta validación evita leer fuera del ACE si una ACL está dañada. Decisión: 2026-10-25.

El SID devuelto por el token del proceso también se acota antes de llamar a `IsValidSid`: se exige su cabecera completa, máximo 15 subautoridades y longitud total dentro del búfer devuelto por `GetTokenInformation`. `GetLengthSid` debe coincidir después. Así ni siquiera un token malformado se entrega a Win32 con un rango no comprobado. Decisión: 2026-10-25.

## Lints de código público y muerto

`unreachable_pub` y `dead_code` se deniegan en todo el workspace. Los métodos de `GraphStore` y las funciones de serialización de `Actor` que solo usa su crate pasan a `pub(crate)`. El barrido con `cargo-machete` no encontró dependencias sin uso. La duplicación de validación HTTP entre adaptadores LLM y EDR se mantiene por ahora: cada producto conserva protocolo, autenticación y pruebas propios; se propone una utilidad interna común solo si una medición demuestra ahorro sin mezclar contratos. Decisión: 2026-10-25.

## Desafío de aprobación de duración limitada

La firma de aprobación usa un separador de dominio propio y cubre caso, secuencia, herramienta, argumentos canónicos, SHA-256 de esos argumentos y vencimiento a cinco minutos. `sha2` se añade al dominio como primitiva pura sin I/O; es una excepción explícita a la preferencia inicial por `std` exclusivo, necesaria para vincular criptográficamente el hash de los argumentos sin delegar la decisión de autorización a infraestructura. Decisión: 2026-10-25.

## Firma independiente del sello

`Repository::write_seal_file` recibe ahora un `CaseSeal` firmado por el caso de uso con `irmind-seal-v1`, el id, la secuencia, el hash final y el manifiesto. SQLite conserva la firma en una tabla de intención append-only antes de crear el archivo. Si la caída ocurre tras la transacción de auditoría y antes de guardar esa firma, `verify` declara el caso inconsistente: no se inventa una firma nueva. El paquete exportado pasa a versión 3; los paquetes antiguos se rechazan porque reutilizaban la firma de auditoría como sello. Cambio de puerto aprobado por el usuario: 2026-10-25.

## Búsqueda SIEM restringida

El MVP solo acepta un término literal en `siem_search`; Splunk construye en el servidor el índice configurado y los límites `earliest_time`/`latest_time` de los argumentos ya contrastados con el alcance. Se deniegan los nombres de comandos con efectos o lectura privilegiada (`outputlookup`, `outputcsv`, `collect`, `sendemail`, `sendalert`, `script`, `run`, `rest`, `map`, `delete`, `tscollect`, `meventcollect`). Cualquier texto no clasificable como literal genera `NeedsApproval` con la consulta exacta, pero el adaptador no ejecuta SPL arbitrario aun después de aprobarlo. La aprobación no amplía el dialecto seguro. Decisión: 2026-10-25.

## Límite del paquete exportado

`export` y `verify-export` rechazan paquetes JSON mayores de 128 MiB antes de acumularlos o analizarlos; cada evidencia decodificada sigue limitada a 50 MB. El formato no extrae rutas ni descomprime archivos. Un caso mayor debe dividirse o requerirá en el futuro un formato streaming firmado, sin elevar este límite por configuración. Decisión: 2026-10-25.

## Apertura de evidencia sin seguir el enlace final

La lectura de archivos para ingesta usa `O_NOFOLLOW` en Unix y `FILE_FLAG_OPEN_REPARSE_POINT` con comprobación de atributo en Windows. Tras abrir comprueba que el descriptor sea un archivo regular, lee una copia acotada y el motor hashea y procesa esos mismos bytes. La carrera por sustitución de componentes de directorio superiores exige en el futuro un recorrido por descriptores relativos; queda registrada como riesgo local residual. Decisión: 2026-10-25.

## Errores de red sin URL

Los adaptadores HTTP devuelven errores de transporte estáticos en lugar de propagar el texto de `reqwest::Error`, que puede incluir URLs con IOC o datos del caso. Los códigos HTTP se conservan para diagnóstico. Decisión: 2026-10-25.

## Ollama local por HTTP o HTTPS

El endpoint OpenAI compatible permite HTTP solo si el destino es `localhost` o una IP de loopback, para mantener la conexión directa con Ollama local, y también permite HTTPS. Los servicios remotos siguen exigiendo TLS y clave específica. Esta excepción a «HTTP: solo TLS» fue indicada por el usuario el 2026-10-25; HTTP local no protege ante un proceso del mismo equipo que intercepte o suplante el servicio. Las redirecciones permanecen desactivadas.

## Unificación de features y límite de memoria

Se evaluó `cargo-hakari 0.9.39` con los tres targets de CI. Su manifiesto generado activaba `serde_json/preserve_order` en crates que no usan AWS y añadía dependencias de conectores opcionales a otros crates. La feature `unbounded_depth` también aparecía, pero solo habilita una API optativa: el límite de profundidad predeterminado permanece activo. El workspace-hack cambiaría la representación de JSON y la modularidad de compilación, por lo que se descartó. Se mantienen features explícitas, con `default-features = false` donde es seguro. Revisión si cargo-hakari permite unificar solo dependencias compartidas sin cambiar la representación de datos ni conectar familias de productos. Decisión: 2026-10-25.

La máquina local carece de swap y sufrió una interrupción por memoria al compilar DuckDB con ASan y otra compilación en paralelo. Las mediciones y pruebas restantes se ejecutan secuencialmente con `CARGO_BUILD_JOBS=1`; el target de fuzz de exportación usa libFuzzer sin sanitizador y con optimización de compilación a nivel 0 para contener la compilación C++ de DuckDB. B3e aplicó ese mismo límite a CI; B3f lo retira de los runners. Decisión: 2026-10-25.

## Timeout de AWS

El SDK AWS fija 10 s para conectar, 30 s para leer, 45 s por intento y 90 s para la operación completa. Así la cancelación del caso no depende solo de descartar el futuro y el proveedor no puede retener indefinidamente una llamada. Decisión: 2026-10-25.

## Errores locales sin datos de evidencia

Los errores del motor DuckDB y del llavero se reducen a mensajes estáticos. Una excepción de SQL puede incluir valores de registros y una excepción del llavero puede contener detalles de cuenta o backend; ninguno debe alcanzar auditoría, TUI ni trazas. Decisión: 2026-10-25.

Los errores de cualquier puerto remoto se reducen en el motor a `remote tool execution failed` antes de mostrarlos. El evento `ToolError` firmado guarda solo el identificador de la herramienta, no el texto aportado por un adaptador o proveedor. Esto mantiene el límite aunque un módulo nuevo propague por error una URL o un secreto. Decisión: 2026-10-25.

La CLI de ingesta y sus errores muestran rutas con `Debug` escapado en vez de `Path::display()`. Un nombre de archivo creado por un adversario puede contener controles de terminal; el escape conserva el nombre legible sin ejecutarlos en la pantalla. Decisión: 2026-10-25.

`SignedEntry`, `Tainted<T>`, `ProposedCall`, `ApprovalRequest`, `CompletionRequest` y `ModelResponse` implementan `Debug` sin valores de evidencia, argumentos, mensajes, respuesta ni firma. Así una traza accidental de esos tipos no vuelca datos sensibles. La serialización firmada y el acceso normal a los campos conservan su comportamiento. Decisión: 2026-10-25.

## Límites del parser JSON

El parser rechaza entradas de más de 50 MB y más de 100 000 registros; conserva el límite de profundidad predeterminado de `serde_json`. Las colecciones grandes se tratarán con parser en streaming en C4, sin subir estos límites por configuración. Decisión: 2026-10-25.

## Instalación precompilada de cargo-fuzz en CI

`taiki-e/install-action` no incluye `cargo-fuzz` en su lista de herramientas; con `fallback: none` fallaría y con el fallback habitual podría compilar desde fuentes. El job semanal descarga el binario oficial Linux 0.13.2, fija su SHA-256 y borra el archivo de descarga al terminar. Los demás subcomandos Cargo de CI se instalan con `taiki-e/install-action` sin fallback; mold procede del paquete binario de Ubuntu. No se ejecuta `cargo install` en CI. Decisión: 2026-10-25.

## CI y caché de compilación

Linux ejecuta todas las puertas en cada push y PR; Windows ejecuta sus pruebas en PR y main, y macOS en main, nightly y tags. Los jobs de Windows y macOS esperan a Linux. La verificación cruzada se hace en el mismo job de destino; un job breve de Linux verifica el paquete creado por Windows. Se usan cachés separadas por sistema y job, perfil `ci` y mold en Linux; la compilación serial de B3e se retiró de CI en B3f. Mold se instala desde el paquete binario de Ubuntu porque tampoco figura en el catálogo de `taiki-e`. No se añade sccache sin una medición remota que demuestre que `rust-cache` es insuficiente. Las duplicaciones de `crossterm`, `base64`, `hashlink` y `toml` vienen de versiones mayores fijadas por dependencias transitivas; forzarlas sin prueba de compatibilidad cambiaría el comportamiento. Decisión: 2026-10-25.

En B3e, `nextest` usaba un solo hilo de tests en local y CI. Las pruebas de grafo y custodia pueden coincidir en memoria con DuckDB; en una máquina sin swap se prefiere una ejecución predecible. B3f conserva esa limitación solo en local y usa un grupo limitado para infraestructura en CI. La ejecución final en Linux terminó en 31,454 s, con 117 tests aprobados. Decisión: 2026-10-25.

## B3f: paralelismo de CI y módulos internos

La compilación de CI usa el paralelismo del runner; `CARGO_BUILD_JOBS=1` y `--test-threads 1` quedan reservados para la máquina local sin swap. `nextest` limita a dos los tests de `irmind-infra`, que abren bases locales pesadas, sin serializar los demás crates. macOS depende solo de Linux y se ejecuta en paralelo con Windows; un job posterior verifica el paquete de Windows en macOS para conservar la verificación cruzada. La clave de concurrencia usa el nombre de rama tanto en push como en PR, de modo que el PR cancela el run previo de esa misma rama. Los jobs de compilación tienen 120 minutos de límite mientras se mide la primera ejecución con DuckDB bundled; se ajustarán con el tiempo real observado. Decisión: 2026-10-25. Esta decisión sustituye la serialización global descrita arriba.

`irmind-app` separa puertos, motor, despacho, aprobaciones, ingesta, informes y custodia. `irmind-infra` separa SQLite, evidencias, firma, sello, grafo, reloj y la frontera Win32. Las fachadas de ambos crates mantienen las exportaciones públicas anteriores. Los helpers compartidos entre archivos son visibles solo dentro del crate. Decisión: 2026-10-25.

## B3f: reloj inyectado

El dominio recibe segundos Unix como dato explícito al evaluar propuestas, crear una aprobación pendiente y resolverla; no consulta el reloj del sistema. `Clock` es un puerto obligatorio inyectado por la raíz de composición. `SystemClock` vive en infraestructura y `FixedClock` en testkit. Un fallo al leer el reloj impide firmar el evento o aprobar una llamada. La reconstrucción de una aprobación firmada usa el instante de su propia entrada de auditoría para recomputar su política original. Decisión: 2026-10-25.

## Propuesta para C: consulta SIEM estructurada

Se propone que el modelo produzca un AST de consulta con campos permitidos por fuente (`event_time`, cuenta, host, usuario, IP, proceso y nombre de evento), operadores tipados (`eq`, `in`, `contains`, comparaciones temporales), ventana obligatoria dentro del caso, límite de resultados y agregaciones simples (`count by`, `top`, `distinct`). El dominio valida cada campo, operador y límite; el módulo Splunk traduce el AST a SPL, escapa los valores y fija el índice y la ventana por parámetros del servidor. La política y la TUI muestran tanto el AST canónico como la consulta efectiva antes de una aprobación. Nunca se aceptará SPL libre del modelo. Esta propuesta no se implementa en B3f y requiere diseño y tests de traducción en C. Propuesta: 2026-10-25.

## Fase T: TUI como punto de entrada

`irmind` sin subcomando abre la TUI. La pantalla de inicio permite descubrir y crear casos; el espacio del caso reúne investigación, ingesta, custodia e informe. Los subcomandos permanecen para automatización y usan los mismos casos de uso. Ningún proveedor LLM se activa de forma implícita. La interfaz no muestra secretos y limpia el contenido externo antes de dibujarlo. Las tareas largas se cancelan mediante el token existente y registran la cancelación. El criterio de H6 es una prueba de caso completo con `ratatui::TestBackend` y módulos falsos, sin CLI. Decisión: 2026-10-25.

## Fase T: auditoría operativa de cancelaciones

Un caso sellado no admite nuevas entradas sin invalidar su sello. Las cancelaciones de tareas de la TUI se registran en una cadena operativa Ed25519 separada, vinculada al `case_id`, con prefijo canónico `irmind-operation-v1`. `verify` comprueba también esa cadena; la cadena sellada del caso no cambia. El analista aprobó ampliar `AuditLog` para este fin. Decisión: 2026-10-25.

`verify-export` se ofrece mediante un puerto local `ExportVerifier` de `irmind-app`. La implementación existente de infraestructura conserva la verificación sin llavero; la CLI la invoca antes de abrir almacenamiento y la TUI la ofrece desde la pantalla de inicio. El analista aprobó este cambio de puerto. Decisión: 2026-10-25.

La exportación usa el puerto local síncrono `CaseExporter` y un único caso de uso de `irmind-app` para TUI y CLI. Ese caso de uso mantiene el bloqueo del caso durante la verificación firmada y la creación del paquete; el adaptador cancela entre evidencias y bloques de escritura y borra un archivo de salida incompleto. El analista aprobó añadir el puerto. Decisión: 2026-10-25.

Para confirmar `seal`, la aplicación prepara una entrada firmada y muestra su hash final real antes de escribirla. Tras la confirmación, comprueba que el caso, su manifiesto y la cabeza de la cadena siguen iguales; una vista previa obsoleta se rechaza. `Engine::seal` usa la misma preparación y ejecución, también desde la CLI. Decisión: 2026-10-25.

La preparación del sello puede verificar evidencias grandes. La TUI la ejecuta en un trabajador cancelable y solo muestra la confirmación cuando recibe una vista previa firmada válida; cancelar no añade la entrada de sello. Decisión: 2026-10-25.

La exportación desde la TUI comprueba la cadena y las evidencias con `verify_cancelable` antes de crear el paquete, igual que la CLI. Una evidencia alterada impide crear el archivo de salida. Decisión: 2026-10-25.

La primera ejecución de B3f reveló que Cargo inicia los tests de integración desde `crates/bin`, mientras el artefacto de CI se buscaba en la raíz del workspace. La ruta del fixture portable se fija con `GITHUB_WORKSPACE` para que Linux y Windows publiquen el archivo que verifican los otros sistemas. Corrección: 2026-10-25.

## Publicación como software libre

IRMind se publica bajo `MIT OR Apache-2.0`, con copyright de 2026 de Aníbal Cañada. Cada commit de un PR debe llevar un tráiler DCO `Signed-off-by` que coincida con el correo del autor; el check DCO precede a los trabajos de compilación para evitar gastar minutos en PRs sin firma. El README declara que la aplicación aún no sirve para incidentes reales con datos sensibles. `SECURITY.md` dirige los informes a GitHub Private Vulnerability Reporting, que se debe habilitar en la configuración del repositorio antes de hacerlo público. Decisión: 2026-10-25.

`cargo-deny` permite la expresión dual del proyecto y todas las licencias actuales de dependencias. `option-ext` 0.2.0 es MPL-2.0, compatible como archivo de una obra mayor, pero conserva sus obligaciones propias; su fuente y licencia se indican en `THIRD_PARTY_NOTICES.md`. Los artefactos de CI incluyen ambas licencias y ese aviso. Un inventario exhaustivo de avisos para todos los componentes, incluidos los nativos, sigue siendo una puerta antes de una distribución binaria externa formal. Decisión: 2026-10-25.

El workspace separado de fuzzing también pasa `cargo-deny`: las dependencias locales llevan versión explícita y se permite NCSA porque `libfuzzer-sys` usa `(MIT OR Apache-2.0) AND NCSA`. NCSA es permisiva y el fuzzer no forma parte del binario distribuido. Se comprueban ambos lockfiles por separado; el pase del workspace principal no cubre el de fuzzing. Decisión: 2026-10-25.

Al pasar a repositorio público, macOS vuelve a ejecutarse en todos los PR, incluidos los que solo cambien documentación; se mantienen cachés, compilación serial, perfil `ci` y verificaciones cruzadas. Los workflows conservan `contents: read` y fijan todas las Actions a commits completos, incluidas las Actions de GitHub. `workflow_dispatch` ejecuta también las tres plataformas y las verificaciones cruzadas para validar manualmente el primer commit público. Los jobs dependientes usan `!cancelled()` para que una ejecución cancelada no siga ocupando la matriz. La rama pública debe requerir los checks DCO, Linux, Windows y macOS. Esta decisión sustituye la cadencia de macOS descrita en la sección anterior. Decisión: 2026-10-25.
