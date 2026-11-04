Traducción de docs/parsers.md en el commit cca6df2f8ac78f6804cabb235ac7051e650479fa; si hay diferencias, prevalece la versión en inglés.

# Parsers de logs

Esta página ayuda al analista a elegir un parser local y probar un formato propio antes de ingerirlo. Todos los parsers actuales son experimentales y se han validado con datos sintéticos. Consulta [módulos](modules.md) para los formatos concretos y [configuración](configuration.md) para el directorio de datos.

## Cómo se elige el parser

El registro entrega como máximo los primeros 64 KiB a cada detector compilado. El nombre del archivo es una pista, nunca una prueba. Solo se elige automáticamente una coincidencia única con confianza del 80 % o superior. Si hay empate o confianza baja, el analista confirma. La ingesta desatendida no elige un parser ambiguo. El manifiesto firmado guarda identidad, versión, confianza y modo de elección.

`/ingest` abre el selector de archivos. `/ingest --parser <nombre> <ruta>` fuerza una elección que queda auditada. **Settings → Preferences** muestra nombres y versiones de los parsers compilados. Compilarlos no selecciona ningún modelo remoto.

| Parser | Entrada | Detección | Campos mapeados | Estado |
| --- | --- | --- | --- | --- |
| JSON y logs de nube exportados | JSON/NDJSON; AWS, GCP, Azure y HuntEval | Campos reconocidos del registro | Instante, identidades, cuentas, recursos e IP | experimental |
| ECS | NDJSON | Versión de ECS e instante/campos característicos | Evento, host, usuario, origen, destino, proceso, archivo, URL | experimental |
| OCSF | JSON/NDJSON o Parquet local | Clase, categoría y metadatos; Parquet requiere confirmación | Autenticación, API, red, procesos, archivos y hallazgos | experimental |
| Herramientas DFIR | Velociraptor, Hayabusa, Chainsaw, plaso, EZTools | Marcadores o cabecera CSV exacta | Instante, host, usuario, proceso, acción y entidades disponibles | experimental |
| Linux | auth.log/secure, auditd, journald JSON y HTTP common/combined | Etiquetas de autenticación, cabecera audit, campos de journald o cabecera HTTP completa | Tiempo, host, usuario, proceso, comando, IP/puertos, acción y resultado; grupos audit parciales | experimental |
| Syslog | RFC 5424/RFC 3164, texto o gzip acotado | PRI y forma de cabecera/instante, no extensión | Host, aplicación, PID, facility, severity, mensaje y tiempo completo | experimental |
| Declarativo | CSV, JSON, NDJSON o regex acotada | Cabecera exacta, campos JSON o regex; máximo 70 % | Mapeo explícito descrito abajo | experimental |

## Lectores actuales y casos existentes

Las ingestas nuevas usan la versión del parser registrada en su manifiesto firmado. JSON usa `json-stream-v3`. No se conservan lectores históricos. Los bytes firmados existentes se pueden autenticar y exportar; para regenerar registros de un lector anterior, crea un caso nuevo e ingiere los originales verificados. Reinstala las definiciones declarativas después de actualizar su lector. Consulta el [registro de cambios](../../CHANGELOG.md#known-issue-fixed).

## Cobertura de Windows

Hoy se investigan estos artefactos mediante exportaciones procesadas. Todos los módulos de la tabla son experimentales y están probados con datos sintéticos. IRMind ingiere las salidas; no ejecuta KAPE, EZTools, Velociraptor ni plaso, ni abre por sí mismo sus artefactos binarios originales.

| Artefacto | Qué ayuda a responder | Cómo se ingiere hoy |
| --- | --- | --- |
| Logs de eventos de Windows, incluido Sysmon | ¿Qué inicios de sesión, procesos o servicios quedaron registrados y cómo se relacionan? | CSV/JSONL de Hayabusa → `parser-hayabusa`; CSV de EvtxECmd → `parser-eztools`. EVTX directo queda pendiente del auxiliar aislado. |
| Registro y sus logs de transacciones | ¿Qué claves y valores de cuentas, configuración o persistencia se registraron? | Procesar externamente con RECmd batch e ingerir su CSV mediante `parser-eztools`. |
| Prefetch (`.pf`) | ¿Qué ejecutables, recuentos e instantes de ejecución aparecen? | CSV de PECmd → `parser-eztools`. |
| Amcache | ¿Qué rutas, hashes y fechas del inventario de aplicaciones se registraron? | CSV de AmcacheParser → `parser-eztools`. |
| AppCompatCache / ShimCache | ¿Qué rutas y metadatos de caché se registraron? | CSV de AppCompatCacheParser → `parser-eztools`. La presencia en caché no demuestra por sí sola ejecución. |
| `$MFT` | ¿Qué rutas y fechas del sistema de archivos se registraron? | CSV de MFTECmd → `parser-eztools`. |
| Accesos directos LNK | ¿Qué destinos, directorios de trabajo y fechas del acceso directo se registraron? | CSV de LECmd → `parser-eztools`. |
| SRUM (`SRUDB.dat`) | ¿Qué aplicaciones y usuarios tienen datos de uso de recursos o red? | CSV de SrumECmd → `parser-eztools`. Los totales de uso no demuestran por sí solos exfiltración. |

Otra vía admitida para estos artefactos es exportar resultados JSONL de Velociraptor con timestamp y metadatos de artefacto, para `parser-velociraptor`, o `json_line` de `psort` de plaso para `parser-plaso`. El esquema debe coincidir con [los contratos de los módulos](modules.md#parser-de-velociraptor): no se admite automáticamente cualquier salida de un colector. EZTools requiere los nombres de columna reconocidos y un timestamp utilizable; los campos no mapeados permanecen en el registro. Empieza por los eventos y correlaciona ejecución, persistencia, movimiento lateral y posible exfiltración, sin tratar un único artefacto como prueba concluyente.

Los [targets y módulos de KAPE](https://github.com/EricZimmerman/KapeFiles), [EZTools](https://ericzimmerman.github.io/) y [los artefactos de Velociraptor](https://docs.velociraptor.app/docs/artifacts/) describen la recogida y el procesamiento externo. Conserva los originales y selecciona las exportaciones procesadas para ingerirlas. Los parsers nativos de registro y `$MFT` quedan como trabajo futuro según demanda, con el auxiliar aislado descrito en [la hoja de ruta](roadmap.md#v02-parsers-y-conectores). Está previsto [un parser de JSON de Volatility 3](https://github.com/ns2switch/irmind/issues/158); no se ingieren directamente imágenes de memoria.

## Un formato propio sin Rust

Abre `/parsers`, elige **Test definition** e introduce un TOML y un archivo de muestra pequeño. La vista previa muestra la confianza y hasta diez filas saneadas. No ingiere evidencia, crea casos ni contacta con un modelo. `/parsers test <definición> <archivo>` abre el mismo formulario con las rutas rellenadas; usa el formulario si contienen espacios.

Parte de uno de los [ejemplos](../examples/parsers/README.md). Cada definición contiene:

- `version = 1`, nombre en minúsculas y descripción breve.
- `input.format`: `csv`, `json`, `ndjson` o `regex`. CSV declara delimitador y cabecera. Regex usa capturas con nombre y el motor de Rust de tiempo lineal.
- `detect.header`, `detect.required_fields` o `detect.pattern`. La confianza va de 1 a 70, por debajo de los formatos nativos de alta confianza. En JSON, los campos son punteros JSON. Solo se analiza la muestra acotada.
- `mapping`: campo común a columna CSV, puntero JSON o captura regex. `time` es obligatorio. Son opcionales `host`, `user`, `process`, `command_line`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `action`, `outcome`, `account` y `region`. El resto del original se conserva en el registro.
- `timestamp.format`: `rfc3339`, `unix` en segundos decimales o un patrón de fecha de chrono. `timestamp.default_timezone` es `UTC`, `Z` o un desplazamiento fijo como `+02:00`. El desplazamiento del original tiene prioridad. Se conserva el texto temporal completo; el índice actual tiene precisión de segundos.
- `limits` opcional para reducir `record_bytes`, `depth`, `fields` y `records`. No permite superar 1 MiB por registro, profundidad 32, 1.024 campos JSON ni diez millones de registros. Cada fuente tiene un máximo de 50 GiB.

La definición no supera 64 KiB. Cada regex tiene como máximo 4 KiB de fuente y 1 MiB para la compilación y el DFA. La muestra de vista previa no supera 1 MiB. Los registros inválidos se cuentan y dejan hasta tres extractos acotados y escapados. Un error irrecuperable de estructura o límite de archivo detiene ese archivo. Nunca se ejecuta la entrada.

## Instalar, cambiar, desactivar y recuperar

Revisa primero la vista previa. Elige **Install definition**, comprueba nombre y SHA-256 y confirma **Sign and apply**. La aplicación firma la definición completa validada en la cadena operativa global, escribe de forma atómica con permisos privados y reinicia la sesión. No necesita un caso. Para cambiarla, instala la versión revisada mediante el mismo flujo; no edites archivos activos para evitar la aprobación.

Los archivos aceptados viven en `parsers/active/` dentro del directorio de datos privado y sus copias por hash en `parsers/archive/`. Un archivo ausente, cambiado, inválido o sin firma queda desactivado y visible en `/parsers`, sin impedir el arranque. **Restore approved file** restaura explícitamente la versión firmada. **Deactivate definition** firma la desactivación para futuras detecciones; las versiones históricas siguen disponibles para reconstruir. Un fallo de escritura tras firmar requiere restauración explícita, nunca aceptación silenciosa.

El hash de la definición forma parte de la versión del parser en el manifiesto existente. Reconstruir un caso usa esa versión exacta, incluso tras cambiarla o desactivarla. El manifiesto exportado conserva el hash; reconstruir en otra máquina requiere también la definición aprobada correspondiente. Verificar una exportación no ejecuta definiciones. Se rechazan enlaces simbólicos. Las escrituras temporales quedan dentro del directorio privado y se borran al terminar o fallar; el arranque limpia temporales huérfanos.

Los registros conservan taint y procedencia de fuente, parser y offset. El guard sanea vista previa, evidencia mostrada y contexto del modelo. Una definición no concede permisos ni cambia el techo de la organización. Mantén las respuestas esperadas de episodios sintéticos fuera del directorio de fuentes que ingieres.

### Tiempo de syslog clásico

RFC 3164 abre un formulario temporal antes de ingerir. Confirma el año del primer registro, el desplazamiento UTC fijo, si diciembre → enero incrementa el año y si la elección se aplica a un fichero o a toda la ingesta. Los campos empiezan vacíos. Otras fuentes verificadas del mismo host pueden sugerir el año y la zona; debes confirmarlos. IRMind nunca usa el reloj del equipo ni la fecha de modificación. Otros retrocesos de mes cuentan como registros inválidos. La elección queda firmada con la fuente. Consulta [el contrato y los límites de syslog](../development/syslog-parser.md).

### Exportaciones de Linux

Auth.log/secure clásico usa el mismo formulario temporal por ingesta que syslog. Journald conserva el instante original en microsegundos. Auditd agrupa registros acotados con el mismo nodo, instante y serial; los grupos incompletos se marcan como parciales. Los formatos de acceso HTTP estándar no incluyen el host del servidor: IRMind lo deja desconocido. Para formatos propios, adapta el [ejemplo declarativo de exportación HTTP](../examples/parsers/nginx-apache-custom.toml). El [contrato de Linux](../development/linux-parser.md) detalla los límites y los campos mapeados.
