Traducción de docs/parsers.md en el commit c6087e07320d77640e88c70461010cd57f1a43c1; si hay diferencias, prevalece la versión en inglés.

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
| Syslog | RFC 5424/RFC 3164, texto o gzip acotado | PRI y forma de cabecera/instante, no extensión | Host, aplicación, PID, facility, severity, mensaje y tiempo completo | experimental |
| Declarativo | CSV, JSON, NDJSON o regex acotada | Cabecera exacta, campos JSON o regex; máximo 70 % | Mapeo explícito descrito abajo | experimental |

## Un formato propio sin Rust

Abre `/parsers`, elige **Test definition** e introduce un TOML y un archivo de muestra pequeño. La vista previa muestra la confianza y hasta diez filas saneadas. No ingiere evidencia, crea casos ni contacta con un modelo. `/parsers test <definición> <archivo>` abre el mismo formulario con las rutas rellenadas; usa el formulario si contienen espacios.

Parte de uno de los [tres ejemplos](../examples/parsers/README.md). Cada definición contiene:

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

RFC 3164 necesita un año y un desplazamiento UTC proporcionados por el analista. IRMind registra la inferencia y nunca los toma del reloj del sistema. Consulta [la configuración y los límites de syslog](../development/syslog-parser.md).
