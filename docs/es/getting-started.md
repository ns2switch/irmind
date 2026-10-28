Traducción de docs/getting-started.md en el commit e414ef4daed9af488f2f72ffce62e64331cc99ac; si hay diferencias, prevalece la versión en inglés.

# Primeros pasos

Esta guía es para analistas que evalúan IRMind con datos sintéticos. Explica cómo instalarlo y abrir un primer caso local. Lee el [modelo de seguridad](security-model.md) antes de conectar un servicio real.

> IRMind está en desarrollo. No lo uses para incidentes reales ni datos sensibles.

## Instalación

La opción recomendada para uso interno es compilar desde el código. Instala Rust 1.95.0 y un terminal compatible. Puedes elegir el archivo cifrado sin disponer de un llavero del sistema. Después ejecuta:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
./target/release/irmind
```

En Windows, ejecuta `.\target\release\irmind.exe` desde Windows Terminal. Cuando haya un artefacto de CI disponible, también puedes descargarlo y comprobar `SHA256SUMS` antes de usarlo. Consulta [plataformas](platforms.md) para los pasos de cada sistema. Los binarios aún no están firmados.

## Primer arranque

Al ejecutar `irmind` sin subcomando se abre la TUI. Elige `os` o `file` por separado para la firma y los secretos. Ambos se compilan por defecto; IRMind nunca cambia de backend en silencio. El archivo cifrado pide una passphrase sin eco y funciona por SSH con un terminal interactivo, sin sesión gráfica. En el primer uso, IRMind crea la clave de firma del analista y muestra su huella pública. Guárdala por otro canal de confianza. Un paquete exportado no permite recuperar una clave perdida.

Si el backend elegido no está disponible, el arranque se detiene y la TUI ofrece cambiarlo explícitamente. La selección queda en `keystore.toml`, dentro del directorio de datos. Pulsa `k` en la pantalla de inicio para ver los backends y la huella, gestionar credenciales, cambiar la passphrase del archivo o migrar. Tras sustituir una credencial, los conectores activos conservan el valor anterior; pulsa `r` en esta vista para reiniciar la sesión.

Pulsa `m` para ver qué módulos están compilados, habilitados y configurados. Usa las flechas para elegir un módulo, Tab para elegir un campo público y `e` para editarlo. Enter selecciona un LLM o activa un conector. `k` abre sus credenciales en el llavero. Un cambio que pueda enviar datos fuera del equipo pide confirmación firmada. La TUI recarga la sesión tras aplicarlo. Ningún LLM se activa automáticamente.

Si `config.toml` requiere recuperación, la TUI ofrece restaurarlo o revisar los cambios campo a campo antes de abrir casos. Los flags y variables de entorno que cambian los destinos se muestran y requieren confirmación; rechazarlos mantiene los ajustes guardados.

## Primer caso sintético

1. Pulsa `n`, escribe un título como «Alerta de CloudTrail de prueba», elige una severidad y deja vacíos los campos de fuentes remotas. Se creará un caso local con un evento firmado.
2. En el caso, escribe `/ingest` y selecciona [el archivo sintético de CloudTrail](../../examples/cloudtrail-alert.json). IRMind lo identifica por su hash en su ubicación y crea un índice Parquet. Solo copia el original si usas expresamente `/ingest --copy-original <ruta>`.
3. Usa `/timeline` o `/graph` para examinar los eventos indexados. `/search <palabras>` busca registros JSON coincidentes. Usa `/raw <hash> <índice>` para consultar un registro indexado.
4. Vuelve a la pantalla de inicio, pulsa `m` y elige un modelo y sus ajustes públicos como explica [configuración](configuration.md). La sesión se recarga sin salir de IRMind. Abre el caso y pregunta: «¿Qué sugiere el evento AssumeRole sintético?».
5. Revisa las llamadas propuestas en la conversación. Enter envía; Alt+Enter o Shift+Enter añade una línea. Escribe `/` para ver sugerencias o pulsa `Ctrl+K` para abrir la paleta. `/pause` o Esc cancela una tarea activa.
6. Ejecuta `/verify <directorio-origen>` para comprobar los bytes originales, revisa `/report` y usa `/seal` y `/export` solo después de comprobar el hash del caso y la huella de la clave de firma que se muestran.

Puedes verificar el paquete en otro equipo con `irmind verify-export <PACKAGE> --expected-key <FINGERPRINT>`. Consulta la [referencia de la CLI](../development/cli.md) para automatización.

## Navegar por el caso

La conversación ocupa el espacio principal. Las propuestas, aprobaciones, resultados y hallazgos aparecen en tarjetas ordenadas. `Ctrl+B` muestra u oculta el panel lateral. Tab recorre cronología, evidencias, aprobaciones y hallazgos. `Ctrl+L` enfoca la conversación y `Ctrl+I` vuelve al campo de entrada. Enter o Espacio despliega una tarjeta seleccionada; `a`, `d` y `e` actúan sobre una aprobación seleccionada.

Las consultas del grafo y las búsquedas locales también aparecen como tarjetas de resultado. Las respuestas largas empiezan plegadas; selecciona la tarjeta y pulsa Enter o Espacio para desplegarla, y desplázate por la conversación.

Con un SIEM configurado, `/siem-alert` obtiene una alerta dentro del alcance por su ID. El resultado aparece como una tarjeta protegida y plegable en la conversación. `/help` muestra el orden de los argumentos.

![Conversación de un caso sintético de CloudTrail con una respuesta del modelo que aparece de forma incremental](../assets/conversation.png)

PgUp/PgDn y Ctrl+U/Ctrl+D desplazan la vista enfocada. Inicio/Fin o `g`/`G` en la conversación saltan al principio/final. El texto nuevo del modelo sigue el final solo si ya estás allí; Fin quita el indicador de contenido nuevo. ↑/↓ recuperan entradas anteriores. `/help` o `?` muestran los comandos y atajos. La rueda del ratón funciona por defecto. Para seleccionar texto con el terminal, pon `mouse_capture = false` en la [configuración](configuration.md) y acepta el cambio desde la TUI.

![Menú de comandos con sus descripciones sobre el campo de entrada](../assets/command-menu.png)

Una consulta externa espera la aprobación firmada del analista. La tarjeta muestra los argumentos exactos y el fragmento de evidencia sintética del que procede el valor no confiable.

![Tarjeta de aprobación con la consulta externa, sus argumentos y el fragmento de origen no confiable](../assets/approval-card.png)

## Siguientes pasos

Consulta [configuración](configuration.md) para el alcance, la política, los backends y los nombres de credenciales. Consulta [módulos](modules.md) para los permisos y límites de los conectores y [plataformas](platforms.md) para el uso por SSH. La TUI es el flujo principal; los subcomandos sirven para automatizar tareas.
