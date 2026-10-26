Traducción de docs/getting-started.md en el commit 095cd1db66e6dec2b51c6115d4fd44de6981e6a4; si hay diferencias, prevalece la versión en inglés.

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

En Windows, ejecuta `.\target\release\irmind.exe` desde Windows Terminal. También puedes descargar un binario de CI y comprobar `SHA256SUMS` antes de usarlo. Consulta [plataformas](platforms.md) para los pasos de cada sistema. Los binarios aún no están firmados.

## Primer arranque

Al ejecutar `irmind` sin subcomando se abre la TUI. Elige `os` o `file` por separado para la firma y los secretos. Ambos se compilan por defecto; IRMind nunca cambia de backend en silencio. El archivo cifrado pide una passphrase sin eco y funciona por SSH con un terminal interactivo, sin sesión gráfica. En el primer uso, IRMind crea la clave de firma del analista y muestra su huella pública. Guárdala por otro canal de confianza. Un paquete exportado no permite recuperar una clave perdida.

Si el backend elegido no está disponible, el arranque se detiene y la TUI ofrece cambiarlo explícitamente. La selección queda en `keystore.toml`, dentro del directorio de datos. Pulsa `k` en la pantalla de inicio para ver los backends y la huella, gestionar credenciales, cambiar la passphrase del archivo o migrar. Tras sustituir una credencial, los conectores activos conservan el valor anterior; pulsa `r` en esta vista para reiniciar la sesión.

Pulsa `m` para ver qué módulos están compilados, habilitados y configurados. Ningún LLM se activa automáticamente. Puedes trabajar con casos locales sin modelo.

## Primer caso sintético

1. Pulsa `n`, escribe un título como «Alerta de CloudTrail de prueba», elige una severidad y deja vacíos los campos de fuentes remotas. Se creará un caso local con un evento firmado.
2. En el caso, escribe `/ingest` y selecciona [el archivo sintético de CloudTrail](../../examples/cloudtrail-alert.json). El original se guarda y se identifica por su hash.
3. Usa `/timeline` o `/graph` para examinar los eventos indexados. Usa `/evidence <hash>` para ver un registro original.
4. Si tienes un proveedor aprobado, selecciónalo según [configuración](configuration.md), reinicia IRMind, abre el caso y pregunta: «¿Qué sugiere el evento AssumeRole sintético?».
5. Revisa las llamadas propuestas antes de aprobarlas. `/pause` cancela una tarea activa; `/help` y `Ctrl+K` muestran las acciones.
6. Ejecuta `/verify`, revisa `/report` y usa `/seal` y `/export` solo después de comprobar el hash del caso y la huella de la clave de firma que se muestran.

Puedes verificar el paquete en otro equipo con `irmind verify-export <PACKAGE> --expected-key <FINGERPRINT>`. Consulta la [referencia de la CLI](../development/cli.md) para automatización.

## Siguientes pasos

Consulta [configuración](configuration.md) para el alcance, la política, los backends y los nombres de credenciales. Consulta [módulos](modules.md) para los permisos y límites de los conectores y [plataformas](platforms.md) para el uso por SSH. La TUI es el flujo principal; los subcomandos sirven para automatizar tareas.
