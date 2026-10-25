Traducción de docs/platforms.md en el commit 332d190657f969d89689b9ae150900b5c7b35723; si hay diferencias, prevalece la versión en inglés.

# Plataformas

Esta página es para quienes instalan IRMind en Linux, macOS o Windows. Explica los requisitos de compilación, los binarios de CI sin firmar, los llaveros y el comportamiento del terminal. Empieza por [primeros pasos](getting-started.md) para el flujo de un caso.

## Compilar desde el código

La compilación desde el código es la vía recomendada para una evaluación interna:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
```

CI prueba Ubuntu Linux, macOS arm64 y Windows x64 con el toolchain MSVC. SQLite y DuckDB se compilan desde fuentes incluidas. TLS usa rustls con las raíces de certificados nativas, incluidas las CA corporativas instaladas; IRMind no enlaza OpenSSL del sistema. Esta opción de raíces nativas puede diferir de las comprobaciones de política de un verificador específico de cada plataforma.

## Artefactos de CI y checksums

Cada job publica el binario, las dos licencias del proyecto, los avisos de terceros y `SHA256SUMS`. Descarga desde una ejecución de CI de confianza y compara el checksum **antes** de ejecutar el archivo:

| Sistema | Comprobación |
| --- | --- |
| Linux | Ejecuta `sha256sum -c SHA256SUMS` en el directorio extraído. |
| macOS | Ejecuta `shasum -a 256 -c SHA256SUMS` en ese directorio. |
| Windows PowerShell | Compara `(Get-FileHash .\irmind.exe -Algorithm SHA256).Hash.ToLowerInvariant()` con la línea de `irmind.exe` en `SHA256SUMS`. |

Los binarios no tienen firma de código, notarización ni Authenticode. El checksum demuestra que el archivo coincide con el artefacto de CI elegido, no quién lo publicó. La decisión sobre firma de distribución se revisará antes del 24 de abril de 2027.

## Linux

Usa un terminal compatible con xterm, como GNOME Terminal o Konsole. Secret Service debe estar disponible mediante D-Bus; IRMind falla de forma cerrada si no puede guardar o cargar la clave de firma. Los archivos y directorios locales se restringen al usuario actual con permisos Unix `0600` y `0700`.

## macOS

Usa Terminal.app o iTerm2. Las claves de firma se guardan en Keychain. CI compila para Apple Silicon. Después de comprobar el checksum, Gatekeeper puede bloquear el binario descargado sin firma. Autoriza **solo ese binario** en Ajustes del Sistema → Privacidad y seguridad, o elimina únicamente su atributo de cuarentena con `xattr -d com.apple.quarantine ./irmind`. Nunca desactives Gatekeeper para todo el sistema.

## Windows

Usa Windows Terminal y el binario x64 MSVC. Las claves de firma se guardan en Credential Manager. IRMind comprueba que los archivos locales del caso están restringidos al SID del usuario actual. SmartScreen o el antivirus corporativo pueden advertir sobre un binario sin firma. Comprueba el checksum y la procedencia y, si la política lo permite, solicita una excepción limitada al equipo de seguridad. No desactives la protección globalmente.

## Datos y terminal

Sin `--home`, los datos se guardan en el directorio estándar de datos locales de cada plataforma: XDG en Linux, Application Support en macOS y LocalAppData en Windows. Los nombres de evidencia son hashes en minúsculas; las rutas de auditoría y exportación son relativas y usan `/`. Cada caso tiene una base SQLite de auditoría y un grafo derivado DuckDB.

La TUI usa la pantalla alternativa y sanea el texto externo antes de mostrarlo. Los tests automáticos comprueban secuencias de control y controles bidireccionales en los tres sistemas. La interacción visual aún requiere revisión manual en cada terminal antes de usarse en producción. No existe un respaldo de clave en archivo cifrado si falta el llavero nativo; `verify-export` sí puede ejecutarse sin un llavero local.
