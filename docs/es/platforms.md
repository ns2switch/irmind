Traducción de docs/platforms.md en el commit ba25f5d9205890fc05649a84caaa003d08bc0116; si hay diferencias, prevalece la versión en inglés.

# Plataformas

Esta página es para quienes instalan IRMind en Linux, macOS o Windows, también en equipos a los que acceden por SSH. Explica compilación, binarios sin firma, backends de llavero y terminales. Empieza por [primeros pasos](getting-started.md) para el flujo de un caso.

## Compilar desde el código

La compilación desde el código es la vía recomendada para una evaluación interna:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
```

CI prueba Ubuntu Linux, macOS arm64 y Windows x64 con el toolchain MSVC. SQLite y DuckDB se compilan desde fuentes incluidas. TLS usa rustls con las raíces de certificados nativas, incluidas las CA corporativas instaladas; IRMind no enlaza OpenSSL del sistema. Esta opción de raíces nativas puede diferir de las comprobaciones de política de un verificador específico de cada plataforma.

## Artefactos de CI y checksums

La ejecución diaria de CI en `main` publica un binario por plataforma solo cuando hubo cambios de código en las 24 horas anteriores. Los cambios exclusivos de documentación no generan binarios de distribución. Cada artefacto incluye las dos licencias del proyecto, los avisos de terceros y `SHA256SUMS`. Descárgalo de una ejecución diaria de confianza y compara el checksum **antes** de ejecutar el archivo:

| Sistema | Comprobación |
| --- | --- |
| Linux | Ejecuta `sha256sum -c SHA256SUMS` en el directorio extraído. |
| macOS | Ejecuta `shasum -a 256 -c SHA256SUMS` en ese directorio. |
| Windows PowerShell | Compara `(Get-FileHash .\irmind.exe -Algorithm SHA256).Hash.ToLowerInvariant()` con la línea de `irmind.exe` en `SHA256SUMS`. |

Los binarios no tienen firma de código, notarización ni Authenticode. El checksum demuestra que el archivo coincide con el artefacto de CI elegido, no quién lo publicó. La decisión sobre firma de distribución se revisará antes del 24 de abril de 2027.

## Linux

Usa un terminal compatible con xterm, como GNOME Terminal o Konsole. El backend `os` necesita Secret Service mediante D-Bus, que puede no estar disponible por SSH. Elige `file` explícitamente para una sesión sin entorno gráfico. Los archivos y directorios locales se restringen al usuario actual con permisos Unix `0600` y `0700`.

## macOS

Usa Terminal.app o iTerm2. `os` utiliza Keychain; `file` se puede elegir explícitamente por SSH. CI compila para Apple Silicon. Después de comprobar el checksum, Gatekeeper puede bloquear el binario descargado sin firma. Autoriza **solo ese binario** en Ajustes del Sistema → Privacidad y seguridad, o elimina únicamente su atributo de cuarentena con `xattr -d com.apple.quarantine ./irmind`. Nunca desactives Gatekeeper para todo el sistema.

## Windows

Usa Windows Terminal y el binario x64 MSVC. `os` utiliza Credential Manager; `file` está disponible si se selecciona explícitamente. IRMind comprueba que los archivos del caso y el almacén cifrado están restringidos al SID del usuario actual. SmartScreen o el antivirus corporativo pueden advertir sobre un binario sin firma. Comprueba el checksum y la procedencia y, si la política lo permite, solicita una excepción limitada al equipo de seguridad. No desactives la protección globalmente.

## Datos y terminal

Sin `--home`, los datos se guardan en el directorio estándar de datos locales de cada plataforma: XDG en Linux, Application Support en macOS y LocalAppData en Windows. Los nombres de evidencia son hashes en minúsculas; las rutas de auditoría y exportación son relativas y usan `/`. Cada caso tiene una base SQLite de auditoría y un grafo derivado DuckDB.

La TUI usa la pantalla alternativa y sanea el texto externo antes de mostrarlo. Los tests automáticos comprueban secuencias de control y controles bidireccionales en los tres sistemas. La interacción visual aún requiere revisión manual en cada terminal antes de usarse en producción. Por SSH, solicita un terminal con `ssh -t`, elige `file` y escribe la passphrase en el prompt sin eco. IRMind no cambia de backend en silencio. `verify-export` funciona sin desbloquear un llavero.
