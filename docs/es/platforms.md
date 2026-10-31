Traducción de docs/platforms.md en el commit 1062ed9ecebb5f0c6cbe3fbccb335de723e20dbe; si hay diferencias, prevalece la versión en inglés.

# Plataformas

Esta página es para quienes instalan IRMind en Linux, macOS o Windows, también por SSH. Explica la compilación, la verificación de descargas, los llaveros y los terminales. Empieza por [primeros pasos](getting-started.md) para el flujo de un caso.

## Compilar desde el código

La compilación desde el código es la vía recomendada para una evaluación interna:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
```

CI prueba Ubuntu Linux, macOS arm64 y Windows x64 con el toolchain MSVC. SQLite se compila desde fuentes incluidas. Arrow y Parquet usan crates de Rust. TLS usa rustls con las raíces de certificados nativas, incluidas las CA corporativas instaladas; IRMind no enlaza OpenSSL del sistema. Esta opción de raíces nativas puede diferir de las comprobaciones de política de un verificador específico de cada plataforma.

Instala un compilador de C/C++ antes de compilar: GCC o Clang y `pkg-config` en Linux, Xcode Command Line Tools en macOS, o Visual Studio Build Tools con MSVC C++ en Windows. Una compilación release sin caché sigue compilando muchos crates de Rust y SQLite incluido. Reserva tiempo y disco adicionales; depende de la CPU, el compilador y la caché. Consulta las [mediciones](../development/benchmarks.md).

## Verificar una versión antes de instalar

Descarga el binario de tu sistema y `SHA256SUMS` desde la [versión en GitHub](https://github.com/ns2switch/irmind/releases). Comprueba el nombre exacto del binario en el archivo de hashes antes de ejecutarlo. La primera versión preliminar, v0.1.0, solo incluye hashes; las versiones posteriores añadirán firmas y procedencia. El hash comprueba los bytes frente a ese archivo, pero no la identidad del editor.

| Sistema | Comprobación |
| --- | --- |
| Linux | Ejecuta `sha256sum -c SHA256SUMS` en el directorio de descarga. |
| macOS | Ejecuta `shasum -a 256 -c SHA256SUMS` en ese directorio. |
| Windows PowerShell | Compara `(Get-FileHash .\irmind.exe -Algorithm SHA256).Hash.ToLowerInvariant()` con la línea de `irmind.exe` en `SHA256SUMS`. |

El repositorio incluye [install.sh](../../install.sh) e [install.ps1](../../install.ps1). Cuando una versión adjunte estos scripts, descárgalos y comprueba su hash contra `SHA256SUMS` **antes** de ejecutarlos. Detectan el sistema y verifican el hash del binario. Si `cosign` o `gh` están instalados, verifican también la firma y la procedencia; cualquier fallo impide instalar. Nunca solicitan permisos de administrador ni cambian `PATH`.

```sh
# Linux o macOS, después de comprobar install.sh con SHA256SUMS:
sh ./install.sh v0.1.1
```

```powershell
# Windows, después de comprobar install.ps1 con SHA256SUMS:
& .\install.ps1 -Version v0.1.1
```

Omite la versión para elegir la última publicada, incluida una preliminar. Un segundo argumento de POSIX o `-InstallDir` en PowerShell cambia el directorio del usuario. Por defecto se instala en `~/.local/bin` o `%LOCALAPPDATA%\IRMind\bin`. Si no está en `PATH`, el script indica cómo añadirlo manualmente.

CI también genera artefactos sin firma en tags de versión y ejecuciones nocturnas relevantes. Las PR y los merges a `main` no publican binarios. Apple no notariza los binarios y Windows no usa Authenticode; ambos sistemas pueden mostrar avisos incluso después de verificar la descarga.

## Linux

Usa un terminal compatible con xterm, como GNOME Terminal o Konsole. El backend `os` necesita Secret Service mediante D-Bus, que puede no estar disponible por SSH. Elige `file` explícitamente para una sesión sin entorno gráfico. Los archivos y directorios locales se restringen al usuario actual con permisos Unix `0600` y `0700`.

## macOS

Usa Terminal.app o iTerm2. `os` utiliza Keychain; `file` se puede elegir explícitamente por SSH. CI compila para Apple Silicon. Después de comprobar el checksum, Gatekeeper puede bloquear el binario descargado sin firma. Autoriza **solo ese binario** en Ajustes del Sistema → Privacidad y seguridad, o elimina únicamente su atributo de cuarentena con `xattr -d com.apple.quarantine ./irmind`. Nunca desactives Gatekeeper para todo el sistema.

## Windows

Usa Windows Terminal y el binario x64 MSVC. `os` utiliza Credential Manager; `file` está disponible si se selecciona explícitamente. IRMind comprueba que los archivos del caso y el almacén cifrado están restringidos al SID del usuario actual. SmartScreen o el antivirus corporativo pueden advertir sobre un binario sin firma. Comprueba el checksum y la procedencia y, si la política lo permite, solicita una excepción limitada al equipo de seguridad. No desactives la protección globalmente.

## Datos y terminal

Sin `--home`, los datos se guardan en el directorio estándar de datos locales de cada plataforma: XDG en Linux, Application Support en macOS y LocalAppData en Windows. Los nombres de evidencia son hashes en minúsculas; las rutas de auditoría y exportación son relativas y usan `/`. SQLite guarda la auditoría y el estado del caso; los artefactos Parquet firmados proporcionan las consultas derivadas del grafo.

La TUI usa la pantalla alternativa y sanea el texto externo antes de mostrarlo. Los tests automáticos comprueban secuencias de control y controles bidireccionales en los tres sistemas. La interacción visual aún requiere revisión manual en cada terminal antes de usarse en producción. Por SSH, solicita un terminal con `ssh -t`, elige `file` y escribe la passphrase en el campo enmascarado de la TUI. IRMind no cambia de backend en silencio. `verify-export` funciona sin desbloquear un llavero.
