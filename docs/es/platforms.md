Traducción de docs/platforms.md en el commit e31fd5cc947308542888df4a52164d8892c56b93; si hay diferencias, prevalece la versión en inglés.

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

Descarga el binario de tu sistema y `SHA256SUMS` desde la [versión en GitHub](https://github.com/ns2switch/irmind/releases). Comprueba el nombre exacto del binario en el archivo de hashes antes de ejecutarlo. La primera versión preliminar, v0.1.0, solo incluye hashes. Desde v0.1.1 hay bundles Sigstore y procedencia de GitHub. Un hash comprueba los bytes frente a un archivo, pero no la identidad del editor.

| Sistema | Comprobación |
| --- | --- |
| Linux | Comprueba la línea del binario exacto con `sha256sum -c -`. |
| macOS | Comprueba la línea del binario exacto con `shasum -a 256 -c -`. |
| Windows PowerShell | Compara `Get-FileHash` con la única línea del binario exacto. |

El archivo de hashes enumera todos los assets; comprobar `SHA256SUMS` completo exige descargarlos todos. Si solo descargaste un binario, selecciona su línea y exige exactamente una coincidencia. En Linux o macOS:

```sh
binary=irmind-linux-x86_64 # sustituye por el nombre descargado
line=$(awk -v name="$binary" '$2 == name { print }' SHA256SUMS)
test -n "$line" && test "$(printf '%s\n' "$line" | wc -l)" -eq 1 || exit 1
printf '%s\n' "$line" | sha256sum -c - # usa shasum -a 256 -c - en macOS
```

En Windows, compara el resultado en minúsculas de `Get-FileHash` con el hash de la única línea de `SHA256SUMS` para `irmind-windows-x86_64.exe`.

Para v0.1.1 y posteriores, descarga además los bundles `.sigstore.json` del binario y de `SHA256SUMS`. Usa cosign **3.1.3 o posterior**: las versiones v3 anteriores sufren una [evasión de la comprobación de identidad con bundles antiguos](https://github.com/sigstore/cosign/security/advisories/GHSA-fx35-mq7g-6g98). Los instaladores rechazan esas versiones. Verifica ambos archivos con la identidad y el emisor exactos, sustituyendo `<TAG>` y `<BINARY>` por la versión y el nombre descargado:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/<TAG>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-blob "<BINARY>" --bundle "<BINARY>.sigstore.json" \
  --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/<TAG>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "<BINARY>" -R ns2switch/irmind
```

En Windows PowerShell, usa los mismos comandos de `cosign verify-blob` y `gh attestation verify` con rutas de Windows. La identidad del certificado debe corresponder al **tag que querías instalar**; comprobar solo que existe una firma no basta. La atestación vincula el hash del binario con el workflow de este repositorio. Consulta las guías de [Sigstore](https://docs.sigstore.dev/cosign/verifying/verify/) y [GitHub](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

El repositorio incluye [install.sh](../../install.sh) e [install.ps1](../../install.ps1). Descarga el script y `SHA256SUMS`. Primero verifica el bundle Sigstore de `SHA256SUMS` contra el tag y la identidad exacta del workflow con el comando anterior; después comprueba **la línea exacta del hash del script** antes de ejecutarlo. En Linux o macOS usa `binary=install.sh` en el ejemplo anterior. En Windows compara `Get-FileHash .\install.ps1 -Algorithm SHA256` con su única línea en `SHA256SUMS`. El instalador detecta el sistema y verifica el hash del binario; si están disponibles, `cosign` y una versión actual de `gh` comprueban la firma y la procedencia. Cualquier fallo impide instalar. Nunca solicita permisos de administrador ni cambia `PATH`.

```sh
# Linux o macOS, después de comprobar install.sh con SHA256SUMS:
sh ./install.sh v0.1.1
```

```powershell
# Windows, después de comprobar install.ps1 con SHA256SUMS:
& .\install.ps1 -Version v0.1.1
```

Omite la versión para elegir la última publicada, incluida una preliminar. Un segundo argumento de POSIX o `-InstallDir` en PowerShell cambia el directorio del usuario. Por defecto se instala en `~/.local/bin` o `%LOCALAPPDATA%\IRMind\bin`. Si no está en `PATH`, el script indica cómo añadirlo manualmente.

CI también genera artefactos de prueba en ejecuciones nocturnas relevantes; no son versiones publicadas. Las PR y los merges a `main` no publican binarios. Apple no notariza los binarios y Windows no usa Authenticode; ambos sistemas pueden mostrar avisos incluso después de verificar la descarga.

## Linux

Usa un terminal compatible con xterm, como GNOME Terminal o Konsole. El backend `os` necesita Secret Service mediante D-Bus, que puede no estar disponible por SSH. Elige `file` explícitamente para una sesión sin entorno gráfico. Los archivos y directorios locales se restringen al usuario actual con permisos Unix `0600` y `0700`.

## macOS

Usa Terminal.app o iTerm2. `os` utiliza Keychain; `file` se puede elegir explícitamente por SSH. CI compila para Apple Silicon. Después de verificar la versión, Gatekeeper puede bloquear un binario descargado sin firma de código de Apple. Autoriza **solo ese binario** en Ajustes del Sistema → Privacidad y seguridad, o elimina únicamente su atributo de cuarentena con `xattr -d com.apple.quarantine ./irmind`. Nunca desactives Gatekeeper para todo el sistema.

## Windows

Usa Windows Terminal y el binario x64 MSVC. `os` utiliza Credential Manager; `file` está disponible si se selecciona explícitamente. IRMind comprueba que los archivos del caso y el almacén cifrado están restringidos al SID del usuario actual. SmartScreen o el antivirus corporativo pueden advertir sobre un binario sin Authenticode. Comprueba el checksum, la identidad Sigstore y la procedencia y, si la política lo permite, solicita una excepción limitada al equipo de seguridad. No desactives la protección globalmente.

## Datos y terminal

Sin `--home`, los datos se guardan en el directorio estándar de datos locales de cada plataforma: XDG en Linux, Application Support en macOS y LocalAppData en Windows. Los nombres de evidencia son hashes en minúsculas; las rutas de auditoría y exportación son relativas y usan `/`. SQLite guarda la auditoría y el estado del caso; los artefactos Parquet firmados proporcionan las consultas derivadas del grafo.

La TUI usa la pantalla alternativa y sanea el texto externo antes de mostrarlo. Los tests automáticos comprueban secuencias de control y controles bidireccionales en los tres sistemas. La interacción visual aún requiere revisión manual en cada terminal antes de usarse en producción. Por SSH, solicita un terminal con `ssh -t`, elige `file` y escribe la passphrase en el campo enmascarado de la TUI. IRMind no cambia de backend en silencio. `verify-export` funciona sin desbloquear un llavero.
