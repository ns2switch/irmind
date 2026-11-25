[English](../reproducible-builds.md)

# Compilaciones reproducibles

Antes de firmar una release, la [matriz de compilación](../../.github/workflows/release-binaries.yml)
compila `irmind` e `irmind-evtx` desde dos copias limpias del mismo commit
en rutas distintas. Compara el SHA-256 completo de cada ejecutable y bloquea
la publicación si hay diferencias. La comprobación se aplica a los tags cuyo
workflow usa esta matriz. Cubre los ejecutables antes de la firma nativa de la
plataforma. Los bundles de Sigstore y las attestations se verifican por separado.

## Primeras releases reproducibles

| Ejecutable | Plataformas | Reproducible desde |
| --- | --- | --- |
| `irmind` | Linux x86_64 y Arm64, Windows x64 | v0.6.1 |
| `irmind-evtx` | Los cinco destinos de release | v0.6.1 |
| `irmind` | macOS Intel y Apple Silicon | v0.6.2 |

En v0.6.1, el ejecutable principal de macOS usó el workspace, el directorio de
Cargo y el directorio de compilación del runner. El principal de macOS usa
las rutas fijas desde v0.6.2. Para v0.6.1, consulta el
[workflow de la release](https://github.com/ns2switch/irmind/blob/v0.6.1/.github/workflows/ci.yml)
y su [registro de compilación](https://github.com/ns2switch/irmind/actions/runs/45056933393).
El inventario firmado y el comando de compilación por pares se incorporan en
v0.6.2.

## Ensayar la publicación antes de crear el tag

En GitHub Actions, abre **Rust CI**, selecciona **Run workflow** y elige
la rama candidata. Activa `release_dry_run`.

Antes de crear el tag, comprueba que el job `release` terminó correctamente
sobre el mismo árbol Git que se etiquetará. El job descarga los cinco paquetes
de distribución y el manifiesto de mapeos nativos, prepara los ficheros,
genera los SBOM y las attestations, y firma y verifica los paquetes con
Sigstore. El artefacto `signed-release-dry-run` contiene el resultado
verificado. Si cambia el árbol, repite el ensayo.
`release_binary_reproducibility` comprueba la reproducibilidad de los
binarios y los casos portables de Sigma. No ejecuta el empaquetado final.

| Paso o job omitido en el ensayo completo | Motivo |
| --- | --- |
| Crear o actualizar la release de GitHub y añadir su política de firma | Estos pasos escriben en la release pública y requieren un push del tag. |
| `native_macos` | La firma Developer ID está desactivada. Su activación requiere un despliegue protegido desde un tag y las credenciales de Apple. |
| `verify_install_linux`, `verify_install_macos`, `verify_install_windows` | Usan la URL pública de descarga y la identidad de firma del tag. El ensayo ejecuta las pruebas de instaladores sin conexión en la matriz y prueba los ficheros firmados de prueba con `rehearse_install_windows`. |
| `update_homebrew` | El tap usa una release publicada y necesita la aprobación del entorno protegido `release`. |
| `release_profile` y sus pruebas de rendimiento y reproducibilidad | Son experimentos manuales separados. El ensayo sí comprueba la reproducibilidad en los cinco destinos. |

## Entradas de la compilación

Usa un equipo o una máquina virtual con la arquitectura del destino, Git y
Python 3.10 o posterior. Consulta las versiones en el fichero verificado
`BUILD-ENVIRONMENT.json` de los [ficheros de la release](https://github.com/ns2switch/irmind/releases).
Cada entrada de `targets` registra las herramientas usadas para ese destino.

GitHub actualiza periódicamente las imágenes de sus runners, incluidas las
etiquetas versionadas, y deja de ofrecer las revisiones retiradas para
ejecutar jobs. Los campos `image_os` e `image_version` ayudan a localizar
el inventario histórico de software. Para reproducir un binario antiguo,
instala las versiones registradas en tu equipo o máquina virtual.
[Mantenimiento de las imágenes de GitHub](https://github.com/actions/runner-images#software-and-image-support)

| Argumento de destino y sufijo de release | Runner de release | Ejecutable principal |
| --- | --- | --- |
| `linux-x86_64` | Ubuntu 22.04 | ThinLTO, una unidad de generación de código, mold 2.42.1 |
| `linux-aarch64` | Ubuntu 24.04 Arm64 | ThinLTO, una unidad de generación de código, enlazador del sistema |
| `macos-aarch64` | `macos-26` en Apple Silicon | Enlazador nativo de Apple |
| `macos-x86_64` | `macos-15-intel` en Intel | Enlazador nativo de Apple |
| `windows-x86_64` | `windows-2025-vs2026` en x64 | ThinLTO, una unidad de generación de código, MSVC con `/Brepro` |

El [script de compilación](../../.github/scripts/build_release_binaries.py)
usa `--release --locked`, fija `CARGO_INCREMENTAL=0` y
`CARGO_PROFILE_RELEASE_STRIP=symbols` y selecciona el destino y las opciones
del enlazador. Ejecútalo desde la sesión donde seleccionaste las herramientas
correspondientes, con los ajustes de compilación del tag. El worktree de Windows usa CRLF
en archivos como `Cargo.lock` que se rigen por la conversión automática de
texto de Git. Sus bytes son parte de la identidad de los mapeos nativos actuales.

Para el ejecutable principal de macOS, el script prepara el árbol del commit
en `/private/tmp/irmind-macos-release-v1/source`, fija
`CARGO_HOME=/private/tmp/irmind-macos-release-v1/cargo-home` y
`CARGO_TARGET_DIR=/private/tmp/irmind-macos-release-v1/target`, y remapea los
tres prefijos de Rust a `/canonical/workspace`, `/canonical/cargo_home` y
`/canonical/target`. Las rutas físicas fijas también estabilizan el UUID de
compilación del enlazador de Apple.

EVTX usa su propio lockfile y perfil de Cargo. El árbol del commit y la salida
se preparan en los subdirectorios `source` y `target` de
`/tmp/irmind-evtx-release-v1` en Linux, `/private/tmp/irmind-evtx-release-v1`
en macOS y `C:\irmind-evtx-release-v1` en Windows. Usa el directorio de Cargo
de la sesión de compilación. Las rutas fijas deben estar libres al empezar. El script elimina
los directorios temporales que crea.

## Compilar y comparar con una release

Desde un clon del repositorio público, asigna a `tag` el tag exacto. Verifica
el inventario y la lista de sumas con cosign 3.1.3 o posterior antes de
elegir las herramientas.

```bash
tag='<TAG>'
git fetch --tags origin
git checkout --detach "$tag"
gh release download "$tag" -R ns2switch/irmind \
  -p 'BUILD-ENVIRONMENT.json*' -p 'SHA256SUMS*' -D release-checksums
for file in BUILD-ENVIRONMENT.json SHA256SUMS; do
  cosign verify-blob "release-checksums/$file" \
    --bundle "release-checksums/$file.sigstore.json" \
    --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com || exit 1
done
```

Si la release publica `NATIVE-MAPPING-INPUTS.json`, descárgalo junto con
su bundle de Sigstore y los dos ficheros anteriores. Verifícalo con la misma
identidad del certificado de la release y comprueba su entrada en
`SHA256SUMS` firmado. Usa Python 3.11 o posterior y añade
`--mapping-inputs release-checksums/NATIVE-MAPPING-INPUTS.json` al comando
de compilación de abajo. El workflow reúne las observaciones de los cinco
destinos de release. El script vuelve a comprobar la observación del destino
elegido antes de aceptar el binario reconstruido.

### Instalar las herramientas nativas

Elige en `targets` la entrada del binario que quieres reproducir. Comprueba
las versiones en la sesión donde vas a compilar.

**Linux.** Usa la versión de Ubuntu y la arquitectura de la tabla. Instala el
compilador y las bibliotecas de desarrollo desde la instantánea
correspondiente del archivo de Ubuntu. Usa la versión registrada del
compilador y la lista de software enlazada desde el log del workflow de
release. En Arm64, instala la versión correspondiente de GNU Binutils y
comprueba qué enlazador selecciona el compilador. En x86_64, instala la
versión registrada de mold y pon su directorio `bin` en `PATH`. Compara
`cc --version` y, según el destino, la versión del enlazador indicado por
`cc -print-prog-name=ld` en Arm64 o `mold --version` en x86_64 con el
inventario. [Instantáneas de Ubuntu](https://snapshot.ubuntu.com/) ·
[Releases de mold](https://github.com/rui314/mold/releases)

**macOS.** Descarga desde Apple Developer Downloads la versión y el número de
compilación de Xcode indicados en `native.xcode`. Usa una versión de macOS
compatible con ese Xcode en la arquitectura del destino. Instala la
aplicación y usa el SDK de macOS que incluye. Fija `DEVELOPER_DIR` en la
sesión de compilación y compara el build de Xcode, la versión y el build
del SDK, el compilador y el enlazador con los campos de `native`.
[Descargas de Apple](https://developer.apple.com/download/all/?q=Xcode) ·
[Selección de herramientas de Xcode](https://developer.apple.com/documentation/xcode/configuring-command-line-tools-settings)

```bash
export DEVELOPER_DIR='/Applications/<aplicación Xcode>/Contents/Developer'
unset SDKROOT
xcodebuild -version
xcodebuild -version -sdk macosx
xcrun clang --version
xcrun ld -v
```

**Windows.** Usa el instalador de versión fija de Build Tools para el build
de `native.visual_studio`. En Visual Studio Installer, instala **Desarrollo
para el escritorio con C++**, con las **herramientas de compilación de
C++ MSVC para x64/x86** y el **SDK de Windows** registrados. Usa
**Componentes individuales** para elegir las versiones indicadas por
`native.msvc_toolset` y `native.windows_sdk`. Abre una sesión nueva del
Símbolo del sistema y sustituye los marcadores por la ruta de esa
instalación y las versiones registradas.
[Historial de Visual Studio](https://learn.microsoft.com/en-us/visualstudio/releases/2026/release-history) ·
[Componentes de Build Tools](https://learn.microsoft.com/en-us/visualstudio/install/workload-component-id-vs-build-tools?view=vs-2026) ·
[Selección de herramientas y SDK](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-140)

```bat
call "<ruta de Visual Studio>\VC\Auxiliary\Build\vcvarsall.bat" x64 <windows_sdk> -vcvars_ver=<msvc_toolset>
echo %VCToolsVersion%
echo %WindowsSDKVersion%
where.exe cl.exe
where.exe link.exe
```

Compara las versiones de los ficheros `cl.exe` y `link.exe` seleccionados
en **Propiedades > Detalles** con `native.compiler` y `native.linker`. Abre
Git Bash con `"<ruta de Git for Windows>\bin\bash.exe"` desde ese Símbolo
del sistema para que herede el entorno seleccionado.

En Git Bash, pon primero en `PATH` las herramientas de MSVC seleccionadas y
comprueba las rutas de ambos ejecutables.

```bash
msvc_bin="$(cygpath -u "$VCToolsInstallDir")/bin/Hostx64/x64"
export PATH="$msvc_bin:$PATH"
command -v cl.exe
command -v link.exe
```

### Instalar la toolchain exacta de Rust y recompilar

En la sesión de compilación, combina las líneas `release` y `host` del
campo `rustc` del destino para formar el nombre de la toolchain de rustup.
Por ejemplo, `1.95.0-aarch64-apple-darwin` combina la versión `1.95.0` con
el host `aarch64-apple-darwin`. Comprueba que la versión coincide con
[`rust-toolchain.toml`](../../rust-toolchain.toml) en el tag. Compara la salida
de `rustc -vV` y `cargo -vV` con el inventario, incluidos los hashes de commit.
[Instalación de rustup](https://rust-lang.github.io/rustup/installation/) ·
[Selección de la toolchain por sesión](https://rust-lang.github.io/rustup/overrides.html)

```bash
toolchain='<release>-<host>'
rustup toolchain install "$toolchain"
export RUSTUP_TOOLCHAIN="$toolchain"
rustc -vV
cargo -vV
```

Selecciona el destino de la tabla y un directorio de salida nuevo. El comando
ejecuta la compilación por pares de la CI.

```bash
destination=macos-aarch64
python .github/scripts/build_release_binaries.py "$destination" reproduced --verify
```

Compara los dos ejecutables locales con los nombres publicados en la release:

```bash
python - "$destination" <<'PY'
import hashlib
from pathlib import Path
import sys

destination = sys.argv[1]
extension = ".exe" if destination.startswith("windows-") else ""
lines = Path("release-checksums/SHA256SUMS").read_text(encoding="ascii").splitlines()
for name in ("irmind", "irmind-evtx"):
    asset = f"{name}-{destination}{extension}"
    expected = [fields[0] for line in lines
                if len(fields := line.split()) == 2 and fields[1] == asset]
    digest = hashlib.sha256((Path("reproduced") / (name + extension)).read_bytes()).hexdigest()
    if expected != [digest]:
        sys.exit(f"{asset}: SHA-256 distinto o entrada ausente o duplicada")
    print(f"{asset}: {digest}")
PY
```

Si se activa la firma Developer ID de un tag, los binarios de macOS descargables
cambian después de esta comprobación. Usa la
[guía de plataformas](platforms.md) para verificar sus firmas y su procedencia.
