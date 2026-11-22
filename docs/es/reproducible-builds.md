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

## Entradas de la compilación

Usa la toolchain de Rust fijada en [`rust-toolchain.toml`](../../rust-toolchain.toml)
en el tag, actualmente 1.95.0, además de Git y Python 3.10 o posterior. Usa la
revisión de imagen y las versiones indicadas en `BUILD-ENVIRONMENT.json`, entre
los [ficheros del tag de la release](https://github.com/ns2switch/irmind/releases).
El inventario recoge Rust y Cargo, el compilador y el enlazador nativos, Xcode
y la versión y número de compilación del SDK de macOS, además de la instalación
de Visual Studio, las herramientas MSVC y el SDK de Windows. Las etiquetas
versionadas fijan la familia de imagen. GitHub puede actualizarla dentro de
esa familia, así que consulta también la revisión registrada. En Windows, usa
el entorno de desarrollo x64 de Visual Studio correspondiente con Git Bash.

| Argumento de destino y sufijo de release | Runner nativo | Ejecutable principal |
| --- | --- | --- |
| `linux-x86_64` | Ubuntu 22.04 | ThinLTO, una unidad de generación de código, mold 2.42.1 |
| `linux-aarch64` | Ubuntu 24.04 Arm64 | ThinLTO, una unidad de generación de código, enlazador del sistema |
| `macos-aarch64` | `macos-26` en Apple Silicon | Enlazador nativo de Apple |
| `macos-x86_64` | `macos-15-intel` en Intel | Enlazador nativo de Apple |
| `windows-x86_64` | `windows-2025-vs2026` en x64 | ThinLTO, una unidad de generación de código, MSVC con `/Brepro` |

El [script de compilación](../../.github/scripts/build_release_binaries.py)
usa `--release --locked`, fija `CARGO_INCREMENTAL=0` y
`CARGO_PROFILE_RELEASE_STRIP=symbols` y selecciona el destino y las opciones
del enlazador. Ejecútalo con el entorno normal de Cargo y del compilador del
runner, sin ajustes locales de compilación. El worktree de Windows usa CRLF
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
del runner. Las rutas fijas deben estar libres al empezar. El script elimina
los directorios temporales que crea.

## Compilar y comparar con una release

Asigna a `tag` el tag exacto. Descarga el inventario y la lista de sumas y
verifica sus firmas con cosign 3.1.3 o posterior antes de elegir las herramientas.

```bash
tag='<TAG>'
gh release download "$tag" -R ns2switch/irmind \
  -p 'BUILD-ENVIRONMENT.json*' -p 'SHA256SUMS*' -D release-checksums
for file in BUILD-ENVIRONMENT.json SHA256SUMS; do
  cosign verify-blob "release-checksums/$file" \
    --bundle "release-checksums/$file.sigstore.json" \
    --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com || exit 1
done
```

Usa las versiones del inventario verificado. Desde un clon del repositorio
público, selecciona un destino de la tabla y un directorio de salida que aún
no exista. El comando ejecuta la misma compilación por pares que la CI.

```bash
destination=macos-aarch64
git fetch --tags origin
git checkout --detach "$tag"
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
