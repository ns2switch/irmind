[English](../reproducible-builds.md)

# Compilaciones reproducibles

Antes de firmar una release, la [matriz de compilación](../../.github/workflows/release-binaries.yml)
compila `irmind` e `irmind-evtx` desde dos copias limpias del mismo commit
en rutas distintas. Compara el SHA-256 completo de cada ejecutable y bloquea
la publicación si hay diferencias. La comprobación se aplica a los tags cuyo
workflow usa esta matriz. Cubre los ejecutables antes de la firma nativa de la
plataforma. Los bundles de Sigstore y las attestations se verifican por separado.

## Entradas de la compilación

Usa la toolchain de Rust fijada en [`rust-toolchain.toml`](../../rust-toolchain.toml)
en el tag, actualmente 1.95.0, además de Git y Python 3.10 o posterior. Usa la
misma imagen de runner y las mismas versiones del compilador y del enlazador
que constan en el workflow del tag. En macOS, usa las versiones de Xcode y del
SDK de macOS indicadas. En Windows, usa las herramientas de C++ de Visual Studio
y el SDK de Windows indicados, y ejecuta los comandos en Git Bash.

| Argumento de destino y sufijo de release | Runner nativo | Ejecutable principal |
| --- | --- | --- |
| `linux-x86_64` | Ubuntu 22.04 | ThinLTO, una unidad de generación de código, mold 2.42.1 |
| `linux-aarch64` | Ubuntu 24.04 Arm64 | ThinLTO, una unidad de generación de código, enlazador del sistema |
| `macos-aarch64` | `macos-latest` en Apple Silicon | Enlazador nativo de Apple |
| `macos-x86_64` | `macos-15-intel` en Intel | Enlazador nativo de Apple |
| `windows-x86_64` | `windows-latest` en x64 | ThinLTO, una unidad de generación de código, MSVC con `/Brepro` |

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

Desde un clon del repositorio público, asigna a `tag` el tag de la release y
a `destination` el destino de tu sistema. Elige un directorio de salida que
aún no exista. El comando siguiente ejecuta la misma comprobación por pares que la CI.

```bash
tag='<TAG>'
destination=macos-aarch64
git fetch --tags origin
git checkout --detach "$tag"
python .github/scripts/build_release_binaries.py "$destination" reproduced --verify

gh release download "$tag" -R ns2switch/irmind \
  -p SHA256SUMS -p SHA256SUMS.sigstore.json -D release-checksums
cosign verify-blob release-checksums/SHA256SUMS \
  --bundle release-checksums/SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Usa cosign 3.1.3 o posterior y continúa cuando la verificación sea correcta.
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
