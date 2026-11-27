# Conservar la versión de IRMind que creó un caso

[English](../previous-versions.md)

El formato actual es caso 8 y exportación V12. Los casos de v0.8.0-alpha.1
usan el caso 7 y la exportación V11 y necesitan el binario de la alpha.
Para abrir, verificar, exportar o borrar un caso de 0.7.x, usa exactamente
el binario 0.7.x que lo creó. Homebrew puede retirar binarios anteriores
al actualizar. Si tienes un caso abierto, guarda antes una copia verificada
del binario y su auxiliar EVTX, además del directorio de datos y el llavero
compatibles.

## Descargar y verificar un tag concreto

Busca el tag productor en las [releases de GitHub](https://github.com/ns2switch/irmind/releases).
Descarga en un directorio nuevo los dos ejecutables para tu sistema, sus
bundles `.sigstore.json`, `SHA256SUMS` y `SHA256SUMS.sigstore.json`.

| Plataforma | Binario principal | Auxiliar EVTX |
| --- | --- | --- |
| Linux x86-64 | `irmind-linux-x86_64` | `irmind-evtx-linux-x86_64` |
| Linux arm64 | `irmind-linux-aarch64` | `irmind-evtx-linux-aarch64` |
| macOS Apple Silicon | `irmind-macos-aarch64` | `irmind-evtx-macos-aarch64` |
| macOS Intel | `irmind-macos-x86_64` | `irmind-evtx-macos-x86_64` |
| Windows x64 | `irmind-windows-x86_64.exe` | `irmind-evtx-windows-x86_64.exe` |

El [ejemplo con comandos para v0.7.4](../previous-versions.md#download-and-verify-a-specific-tag)
usa Linux x86-64. Sustituye el tag y los dos nombres por los de tu caso.
Comprueba los tres elementos antes de ejecutar el binario.

1. Con cosign 3.1.3 o posterior, ejecuta `cosign verify-blob` para
   `SHA256SUMS` y para ambos ejecutables. Usa el bundle de cada fichero,
   el emisor `https://token.actions.githubusercontent.com` y la identidad
   exacta `https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/<TAG>`.
2. Comprueba una única línea por nombre en el `SHA256SUMS` verificado.
   Usa `sha256sum -c -` en Linux, `shasum -a 256 -c -` en macOS o compara
   `Get-FileHash -Algorithm SHA256` en PowerShell con el hash de esa línea.
3. Para cada ejecutable, usa una versión actual de GitHub CLI.

   ```text
   gh attestation verify "<BINARIO>" -R "ns2switch/irmind" --signer-workflow ns2switch/irmind/.github/workflows/ci.yml --source-ref "refs/tags/<TAG>"
   ```

Si alguna comprobación falla, detente. Consulta la
[guía de Sigstore](https://docs.sigstore.dev/cosign/verifying/verify/) y el
[manual de attestations](https://cli.github.com/manual/gh_attestation_verify).

Conserva los ejecutables verificados en un directorio por versión, aparte
de la instalación habitual. Para usarlos, deja juntos `irmind` e
`irmind-evtx`, con `.exe` en Windows. En Linux y macOS, da permiso de
ejecución a las copias verificadas. Ejecuta el binario conservado por su
ruta con `--home` apuntando al directorio de datos compatible. Para
continuar la investigación en un caso nuevo, reingiere los originales
verificados.

## Borrar un caso de 0.7.x

Para una eliminación firmada de un caso no sellado, abre el directorio
de datos compatible con el binario 0.7.x que lo creó y ejecuta
[`/case delete`](cases.md#borrar-un-caso-no-sellado). El comando impide
borrar un caso sellado.

**El borrado manual es irreversible.** Cierra primero todos los procesos
de IRMind que usen ese directorio de datos. Si borras a mano el directorio
`parquet/<id-de-caso>`, pierdes los ficheros del caso y su entrada puede
seguir apareciendo en la base compartida. No queda lápida firmada ni un
caso recuperable. Si el directorio de datos antiguo estaba dedicado a los
casos que quieres descartar, puedes quitarlo entero para eliminar también
la base, las claves conservadas, la configuración y los ficheros de los
casos. Revisa antes qué contiene, incluidas las copias u originales que
necesites. En un directorio de datos compartido, usa el binario productor
para borrar con firma un caso individual no sellado.
