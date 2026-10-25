# Plataformas y distribución

IRMind usa el mismo formato de auditoría firmado en Linux, macOS arm64 y Windows x64. CI compila, comprueba y ejecuta los tests en `ubuntu-latest`, `macos-latest` (arm64) y `windows-latest`. La verificación cruzada lee exportaciones sintéticas de Linux en macOS y Windows, y las de Windows en Linux y macOS. La compilación desde el código es la vía recomendada para uso interno:

```sh
rustup toolchain install 1.95.0
cargo build --release --locked -p irmind
```

En Linux, la biblioteca DBus se compila desde la fuente empaquetada para Secret Service. SQLite y DuckDB también se compilan desde las versiones empaquetadas; las conexiones HTTPS usan rustls con las raíces de certificados del sistema, incluidas CA corporativas instaladas por el administrador. No se usa el backend TLS de OpenSSL del sistema.

## Artefactos de CI

Cada trabajo de plataforma publica `irmind` o `irmind.exe`, `LICENSE-MIT`, `LICENSE-APACHE`, `THIRD_PARTY_NOTICES.md` y un `SHA256SUMS` que cubre los cuatro archivos. Linux se ejecuta en cada push y PR; Windows en PR y main; macOS en cada PR, main, cada noche y tags. El check DCO se ejecuta primero en los PR. Descargue el artefacto correspondiente a su sistema desde un trabajo de CI confiable y compruebe el hash **antes de ejecutarlo**:

| Sistema | Comprobación |
| --- | --- |
| Linux | `sha256sum -c SHA256SUMS` |
| macOS | `shasum -a 256 -c SHA256SUMS` |
| Windows PowerShell | Compare `(Get-FileHash .\irmind.exe -Algorithm SHA256).Hash.ToLowerInvariant()` con el valor de `SHA256SUMS`. |

Los binarios aún no están firmados, notarizados ni llevan Authenticode. La decisión se revisa el 2027-04-24 o antes de una distribución externa.

### macOS

Después de comprobar el checksum, si Gatekeeper bloquea **ese** binario descargado, use la excepción puntual de *Ajustes del Sistema → Privacidad y seguridad → Abrir de todos modos* o quite su atributo de cuarentena con `xattr -d com.apple.quarantine ./irmind`. Nunca desactive Gatekeeper para el sistema completo. Consulte las [instrucciones de Apple](https://support.apple.com/en-us/102445).

### Windows

Ejecute el binario desde Windows Terminal. SmartScreen puede advertir sobre un ejecutable sin firma. Compruebe el checksum y la procedencia del artefacto; si la política corporativa lo permite, use la excepción puntual. Si SmartScreen o el antivirus empresarial lo bloquean, solicite revisión al equipo de seguridad. No desactive la protección global. Consulte la [guía de Microsoft sobre SmartScreen](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation).

## Datos y llavero

Sin `--home`, los datos se guardan en el directorio de datos local que devuelve `directories::ProjectDirs`: XDG en Linux, Application Support en macOS y LocalAppData en Windows. `--home` permite una ubicación explícita. Las claves Analyst y Agent se guardan en Secret Service, Keychain o Credential Manager. Si el llavero no está disponible, la firma falla cerrada y se muestra un error; `verify-export` solo necesita la clave pública incluida en el paquete. No habrá respaldo del llavero.

Los ficheros del almacén usan `0600` y los directorios `0700` en Unix. En Windows se restringe la DACL al usuario actual; un fallo al aplicar o comprobar la ACL impide continuar. Las rutas grabadas al ingerir son relativas y usan `/`, y los hashes de evidencia son hexadecimales minúsculos. Los nombres cortos de hash y caso evitan rutas profundas en el almacén de Windows. No se usa `memmap2`: las lecturas cierran el descriptor antes de reemplazar o borrar un archivo.

## Terminales

La TUI usa crossterm y pantalla alternativa. Terminales objetivo: Windows Terminal, Terminal.app e iTerm2 en macOS, y GNOME Terminal, Konsole y terminales compatibles con xterm en Linux. El guard elimina secuencias de control de los datos externos antes de mostrarlos; los tests automatizados cubren CSI, OSC, controles y bidi. La matriz de CI prueba el código y la sanitización en los tres sistemas; una revisión interactiva de cada terminal sigue siendo necesaria antes de declarar la experiencia visual validada.
