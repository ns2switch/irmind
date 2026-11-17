Traducción de CODE_SIGNING.md en el commit 4346ab637e1d0e0cfb3a6a36382bfad1a46ac31e; si hay diferencias, prevalece la versión en inglés.

[English version](CODE_SIGNING.md)

# Política de firma de código

## Atribución

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/)

Esta atribución se aplica a la firma Authenticode de los binarios propios de
Windows: `irmind.exe` y su auxiliar EVTX aislado, `irmind-evtx.exe`. El mantenedor
ha presentado la solicitud a la Foundation; la aprobación y la integración están
pendientes. **SignPath no está activo y las versiones Windows actuales no llevan
firmas Authenticode de SignPath.** Linux y macOS se firman con Sigstore sin claves
permanentes. Developer ID Application, hardened runtime y la notarización de Apple
para macOS están preparados, pero desactivados hasta su configuración y activación.

## Roles del equipo

- Committers and reviewers: Anibal Cañada (@ns2switch)
- Approvers: Anibal Cañada (@ns2switch)

La cuenta del proyecto es [@ns2switch](https://github.com/ns2switch). Cada solicitud
de firma requiere la aprobación manual del aprobador para un tag publicado.
GitHub Actions compila el binario desde el código público de ese tag exacto;
el workflow no puede aprobar su propia solicitud. El equipo debe usar
multifactor en GitHub y SignPath.

Las contribuciones llevan DCO y pasan revisión y CI. Aprobar una release no elude
las pruebas de política, custodia, TLS, aislamiento ni límites. Los aprobadores
adicionales deben identificarse en esta política antes de activar la integración.

## Política de privacidad

IRMind no incluye telemetría. Este programa no transferirá información a otros
sistemas en red salvo petición específica del usuario o de la persona que lo
instale u opere.

Cuando el analista configura y aprueba expresamente un proveedor de modelos
(DeepSeek, Anthropic, OpenAI, OpenRouter u otro compatible) o un conector (Splunk,
Elastic, Chronicle, VirusTotal, MISP o servicios de nube), los datos enviados
quedan sujetos a la política de privacidad del proveedor. Revisa sus condiciones
antes de enviar datos. Configurarlo no elude la política, el alcance del caso,
el techo de la organización ni las aprobaciones necesarias. Las skills y los
subagentes no amplían esos permisos.

Las descargas y actualizaciones explícitas del catálogo también son peticiones de
red del usuario; las skills no se descargan ni actualizan automáticamente.
La demo no contacta con ningún servicio: usa un modelo guionizado, consultas
externas simuladas, datos sintéticos y claves temporales.

## Qué se firma y cómo se compila

Solo se firman la CLI propia y el auxiliar EVTX. Los assets Windows llevan sufijos
de plataforma; los archivos instalados son `irmind.exe` e `irmind-evtx.exe`.
La futura configuración SignPath debe limitar la firma a esos ejecutables y exigir
el nombre de producto IRMind y la misma versión de release en ambos.

El workflow de GitHub Actions, con acciones fijadas por commit, compila tags
revisados con dependencias bloqueadas. Solo jobs de tags podrán solicitar
credenciales nativas; las PR y los ensayos de ramas no podrán. SignPath usará el
environment protegido `release`, con aprobación manual de cada firma. Una vez
activado, un rechazo, timeout o resultado inválido bloqueará la publicación, sin
alternativa silenciosa sin firma nativa.

La firma nativa termina antes de generar checksums, Sigstore y procedencia para
vincular los bytes finales descargables. Sigstore firma cada binario y
`SHA256SUMS`; esta lista vincula instaladores, licencias, SBOM e inventarios de
unsafe. GitHub Actions atesta la procedencia de binarios y SBOM. No se guarda una
clave privada persistente de Sigstore en el repositorio.

## Verificar una release

Antes de ejecutar una descarga, sigue la [guía de plataformas](docs/es/platforms.md#verificar-una-versión-antes-de-instalar):
comprueba el checksum, la identidad exacta de repositorio/workflow/tag y el emisor
del bundle Sigstore y la procedencia de GitHub. Verifica el auxiliar por separado.

Después de activar SignPath, comprueba además ambos ejecutables Windows con
`Get-AuthenticodeSignature`: `Status` debe ser `Valid` y el firmante debe coincidir
con el certificado de la Foundation documentado para esa release. Esta política
no añade Authenticode retroactivamente a las versiones existentes.

La firma acredita origen y proceso de compilación, no corrección forense ni
aptitud para incidentes reales. IRMind es pre-1.0 y se evalúa principalmente con
datos sintéticos. Véanse [SECURITY.md](SECURITY.md) y la
[guía de firma nativa](docs/es/native-signing.md).
