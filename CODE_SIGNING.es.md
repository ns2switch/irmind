Traducción de CODE_SIGNING.md en el commit df9a8bff2dfb803a6ce692b9ad5713f540b45057; si hay diferencias, prevalece la versión en inglés.

[English version](CODE_SIGNING.md)

# Política de firma de código

## Estado actual

Los binarios de Linux, macOS y Windows, incluido el auxiliar EVTX aislado, tienen
firmas Sigstore sin claves permanentes y checksums SHA-256. GitHub Actions aporta
atestaciones de procedencia y SBOM del programa y del auxiliar. La lista firmada
`SHA256SUMS` autentica además instaladores, licencias e inventarios de auditoría.

**Los binarios de Windows no tienen firma Authenticode actualmente.** Una descarga
desde el navegador puede mostrar un aviso de SmartScreen o un editor desconocido.
Sigstore no aporta reputación de Windows ni anula sus controles. Developer ID
Application, hardened runtime y notarización de Apple están preparados pero
desactivados; solo se aplicarán tras la activación explícita del mantenedor.

## Roles del equipo

- Committers and reviewers: Anibal Cañada (@ns2switch)
- Approvers: Anibal Cañada (@ns2switch)

La cuenta del proyecto es [@ns2switch](https://github.com/ns2switch). El mantenedor
aprueba los tags de release. GitHub Actions compila el programa y el auxiliar
desde el código público de ese tag exacto, con dependencias bloqueadas y acciones
fijadas por commit. Las contribuciones pasan DCO, revisión y CI. El equipo debe
usar autenticación multifactor en GitHub.

La aprobación no elude las pruebas de política, custodia, TLS, aislamiento ni
límites. Una futura integración de firma nativa exige revisión separada,
aprobadores identificados y credenciales protegidas solo para tags antes de activarse.

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

Cada release actual firma el programa y el auxiliar EVTX en todas las plataformas
publicadas mediante OIDC de GitHub Actions y Sigstore. Los ejecutables instalados
en Windows son `irmind.exe` e `irmind-evtx.exe`; los assets llevan sufijos de
plataforma. GitHub Actions atesta la procedencia de binarios y SBOM. No se guarda
una clave privada persistente de Sigstore en el repositorio.

Si se activa firma nativa, terminará antes de generar checksums, Sigstore y
procedencia para vincular los bytes finales. La integración deberá bloquear la
publicación ante rechazo, timeout o resultado inválido, sin alternativa sin firma
cuando ya se exija. La firma nativa Windows es una opción futura, no una función
actual de las releases.

## Verificar e instalar una release

Antes de ejecutar una descarga, sigue la [guía de plataformas](docs/es/platforms.md#verificar-una-versión-antes-de-instalar):
comprueba hash, identidad exacta de repositorio/workflow/tag y emisor del bundle
Sigstore, y procedencia de GitHub. Verifica el auxiliar por separado.

En Windows verifica `install.ps1` con la lista autenticada `SHA256SUMS` y ejecútalo
desde PowerShell indicando la versión exacta:

```powershell
./install.ps1 -Version v0.5.4
```

Si dispone de cosign y GitHub CLI actuales, el instalador comprueba firmas
Sigstore, procedencia y hashes antes de instalar. Instala ambos ejecutables para
el usuario actual, sin administrador ni cambios silenciosos del PATH. Si faltan
esas herramientas, explica las comprobaciones manuales adicionales. Sigue la
política de tu organización si Windows bloquea la descarga; no desactives
SmartScreen ni otras protecciones globalmente.

La firma acredita origen y compilación, no corrección forense ni aptitud para
incidentes reales. IRMind sigue siendo software pre-1.0 para evaluación. Véanse
[SECURITY.md](SECURITY.md), el [registro de validación](docs/es/manual-validation.md#registro-de-resultados)
y la [guía de firma nativa](docs/es/native-signing.md).
