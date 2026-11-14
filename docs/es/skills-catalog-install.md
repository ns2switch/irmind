Traducción de docs/development/skills-catalog-install.md en el commit 3dca429ca1fa14cb16147a5cf1bdf37a93d282fa; si hay diferencias, prevalece la versión en inglés.

# Instalación explícita desde el catálogo comunitario de skills

Arquitectura aprobada; la descarga y verificación dentro de IRMind aún no están
implementadas. El catálogo vive en `ns2switch/irmind-skills`, separado del núcleo.
Las skills incluidas no se duplican allí.
[English](../development/skills-catalog-install.md) ·
[Instalación local](../development/skills-installation-contract.md) ·
[Recibos de caso](../development/skills-case-format-contract.md)

## Acción del analista y límites de red

`/skills install catalog:<nombre>` es una acción explícita del analista. Antes de
usar red se muestran repositorio, tag elegido y destinos. Confirmar permite solo
las descargas acotadas de esa release. El arranque, el descubrimiento de skills,
el modelo y las actualizaciones en segundo plano no consultan el catálogo.

Se congelan tag, identidad de release y digest del índice. Se descarga el índice
y su firma Ed25519 separada, se verifican con las claves públicas compiladas y
solo después se obtiene el paquete elegido por su hash. La vista previa muestra
origen exacto, nombre, versión, compromiso del paquete, versión mínima de IRMind,
fuentes/mapeos, cobertura, herramientas y contenido. Todo pasa por ContentGuard
y salida segura; la firma del publicador no convierte metodología en instrucciones
confiables.

Un nombre del núcleo se rechaza antes de admitir y bajo el bloqueo global.
El catálogo no sustituye silenciosamente una skill incluida. Se rechazan también
colisiones con comandos y otras identidades instaladas.

`/skills update` elige explícitamente qué revisar. Muestra diferencias de versión,
hashes, ficheros, contenido, herramientas, cobertura y requisitos. No hay aceptación
automática, consentimiento masivo ni downgrade silencioso. Cada sustitución se
admite con la transacción firmada habitual. Un fallo o cancelación conserva la
versión aprobada anterior. Desactivar también es una operación firmada.

La instalación local sigue disponible sin red. Un paquete descargado y verificado
a mano puede instalarse desde un directorio. Sin prueba verificable por IRMind su
origen sigue siendo analista/organización, no "catálogo verificado". El índice,
firma y paquete descargados bastan para verificar sin conexión; no hay fallback
a red al faltar un fichero.

## Estructura y compilador del catálogo

Una carpeta por skill contiene `SKILL.md` y recursos permitidos; su episodio
sintético y respuestas privadas se mantienen aparte del paquete instalado. Sin
scripts ejecutables ni plugins descargados. Licencia MIT OR Apache-2.0, guía de
contribución en inglés/español y plantilla. No se publica la plantilla como skill
ni se duplican nombres del núcleo.

La CI resuelve una vez la última release publicada no borrador de IRMind,
incluidas pre-releases mientras no haya estable, y registra tag y commit. El
validador de desarrollo se construye contra esa fuente y usa exactamente
`SkillPackageStore::read_candidate` y `SkillCompiler::compile`, no otro validador
aproximado. El episodio usa el mismo motor, guard, instalación firmada y modelo
scripted: confirma hallazgos como analista, verifica, sella y exporta. Las respuestas
esperadas se leen solo por el evaluador después del resultado final; no entran en
modelo, herramientas, evidencia ni paquete.

Cada contribución declara cobertura, fixtures, contratos y referencias ATT&CK
pertinentes. Las acciones se fijan por commit y las herramientas precompiladas
por versión/checksum. La validación de PR tiene permisos de lectura; publicación
ocurre en otro job de tags revisados.

## Índice e identidad de release

Índice JSON UTF-8 determinista, sin campos desconocidos ni duplicados. La cabecera
firmada vincula repositorio, tag y commit congelados, contador de secuencia e ID
de clave. Entradas ordenadas por nombre:

| Campo | Significado |
| --- | --- |
| `name`, `version` | Identidad exacta validada por el compilador. |
| `package_sha256` | Compromiso canónico lógico de IRMind, recalculado. |
| `asset`, `asset_sha256`, `asset_bytes` | Nombre de asset, SHA-256 ordinario y tamaño acotado. |
| `minimum_irmind_version` | Compatibilidad explícita con la versión productora/intérprete. |
| `target_schema`, `interpreter` | Esquema e intérprete soportados exactos. |
| `sources`, `mappings` | Módulos y versiones necesarios. |
| `coverage` | Completa, parcial o no disponible, con explicación acotada. |

Hash del asset y compromiso lógico se comprueban por separado. No se aceptan URLs
arbitrarias: solo assets del repositorio y tag congelados. Cada redirección se
revalida dentro del flujo GitHub permitido, sin reenviar credenciales. No se usa
información del caso ni credenciales ambientales o de nube. El catálogo público
no requiere guardar una credencial GitHub.

Límites iniciales: índice de 1 MiB/1.024 entradas, asset de 1 MiB y texto original
de paquete de 128 KiB; 16 recursos, 32 KiB por recurso, 8 KiB de frontmatter,
firma Ed25519 de 64 bytes y 30 segundos por petición. Los límites concretos se
importan del compilador y el índice no puede ampliarlos. También se acotan bytes
totales, redirecciones y pruebas retenidas. Staging privado en el directorio de
datos, comprobación de disco, cancelación y limpieza en error. Sin rutas absolutas,
traversal, symlinks, hard links, duplicados ni alias de plataforma.

## Confianza Ed25519 y rotación

El catálogo firma el índice canónico con una clave Ed25519 propia. IRMind usa su
código Ed25519 existente y una lista de como máximo ocho claves públicas compiladas.
El índice declara su ID; no proporciona otra raíz confiable. El contrato concreto
fijará derivación del ID, campos, preimagen con dominio separado y vectores.
Clave desconocida, retirada o no coincidente, firma incorrecta, índice alterado,
repositorio/tag erróneos o hashes de paquete inválidos rechazan la operación.
No hay alternativa de solo checksums, subproceso verificador ni dependencia nueva.

No se necesitan reloj, certificados, red, TUF ni refresco de raíces. Las firmas
del catálogo y del analista mantienen la metodología como UNTRUSTED y nunca en
system. Añadir o retirar una clave pública requiere una release revisada de IRMind.
Una clave comprometida se retira en la siguiente release y ese ejecutable deja de
aceptar sus índices. Los ejecutables antiguos conservan sus claves: la retirada
requiere actualizar IRMind, no una descarga automática. Se revalidan admisiones
activas; si falta confianza se desactivan con aviso, sin cambiar su origen en
silencio. Una firma antigua válida no prueba frescura; se muestra la release
seleccionada y no se hace downgrade silencioso.

La clave privada real solo existe como secreto del environment protegido de
release del catálogo, disponible para el job publicador. No va a Git, assets,
paquetes, argumentos ni logs. No se expone a PRs ni a `pull_request_target`, ni
se firman artefactos de PR sin revisión. El maintainer debe aprobar despliegues
de tags y configurar environment/clave tras aprobar el contrato. Este documento
no aprovisiona ninguna clave. Las identidades de los vectores son sintéticas,
no claves de producción.

## Verificación externa de releases

Las releases conservan además firmas/bundles Sigstore del índice, checksums y
paquetes, y procedencia de GitHub. El README del catálogo documenta cosign y
`gh attestation verify` para la comprobación externa. IRMind no necesita esas
herramientas ni sus raíces para admitir un índice Ed25519.

Para `<TAG>`, cosign exige emisor exacto
`https://token.actions.githubusercontent.com` e identidad
`https://github.com/ns2switch/irmind-skills/.github/workflows/release.yml@refs/tags/<TAG>`.
La procedencia vincula repositorio, commit y workflow. Solo el publicador tiene
OIDC, attestations y escritura de release; la validación mantiene `contents: read`.
El ensayo dispatch firma artefactos de prueba sin publicar una release.

## Puertos y admisión firmada

- `SkillCatalogSource`: obtención acotada/cancelable de release e índice congelados
  y assets nombrados, solo desde la instalación solicitada por el analista.
- `CatalogIndexVerifier`: verificación pura acotada contra claves compiladas,
  repositorio/tag esperados; devuelve recibo tipado, sin E/S, reloj ni secretos.

El contrato también fijará retención privada inmutable de la prueba del índice
completo para recuperación, caso y exportación. La entrada seleccionada por sí
sola no permite verificar una firma del índice completo.

Se reutilizan compilador y almacén actuales. El origen `catalog` vinculará
release/tag/commit, digests de índice/asset, ID de clave, política de verificación
y compromiso lógico. Tras inspeccionar, el analista firma la admisión global.
Se conservan versiones y recibos inmutables. El contrato de bytes y su efecto en
casos y export necesita revisión antes de implementar; ninguna firma amplía
herramientas, alcance, política, aprobaciones ni presupuestos.

## Pruebas y siguiente paso

Cubrir firmas válidas/inválidas, claves desconocidas/retiradas, repositorio/tag/
secuencia erróneos, índice o entrada modificados, hashes incorrectos, prueba
completa ausente, nombres del núcleo, paquetes malformados/grandes, mapeos ausentes,
vista saneada, cancelación, fallos de firma/publicación, reinicio, diferencias y
verificación offline sin red. Fuentes falsas prueban que el arranque, modelo o
cancelación no hacen peticiones. Una firma válida no salva contenido malicioso
de los controles de declaración, alcance y aprobación.

Primero el contrato concreto de índice, origen y caso/export con vectores, para
revisión; después la implementación y creación del repositorio. No se crea el
repositorio antes de aprobar ese contrato. Los subagentes son otra función.
