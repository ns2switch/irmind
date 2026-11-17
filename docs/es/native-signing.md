Traducción de docs/development/native-signing.md en el commit 050c01156cc3c45f5229306b88051eb22ed68348; si hay diferencias, prevalece la versión en inglés.

# Preparar la firma nativa

La firma macOS está preparada pero **desactivada**, sin prueba con certificado de
producción. Las releases actuales tienen Sigstore y attestations; no Developer ID
ni Authenticode. La [guía completa en inglés](../development/native-signing.md)
enlaza las instrucciones oficiales y el [documento de política](../../CODE_SIGNING.md).

## Lo que hace el mantenedor en su Mac

1. Usa una cuenta Apple Developer Program. El Account Holder crea un certificado
   **Developer ID Application**: genera un CSR en Acceso a Llaveros → Asistente de
   certificados → Solicitar certificado, súbelo en Certificates, Identifiers &
   Profiles → Certificates → + → Developer ID Application, descarga el .cer e
   impórtalo en el mismo Mac. En Mis certificados debe aparecer su clave privada.
2. Exporta certificado y clave como .p12 protegido con contraseña. Guarda copia
   segura. No uses Apple Development, Mac Distribution ni Developer ID Installer.
3. En App Store Connect → Users and Access → Integrations → App Store Connect API,
   solicita acceso si hace falta y crea una **team API key** con el menor rol que
   permita notarización (Developer). Anota Key ID e Issuer ID y descarga una sola
   vez su .p8. Confirma los roles con el administrador. Una clave individual no
   debe usarse con el comando de issuer del equipo.
4. Crea el environment GitHub **release**, con revisión del mantenedor, sin
   autoaprobación donde esté disponible y despliegues solo desde **tags** v*, no
   ramas. Ningún secreto se añade por el agente.

| Secreto del environment | Contenido |
| --- | --- |
| `APPLE_SIGNING_CERTIFICATE_P12_BASE64` | Base64 del .p12, sin saltos de línea |
| `APPLE_SIGNING_CERTIFICATE_PASSWORD` | Contraseña de exportación |
| `APPLE_SIGNING_IDENTITY` | Nombre exacto Developer ID Application: … (TEAMID), según security find-identity |
| `APPLE_API_KEY_ID` | Identificador de la team API key |
| `APPLE_API_ISSUER_ID` | Issuer ID del equipo |
| `APPLE_API_PRIVATE_KEY` | Contenido completo del .p8 |

Genera el base64 en un fichero privado con umask 077 y `base64 -i DeveloperID.p12`;
elimina los saltos de línea. Sube por stdin o por el formulario enmascarado:

```sh
gh secret set APPLE_SIGNING_CERTIFICATE_P12_BASE64 --repo ns2switch/irmind --env release < certificate-base64.txt
gh secret set APPLE_API_PRIVATE_KEY --repo ns2switch/irmind --env release < AuthKey_KEYID.p8
```

Introduce los otros cuatro valores en el formulario del environment. No los pegues
en chat, argumentos ni incidencias. Borra copias sin cifrar tras la copia segura.

**El job tiene una condición false literal; deja también sin configurar la
variable del repositorio MACOS_NATIVE_SIGNING_ENABLED.** Solo después de otra
aprobación podrá retirarse esa condición en una PR revisada y ponerse la variable
a true para un tag futuro. El job
solo acepta push de tag y solicita el environment protegido. Si está activado y
faltan secretos o falla la notarización, la publicación falla; no hay alternativa
silenciosa sin firma nativa.

Firma los dos ejecutables con hardened runtime y timestamp, los verifica, crea un
DMG firmado, usa notarytool en modo de espera y revisa incidencias; después adjunta
y verifica el ticket en el DMG. Los ejecutables firmados sustituyen el payload antes
de calcular checksums, Sigstore y procedencia. El DMG tiene sus propias pruebas.
Apple no permite adjuntar tickets a ejecutables CLI sueltos: el DMG sirve para la
distribución con ticket sin conexión; los ejecutables sueltos usan consulta online.
Sigue pendiente probar una descarga normal con cuarentena en un Mac del usuario.

## SignPath y Windows

[#66](https://github.com/ns2switch/irmind/issues/66) no contiene constancia de
solicitud o aceptación. El mantenedor revisa las condiciones y solicita el programa
en [SignPath](https://signpath.org/apply). Debe aportar repositorio, licencia,
release existente, política de firma, procedencia de CI y los dos ejecutables.
SignPath decide si el proyecto cumple sus condiciones; no se promete aceptación.
No se añaden credenciales ni integración hasta recibir los IDs y aprobar el diseño.
Una firma tampoco garantiza reputación inmediata en SmartScreen. Mientras tanto,
[verifica las descargas](platforms.md#windows) sin desactivar las protecciones del SO.

## Comprobar una candidata con firma nativa en macOS

Usa una descarga normal sin quitar su atributo de cuarentena. Sustituye los
nombres por los ficheros exactos de esa release:

```sh
codesign --verify --strict --verbose=2 ./irmind
codesign --verify --strict --verbose=2 ./irmind-evtx
codesign -dv --verbose=4 ./irmind
spctl --assess --type execute --verbose=4 ./irmind
xcrun stapler validate ./IRMind-macos-aarch64.dmg
spctl --assess --type open --context context:primary-signature --verbose=4 ./IRMind-macos-aarch64.dmg
```

La identidad debe ser el Developer ID aprobado y las banderas deben incluir
hardened runtime. Ambas evaluaciones y la validación del ticket del DMG deben
funcionar. Comprueba también el DMG sin conexión. Un ejecutable CLI suelto no
admite ticket adjunto: evalúalo con red. Registra versión de macOS, tag y
resultados. Las releases actuales sin firma nativa no tienen por qué superar
estas comprobaciones.

## Preparar la solicitud de SignPath

El repositorio no registra el resultado de ninguna solicitud. Solo el mantenedor
puede confirmar el estado de una solicitud privada. Prepara las URL del proyecto
y sus releases, licencia, política de firma, procedencia de builds, artefactos
a firmar y responsables de revisión y aprobación. Comprueba los campos vigentes
del formulario externo al enviarlo.

Descripción propuesta del proyecto:

> IRMind es un asistente de terminal de código abierto para respuesta defensiva
> a incidentes y análisis forense. El analista consulta evidencia local o fuentes
> remotas configuradas explícitamente. La política y las aprobaciones gobiernan
> las herramientas; los registros del caso se firman. La release Windows incluye
> la CLI y el decodificador EVTX aislado. Los builds proceden de código revisado
> mediante GitHub Actions fijadas e incluyen checksums, firmas Sigstore,
> procedencia y SBOM.

Las [condiciones de la Fundación](https://signpath.org/terms) exigen roles
explícitos, información de privacidad, builds verificables y aprobación de cada
solicitud de firma. [CODE_SIGNING.md](../../CODE_SIGNING.md) identifica los roles
y el estado actual. No atribuyas patrocinio antes de la aceptación. Los metadatos
de nombre y versión de Windows y las restricciones de artefactos de SignPath
se comprobarán al integrar: la política por sí sola no demuestra cumplimiento.
Credenciales y activación requieren una acción posterior del mantenedor.
