Traducción de CODE_SIGNING.md en el commit 050c01156cc3c45f5229306b88051eb22ed68348; si hay diferencias, prevalece la versión en inglés.

# Política de firma de código

Las releases de IRMind se construyen desde commits etiquetados y revisados mediante
el workflow fijado de GitHub Actions. Los mantenedores aprueban las etiquetas;
DCO, CI y los controles de política, custodia, TLS y aislamiento siguen siendo
obligatorios. Se firman el ejecutable principal, el auxiliar EVTX y SHA256SUMS.
Este inventario vincula instaladores, licencias, SBOM e informes de auditoría;
GitHub Actions atesta la procedencia de binarios y SBOM.

La firma sin claves de Sigstore está activa. La identidad esperada fija repositorio,
workflow y etiqueta exacta; véase [plataformas](docs/es/platforms.md). No se guarda
una clave privada persistente de Sigstore en el repositorio.

Developer ID Application, hardened runtime y notarización están preparados pero
**desactivados** hasta que el mantenedor configure el environment protegido
`release` y apruebe su activación. Authenticode mediante SignPath Foundation sigue
pendiente de solicitud y aceptación. Las releases actuales no afirman tener esas
firmas nativas. Solo trabajos de etiquetas pueden solicitar credenciales nativas;
las PR y los ensayos de rama no pueden. Una vez activada, un fallo bloquea la
publicación.

La firma acredita origen y proceso de construcción, no corrección forense ni
aptitud para incidentes reales. IRMind es pre-1.0 y se evalúa principalmente con
datos sintéticos. Véanse [SECURITY.md](SECURITY.md) y la
[guía del mantenedor](docs/es/native-signing.md).

## Responsabilidades y privacidad

Las contribuciones llevan DCO y los mantenedores las revisan. El propietario del
repositorio, [ns2switch](https://github.com/ns2switch), aprueba tags y futuras
solicitudes de firma nativa. Otros aprobadores deben identificarse explícitamente
antes de activar la integración. SignPath debe conservar la aprobación manual
de cada solicitud y confirmar MFA para el equipo participante.

IRMind contacta con modelos, conectores o catálogos remotos mediante la
configuración y las acciones explícitas del analista. Antes de enviar datos,
el analista debe revisar la privacidad del proveedor elegido. Skills y subagentes
no amplían política, alcance ni aprobaciones.

La aceptación por SignPath, la atribución a la Fundación, los metadatos Windows
de producto y versión y las restricciones de artefactos siguen pendientes de
integración. Esta política no afirma que la solicitud esté aceptada ni que los
binarios Windows actuales lleven Authenticode.
