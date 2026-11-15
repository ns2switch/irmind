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
