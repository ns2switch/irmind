Traducción de SECURITY.md en el commit e31fd5cc947308542888df4a52164d8892c56b93; si hay diferencias, prevalece la versión en inglés.

[English source](SECURITY.md)

# Política de seguridad

Esta página es para quienes quieren comunicar una vulnerabilidad de IRMind. El proyecto está en desarrollo y **no está listo para incidentes reales ni datos sensibles**. Revisamos los informes que afecten a la rama pública actual; todavía no se admite una versión de producción.

## Comunicar en privado

No publiques vulnerabilidades, detalles de explotación, datos reales de incidentes ni secretos en issues o PR. En GitHub, usa **Security → Advisories → Report a vulnerability** para enviar un informe privado. Incluye la versión o commit afectado, el impacto, pasos para reproducirlo con datos sintéticos y una forma de contacto.

Si no aparece esa opción, abre un issue pidiendo que se habilite **sin detalles técnicos de la vulnerabilidad**. Este archivo no activa por sí mismo el reporte privado.

## Plazos orientativos

| Paso | Objetivo |
| --- | --- |
| Acuse de recibo | 3 días laborables |
| Evaluación inicial y respuesta | 7 días laborables |
| Actualizaciones mientras siga abierto | Al menos cada 14 días |
| Corrección y divulgación coordinada | Objetivo inicial de 90 días desde el informe; comunicaremos ampliaciones |

Son objetivos de respuesta, no una garantía de corrección en una fecha fija. Coordinaremos un aviso de seguridad con quien informe cuando exista una mitigación verificable. No solicitamos ni aceptamos evidencia real ni secretos para reproducir un fallo.

Consulta el [modelo de seguridad](docs/es/security-model.md) para las garantías y riesgos residuales.

## Verificar una versión

Desde v0.1.1, cada binario de versión y `SHA256SUMS` tienen un bundle Sigstore sin claves permanentes. GitHub registra además una atestación de procedencia para cada binario. Comprueba el hash, la identidad del certificado Sigstore `https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/<TAG>`, el emisor `https://token.actions.githubusercontent.com`, y ejecuta `gh attestation verify <BINARY> -R ns2switch/irmind` antes de usarlo. La [guía de plataformas](docs/es/platforms.md) da los comandos exactos. La firma y la procedencia no sustituyen la revisión del código ni sus límites. Apple sigue sin notarización y Windows sin Authenticode.
