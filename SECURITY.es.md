Traducción de SECURITY.md en el commit c900bb56614458096dbb1e71762d941a70242630; si hay diferencias, prevalece la versión en inglés.

[English source](SECURITY.md)

# Política de seguridad

Esta página es para quienes quieren comunicar una vulnerabilidad de IRMind. El proyecto está en desarrollo y **no está listo para incidentes reales ni datos sensibles**. Las correcciones se dirigen a la última versión preliminar y a la rama principal de desarrollo. Las versiones anteriores deben actualizarse; una versión preliminar no supone soporte de producción.

## Comunicar un problema

Abre un [issue en GitHub](https://github.com/ns2switch/irmind/issues/new/choose) con la versión o commit afectado, el comportamiento esperado y un ejemplo mínimo sintético. No incluyas credenciales, evidencia de incidentes reales, información personal ni detalles operativos de un entorno real.

Si necesitas un canal de contacto privado, abre un issue solicitándolo sin detalles técnicos. Un mantenedor acordará un canal adecuado. No envíes secretos ni evidencia real para demostrar un problema.

## Correcciones y publicación antes de la 1.0

Durante el desarrollo pre-1.0, las correcciones se publican mediante PR públicas ordinarias, los controles habituales de CI y `main`. La siguiente versión incluye una entrada técnica breve en el changelog e identifica las versiones publicadas afectadas cuando se conocen. El proyecto no crea ni publica GitHub Security Advisories ni forks privados temporales para las correcciones.

Esta política de publicación no cambia ningún control de ejecución. Siguen siendo obligatorios el techo de la política, las aprobaciones del analista, ContentGuard, la procedencia, las firmas, los hashes, la verificación de custodia y TLS, el aislamiento y los límites de recursos. Las correcciones conservan sus pruebas de regresión y pasan los controles habituales de integración.

Los informes detallados del analista y los registros de su entorno siguen siendo privados. Las PR públicas describen el comportamiento, las pruebas, los benchmarks release y las decisiones de diseño sin información personal del equipo ni credenciales.

## Plazos orientativos

| Paso | Objetivo |
| --- | --- |
| Acuse de recibo | 3 días laborables |
| Evaluación inicial y respuesta | 7 días laborables |
| Actualizaciones mientras siga abierto | Al menos cada 14 días |
| Evaluación y planificación de la corrección | Objetivo inicial de 90 días desde el informe; comunicaremos ampliaciones |

Son objetivos de respuesta, no una garantía de corrección en una fecha fija. Informaremos a quien comunique el problema sobre la evaluación y las correcciones. No solicitamos ni aceptamos evidencia real ni secretos para reproducir un fallo.

Consulta el [modelo de seguridad](docs/es/security-model.md) para las garantías y riesgos residuales.

## Verificar una versión

Desde v0.1.1, cada binario de versión y `SHA256SUMS` tienen un bundle Sigstore sin claves permanentes. GitHub registra además una atestación de procedencia para cada binario. Comprueba el hash, la identidad del certificado Sigstore `https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/<TAG>`, el emisor `https://token.actions.githubusercontent.com`, y ejecuta `gh attestation verify <BINARY> -R ns2switch/irmind` antes de usarlo. La [guía de plataformas](docs/es/platforms.md) da los comandos exactos. La firma y la procedencia no sustituyen la revisión del código ni sus límites. Apple sigue sin notarización y Windows sin Authenticode.
