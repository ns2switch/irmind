# Añadir un parser o conector

Usa datos sintéticos y respeta [la arquitectura](../development/architecture.md),
[el modelo de seguridad](security-model.md) y [las reglas de contribución](../../CONTRIBUTING.es.md).
La [guía completa en inglés](../development/adding-a-module.md) enlaza los contratos.

## Parser

Cada formato vive en su crate parser propio, detrás de una feature incluida por
defecto y excluible. LogParser detecta de forma pura sobre un máximo de 64 KiB,
con el nombre de fichero como pista débil. SourceDecoder emite SourceRecordV1
Tainted con campos originales, precisión temporal, hash, ordinal y offset real.
Impone límites de registro, profundidad, campos y cancelación. El paralelismo
opcional conserva el orden original. Una línea inválida se cuenta con muestra
acotada; no justifica omitir en silencio las siguientes.

La interpretación pertenece a un SourceMapper identificado, no al decodificador.
Usa [la guía de mapeos](adding-a-mapping.md). El pipeline registra las identidades
seleccionadas y conserva hash/procedencia. Un único candidato de alta confianza se
elige; empates o baja confianza preguntan al analista y en modo desatendido se rechazan.

Añade fixtures válidos, truncados, malformados y hostiles, variantes del proveedor,
un episodio sintético con respuestas aisladas, matriz de detección, fuzz y hashes
idénticos con distintos trabajadores. Actualiza módulos, parsers y mapeos en ambos
idiomas; mide rendimiento solo en release.

## Conector

Usa un puerto existente: SiemPort, EdrPort, CloudAuditPort, ThreatIntelPort u
ObjectSource. Un puerto nuevo requiere diseño previo. Declara ModuleManifest,
campos no secretos y credenciales del SecretBackend; no leas claves del entorno.
Implementa execute sobre AuthorizedCall, con alcance exacto, cancelación y límites
de peticiones, tiempo y respuesta. TLS verifica cadena y hostname, sin redirecciones
ni opción para desactivarlo. Las consultas estructuradas se traducen con valores
escapados; nunca SQL/KQL libre del modelo.

Pasa la suite de contrato común y fixtures sintéticos grabados; documenta endpoint,
campos, rol mínimo, CA opcional y limitaciones. Resultados externos son no confiables,
se conservan firmados y solo se muestran o envían al modelo tras el guard. No cambies
formatos, dependencias o credenciales sin la decisión correspondiente.

Ejecuta fmt, Clippy estricto, tests afectados, dirección de dependencias y cargo-deny.
Para metodología usa [la guía de skills](writing-a-skill.md). Los casos actuales
usan marcador 4, artefactos mapeados V3 y export V8; no hay puente de parser antiguo.
