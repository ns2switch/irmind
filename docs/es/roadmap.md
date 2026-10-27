Traducción de docs/development/roadmap.md en el commit fba2d869fa136190fa7debb05c7490b06f987277; si hay diferencias, prevalece la versión en inglés.

# Hoja de ruta

Esta página es para quienes contribuyen al proyecto o evalúan sus límites actuales. Describe el trabajo previsto sin prometer una fecha de publicación. Antes de usar una integración, lee el [modelo de seguridad](security-model.md).

## Disponible para evaluación con datos sintéticos

- Una TUI centrada en el caso para crearlo, ingerir evidencia, investigar, aprobar llamadas, verificar, sellar y exportar, con los cambios firmados.
- Texto incremental del modelo, paneles de IOC, hipótesis y técnicas ATT&CK con confirmación del analista, y fragmentos de evidencia junto a las aprobaciones relacionadas.
- Consultas de lectura sujetas a política y enriquecimiento externo aprobado por el analista, con un guard obligatorio.
- Custodia local en SQLite, grafo derivado en DuckDB y firmas Ed25519 mediante un llavero del sistema o un archivo cifrado, seleccionados explícitamente.
- Módulos LLM seleccionados explícitamente y conectores opcionales de Splunk, AWS, EDR, MISP y VirusTotal.
- Propuestas tipadas de IOC, hipótesis, técnicas ATT&CK y eventos de cronología; los informes citan evidencia confirmada.
- Alcance del caso con proyectos y techo opcional de política TOML para consultas remotas.
- Contratos automatizados y pruebas de extremo a extremo con datos sintéticos.

## Alcance del MVP

El MVP tiene un alcance cerrado:

1. Procesar CloudTrail y JSON en streaming, añadir búsqueda de texto completo en el grafo DuckDB y medir la ingesta de al menos 1 GB de evidencia sintética.
2. Obtener alertas del SIEM y mantener las trazas de diagnóstico separadas de los eventos firmados de custodia.
3. Sustituir las consultas SIEM libres generadas por el modelo por campos, operadores, ventanas temporales y agregaciones sencillas estructurados; el conector los traduce a su lenguaje de consulta.
4. Completar las pruebas con respuestas grabadas, los contratos compartidos y las guías de configuración de los módulos de nube, SIEM, EDR e inteligencia de amenazas que ya existen en el workspace.

La versión `v0.1.0` solo se publicará cuando todos los hitos del [plan de referencia](../development/plan.md) cumplan sus criterios, se documente la prueba manual del modelo, se pruebe al menos un conector contra un entorno real de pruebas y el tag incluya un registro de cambios y binarios descargables. Todos los módulos actuales siguen siendo experimentales hasta cumplir esas condiciones. Aún no hay fecha de publicación.

La matriz de integración cubre Linux, macOS, Windows y la verificación de exportaciones entre sistemas. Los binarios de publicación se compilan una vez al día en `main` cuando hay cambios de código.

## Después del MVP

Chronicle, GCP, Azure y otros conectores de producto podrán añadirse mediante los puertos compartidos. También se pospone el anclaje externo de los sellos de caso. Un gateway local podrá ejecutar watches y agentes desatendidos; deberá usar una clave Agent distinta, permitir solo lecturas dentro del alcance sin analista y exigir la firma del analista para cada aprobación. La contención queda fuera del alcance actual.

Ningún proveedor se activa por defecto. Antes de usar el proyecto en producción también hacen falta pruebas manuales de la terminal, aprobación de compliance para el proveedor y una decisión sobre la firma de los binarios.
