Traducción de docs/development/roadmap.md en el commit 6932516a9fafe79d5e05e2fb1c3d049d3d62637f; si hay diferencias, prevalece la versión en inglés.

# Hoja de ruta

Esta página es para quienes contribuyen al proyecto o evalúan sus límites actuales. Describe el trabajo previsto sin prometer una fecha de publicación. Antes de usar una integración, lee el [modelo de seguridad](security-model.md).

## Disponible para evaluación con datos sintéticos

- Una TUI centrada en la conversación, con entrada multilínea, tarjetas desplazables de actividad firmada, autocompletado de comandos y un panel lateral opcional. En el mismo espacio se crean casos, se ingiere evidencia, se investiga, se aprueban llamadas, se verifica, se sella y se exporta.
- Texto incremental del modelo, paneles de IOC, hipótesis y técnicas ATT&CK con confirmación del analista, y fragmentos de evidencia junto a las aprobaciones relacionadas.
- Consultas de lectura sujetas a política y enriquecimiento externo aprobado por el analista, con un guard obligatorio.
- Custodia local en SQLite y almacenamiento derivado en Parquet consultado directamente con Arrow, con firmas Ed25519 mediante un llavero del sistema o un archivo cifrado seleccionados explícitamente. Los manifiestos firmados permiten casos grandes sin copiar cada original de forma implícita; la copia es una opción expresa. Los benchmarks sintéticos de 1 GB y 15 GB cumplen los objetivos de ingesta y consulta locales.
- Módulos LLM seleccionados explícitamente y conectores opcionales de Splunk, AWS, EDR, MISP y VirusTotal; Splunk usa campos y agregaciones estructurados.
- Propuestas tipadas de IOC, hipótesis, técnicas ATT&CK y eventos de cronología; los informes citan evidencia confirmada.
- Alcance del caso con proyectos y techo opcional de política TOML para consultas remotas.
- Contratos automatizados y pruebas de extremo a extremo con datos sintéticos.

## Alcance del MVP

El MVP tiene un alcance cerrado:

1. Ingerir casos de 15 a 500 GB con manifiestos firmados de los originales, copia opcional y Parquet particionado. Las consultas acotadas con Arrow leerán solo Parquet firmado y generado por IRMind. La verificación informará de originales ausentes o cambiados; el muestreo indicará su cobertura limitada. Medir 1 GB y 15 GB en un runner estándar.
2. Obtener alertas del SIEM y mantener las trazas de diagnóstico separadas de los eventos firmados de custodia.
3. Mantener las consultas SIEM limitadas a campos, operadores, ventanas temporales y agregaciones sencillas estructurados que traduce el conector.
4. Procesar en streaming exportaciones de CloudTrail, Cloud Audit Logs de GCP, Azure Activity y registros de inicio de sesión de Entra ID, además de JSON genérico. Migrar los casos existentes con verificación antes y después.
5. Leer objetos de S3, GCS y Azure Blob en streaming mediante conectores explícitos de solo lectura. El alcance firmado v3 delimita buckets, contenedores, prefijos y ventanas UTC. Cada lectura de una versión requiere antes una lista completa firmada; los presupuestos de transferencia y la confirmación explícita limitan el coste. Probar cada backend con respuestas sintéticas grabadas.
6. Completar las pruebas con respuestas grabadas, los contratos compartidos y las guías de los módulos de nube, SIEM, EDR e inteligencia de amenazas existentes.

La versión `v0.1.0` solo se publicará cuando todos los hitos del [plan de referencia](../development/plan.md) cumplan sus criterios, se documente la prueba manual del modelo, se pruebe al menos un conector contra un entorno real de pruebas y el tag incluya un registro de cambios y binarios descargables. Todos los módulos actuales siguen siendo experimentales hasta cumplir esas condiciones. Aún no hay fecha de publicación.

Cada PR y merge ejecuta los checks de Linux. Las PR que tocan código de plataforma o CI también ejecutan Windows y macOS; la matriz completa y la verificación cruzada se ejecutan de noche tras cambios en `main` y en tags de versión. Los binarios solo se compilan para tags y ejecuciones nocturnas que incluyan cambios de código.

## Después del MVP

La [consulta en origen](../development/cloud-query-design.md) queda para justo después del MVP: Athena, CloudTrail Lake y Security Lake en AWS; BigQuery y Log Analytics de Cloud Logging en GCP; Azure Data Explorer y Log Analytics en Azure. Solo se prevén consultas estructuradas, con presupuestos de escaneo y resultados firmados. Chronicle, otros conectores de producto, el anclaje externo de los sellos y el gateway con watches siguen aplazados. El gateway deberá usar una clave Agent distinta, permitir solo lecturas dentro del alcance sin analista y exigir la firma del analista para cada aprobación. La contención queda fuera del alcance actual.

Ningún proveedor se activa por defecto. Antes de usar el proyecto en producción también hacen falta pruebas manuales de la terminal, aprobación de compliance para el proveedor y una decisión sobre la firma de los binarios.
