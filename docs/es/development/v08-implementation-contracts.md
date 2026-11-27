# Contratos de implementación de v0.8 para revisión

[English](../../development/v08-implementation-contracts.md)

**Estado.** Propuesta. La implementación requiere aprobación explícita de
los puertos, los límites, los formatos y las decisiones de aislamiento.

- **Hooks locales.** Admisión firmada del ejecutable, la configuración y
  el runtime. El hook previo obligatorio puede vetar, el opcional puede
  aconsejar y el posterior observa un estado ya liquidado. La barra de estado
  usa un permiso separado. Se propone un puerto de ejecución acotada que
  falla en cerrado para hooks obligatorios no disponibles. Aislamiento
  verificado por plataforma. La comparación con WebAssembly no autoriza
  una dependencia. [Contrato de hooks](../../development/v08-hook-contract.md).
- **MCP local.** Solo stdio, revisión 2025-11-25 y herramientas de lectura
  de un caso. El analista firma la descripción, la proyección y el riesgo
  de cada herramienta. Se aplican la política, el alcance y el broker
  normales. Los resultados son no confiables y pasan por ContentGuard.
  [Contrato MCP](../../development/v08-mcp-contract.md).
- **API local.** Primero stdio. Socket Unix y named pipe requerirán las
  pruebas nativas de identidad y permisos. El cliente puede solicitar un
  aviso, pero el analista confirma y desbloquea dentro de IRMind. No hay
  una operación IPC para aprobar. El protocolo no cambia por sí solo
  el formato de caso. [Contrato API](../../development/v08-engine-api-contract.md).
- **Consultas desde subagentes.** Solo el tipo de nube con una asignación
  explícita, alcance y fuentes fijados, y reservas de escaneo y retención
  en el broker único. El 25 % se aplica al plan completo en cada dimensión.
  La captura conserva sus pruebas actuales y los recibos la vinculan al
  checkpoint y al hijo. Usar los tres proveedores simulados de v0.6.
  [Contrato de consultas](../../development/v08-child-source-query-contract.md).

Los cambios con registros firmados proponen un único marcador de caso 8 y
exportación V12. V12 conserva las secciones de V11 y añade una sección
acotada de pruebas de admisión de hooks y MCP. Las consultas reutilizan las
secciones de capturas y ramas. La propuesta mantiene los bytes del sello.
Los contratos incluyen las decisiones pendientes, los casos negativos y
[vectores reproducibles](../../development/v08-implementation-vectors/README.md).
