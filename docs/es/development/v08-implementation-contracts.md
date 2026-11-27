# Contratos de implementación de v0.8 para revisión

[English](../../development/v08-implementation-contracts.md)

**Estado.** Aprobados J, los cuerpos de registros, el caso 8, V12 y los
vectores. Orden de implementación: API del motor, consultas desde subagentes,
MCP y hooks. La superficie de aprobación de la API sigue en revisión.

- **Hooks locales.** Admisión firmada del ejecutable, la configuración y
  el runtime. El hook previo obligatorio puede vetar, el opcional puede
  aconsejar y el posterior observa un estado ya liquidado. La barra de estado
  usa un permiso separado. Se propone un puerto de ejecución acotada que
  falla en cerrado para hooks obligatorios no disponibles. Aislamiento
  verificado por plataforma. Antes de elegir, se medirá el intérprete nativo
  frente a WebAssembly en los cinco destinos: tamaño, dependencias, latencia,
  RSS y aislamiento. [Contrato de hooks](../../development/v08-hook-contract.md).
- **MCP local.** Solo stdio, revisión 2025-11-25 y herramientas de lectura
  de un caso. El analista firma la descripción, la proyección y el riesgo
  de cada herramienta. Se aplican la política, el alcance y el broker
  normales. Los resultados son no confiables y pasan por ContentGuard. Cada
  destino debe demostrar que impide red, ficheros ajenos, procesos hijo e IPC
  externa antes de habilitar MCP.
  [Contrato MCP](../../development/v08-mcp-contract.md).
- **API local.** Primero stdio con `open_case`, `case_status`, `subscribe`,
  `start_turn` y `cancel`. Mientras se revisa el nuevo contrato, las
  decisiones se toman en `/approvals` de la TUI. El analista ha elegido
  que la GUI que lance IRMind por stdio muestre la solicitud y que IRMind
  verifique una reautenticación por decisión. Socket Unix y named pipe
  quedan para otro contrato.
  [Contrato de aprobación gráfica](v08-graphical-approvals-contract.md).
- **Consultas desde subagentes.** Solo el tipo de nube con una asignación
  explícita, alcance y fuentes fijados, y reservas de escaneo y retención
  en el broker único. El 25 % se aplica al plan completo en cada dimensión.
  La captura conserva sus pruebas actuales y los recibos la vinculan al
  checkpoint y al hijo. Usar los tres proveedores simulados de v0.6.
  [Contrato de consultas](../../development/v08-child-source-query-contract.md).

Los cambios con registros firmados comparten el marcador de caso 8 y la
exportación V12. V12 conserva las secciones de V11 y añade una sección
acotada de pruebas de admisión de hooks y MCP. Las consultas reutilizan las
secciones de capturas y ramas. Se conservan los bytes del sello. Los casos
creados con v0.8.0-alpha.1 usan el caso 7 y V11 y requieren el binario de la
alpha, o reingerir los originales verificados.
Los contratos incluyen las decisiones pendientes, los casos negativos y
[vectores reproducibles](../../development/v08-implementation-vectors/README.md).
