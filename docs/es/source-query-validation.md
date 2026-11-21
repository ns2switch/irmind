# Validación manual de consultas en origen

[English](../development/source-query-validation.md)

Este ejercicio opcional usa una cuenta y datos sintéticos que el analista tenga
autorización para consultar. Athena y BigQuery pueden cobrar por el escaneo.
Usa un caso por proveedor y un intervalo breve en UTC con eventos de prueba
conocidos. Las pruebas del repositorio usan proveedores simulados.

## Preparar una fuente de prueba

| Proveedor | Fuente de prueba y contabilidad esperada |
| --- | --- |
| Athena | Usa una tabla particionada de eventos de gestión de CloudTrail y un workgroup dedicado, con configuración obligatoria y tope de escaneo por consulta. Acepta explícitamente las condiciones del tope en la política de la fuente. Comprueba el mínimo de 10 MiB y el redondeo por MiB en los bytes facturados. |
| BigQuery | Usa un sink de Cloud Logging con Cloud Audit Logs sintéticos y declara `timestamp-partitioned` o `date-sharded` según el sink. Si ambos diseños están desplegados, prueba los dos. Comprueba la estimación del dry run, el máximo facturable y los bytes finalmente facturados. |
| Azure Log Analytics | Prueba una tabla Analytics entre `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs` y `AzureActivity`. Comprueba el plan de la tabla y la base de precio Analytics. Los bytes de escaneo no están disponibles en esta ruta. Una tabla de prueba Basic o Auxiliary debe rechazarse antes del envío. |

Consulta los recursos y permisos en el
[diseño de consultas en origen](source-queries-design.md) y la
[guía de configuración](configuration.md#consultas-en-origen). Asigna límites
pequeños para la fuente y el caso que cubran el mínimo o la estimación previa
del proveedor. Introduce las credenciales en **Settings → Keystore**, adopta la
fuente y asigna el presupuesto al caso como analista.

## Ejecutar y registrar

1. Pide al agente principal eventos de la fuente en el intervalo de prueba.
   Usa un límite de filas bajo, con más eventos coincidentes que el límite.
   Si se requiere consentimiento, revisa el alcance, el presupuesto y la
   consulta traducida con `/source-query show <id-del-plan>`. Aprueba ese
   plan con `/source-query approve <id-del-plan>`.
2. Comprueba que la herramienta y `/verify` muestran el límite local de filas.
   Compara `/budget` con el informe de uso del proveedor. Consulta la captura
   en local por timeline o entidad y compara un evento conocido con el original.
3. Propón una fuente o un intervalo fuera de alcance y comprueba que se rechaza
   antes de enviar. En Azure, comprueba también el rechazo de una tabla de
   otro plan.
4. Sella el caso y expórtalo. Verifica la exportación con la clave pública
   esperada del analista y revisa la captura y los avisos de resultado parcial.

| Proveedor y diseño de fuente | Caso y exportación verificados | Bytes facturados y reservados | Filas y bytes retenidos | Aviso de límite y rechazo de alcance |
| --- | --- | --- | --- | --- |
| Athena | | | | |
| BigQuery | | | | |
| Azure Log Analytics | | | | |
