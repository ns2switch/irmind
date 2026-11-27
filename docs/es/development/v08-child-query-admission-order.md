# Atribución de la consulta de un hijo antes de publicarla

**Estado.** Enmienda para revisión. Los cuerpos y vectores aprobados se conservan.

El motor guarda hoy `SourceQueryPlanV1` antes de revisar el preflight. Si la
atribución al hijo se registrara al reservar el envío, el agente principal
podría ejecutar ese ID durante el intervalo y cobrarlo al presupuesto padre.

La propuesta guarda el plan y `irmind-child-source-query-v1` juntos en una
transacción, tras verificar la propuesta de rama, el checkpoint y la reserva
del hijo y tras hacer el preflight. El analista firma la aprobación existente
cuando corresponde. Solo el broker del hijo activo puede despachar. La
transacción de envío comprueba la pareja autenticada y añade la reserva, la
intención y la cuota existentes. Una caída no deja un plan sin atribución y
un hijo caducado no puede ceder su consulta al padre.

[Orden exacto y pruebas de regresión](../../development/v08-child-query-admission-order.md)
