# API local del motor

[English](../../development/engine-api.md)

`irmind serve <case_uuid>` da acceso a un solo caso a un cliente local. El
cliente ejecuta IRMind con tuberías separadas para stdin y stdout y mantiene
el terminal de control del analista. IRMind muestra el UUID en ese terminal
y pide escribirlo para admitir la sesión. El desbloqueo del llavero de
fichero ocurre en IRMind. `--passphrase-fd` se rechaza en este modo.
La API verifica las ramas de subagentes que ya existen. Las delegaciones
nuevas se inician desde la TUI, donde se puede revisar la reserva.

El protocolo comienza con `IRMIND-RPC-V1` y un byte NUL en ambos sentidos.
Cada mensaje usa una longitud u32 big-endian y JSON UTF-8 canónico. El
límite es 64 KiB por mensaje, 16 niveles y 4.096 nodos. `hello` abre la
sesión con versión 1. Después están disponibles `open_case`, `case_status`,
`subscribe`, `start_turn` y `cancel`, siempre para el caso admitido. La
[especificación](../../development/engine-api.md#wire) define los campos.

El flujo entrega eventos autenticados, con vista previa protegida de las
respuestas completas que quedan en el caso. Si llega `resync_required`,
consulta `case_status` y vuelve a suscribirte desde el cursor devuelto.
Consultar `case_status` reemplaza el cursor y cierra su suscripción anterior.
Un cliente desconectado cancela su turno por la ruta normal del motor.

Si un evento indica `review_in_tui`, abre el caso en la TUI de IRMind y
usa `/approvals`. Solo IRMind firma la decisión. La API transmite el estado
con ContentGuard y carece de operaciones para aprobar, firmar o gestionar
credenciales. Esta implementación usa el caso 7 y la exportación V11.
