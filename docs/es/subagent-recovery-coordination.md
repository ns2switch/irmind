# Coordinación entre procesos para recuperar planes interrumpidos

Contrato de puertos para exponer la reconciliación existente en la TUI. No incluye
implementación ni cambia registros firmados o reservas. Propuesta inicial:
[#316](https://github.com/ns2switch/irmind/pull/316).

## Invariante

Solo se recupera trabajo interrumpido cuando ningún proceso conserva una vista
previa o un plan iniciado activo en ese caso. El registro en memoria solo conoce
su proceso. Ni una confirmación, ni un PID, ni una fecha, ni un indicador persistido
sustituyen un bloqueo del sistema operativo. Las lecturas normales siguen siendo
posibles; no se interrumpe otra sesión ni se liberan consumos inciertos.

## Métodos aditivos en SubagentBranchStore

```rust
fn try_plan_activity(&self, case: &CaseId)
    -> Result<Box<dyn CaseLock>, AppError>;
fn try_plan_recovery(&self, case: &CaseId)
    -> Result<Box<dyn CaseLock>, AppError>;
```

Ambos devuelven por defecto un error de no disponibilidad, nunca un permiso vacío.
Adaptadores y fakes deben proporcionar coordinación antes de habilitar la ejecución
o recuperación. Se reutilizan CaseId, CaseLock, AppError y fs4; no cambia ninguna
firma existente ni se añade una dependencia de producción.

El primer método obtiene un bloqueo compartido de actividad por caso; el segundo,
un bloqueo exclusivo de la misma puerta. No esperan: ante contención, error o falta
de soporte fallan cerrado con un mensaje accionable. Esta puerta es distinta del
bloqueo de transacciones y del bloqueo de sesión/borrado: la recuperación puede
publicar sus transacciones sin intentar adquirir un bloqueo compartido debajo de
su propio bloqueo exclusivo.

## Vida y orden

1. Conservar la protección de sesión existente frente al borrado, cuando exista.
2. Adquirir la puerta de actividad antes de publicar el plan o cualquier reserva.
3. Usar el bloqueo normal del repositorio solo durante las transacciones existentes.

El plan preparado/iniciado conserva un permiso privado en memoria. Los workers
lo retienen hasta ser cancelados y unidos; perder el manejador raíz no lo libera
si sigue vivo un hijo. Se libera después de los registros terminales/liberación y
de unir los workers. Una vista previa conserva su expiración firmada existente.
Un cierre brusco libera el bloqueo del SO, sin inventar registros terminales.

Engine::cancel_interrupted_subagent_plans adquiere por sí mismo la puerta exclusiva
antes de enumerar planes y la conserva durante toda la operación. No basta con
comprobarlo en la TUI. Se mantiene además la comprobación local de tareas vivas.
Mientras se recupera, otro proceso no puede publicar una vista previa ni arrancar
un plan.

## TUI y custodia

Confirmación explícita del analista, con Cancelar preseleccionado. Si está ocupado,
se indica terminar/cancelar el plan en su sesión propietaria. Sin opción de forzar,
sin anulación por tiempo y sin herramienta del modelo para recuperar. Los casos
sellados siguen inmutables; se conservan ramas completas, prefijos comprometidos,
uso incierto, liquidación única, alcance y límites.

No cambian el marcador del caso, los registros, el sello, export V8, los golden ni
las migraciones. Los campos nuevos de propiedad solo existen durante la ejecución.

## Pruebas nativas

Procesos independientes y sincronización por eventos, acotada, en Linux, macOS y
Windows. Dos objetos del mismo proceso no bastan.

- Una vista previa/hijo activo en A impide recuperar en B sin nuevos registros,
  cancelación del hijo ni liberación de su reserva.
- Recuperar en B impide otro plan en A antes de firmar la reserva o pedir al modelo.
  Otra recuperación concurrente falla; repetirla después es idempotente.
- Un hijo conserva el bloqueo aunque desaparezca el manejador raíz, hasta su unión.
- Matar A libera el bloqueo. B verifica/reconcilia el prefijo y retiene el consumo
  desconocido, sin repetir llamadas al modelo ni a herramientas.
- El borrado sigue bloqueado durante la actividad/recuperación; las lecturas y
  transacciones normales funcionan sin interbloqueo por orden de adquisición.
- Sin adaptador, con error o sin bloqueo compatible se rechaza la operación.
  El modelo falso obediente no puede invocarla ni eludirla.
