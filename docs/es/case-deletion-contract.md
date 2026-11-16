# Contrato de borrado firmado de casos abiertos

Propuesta; este documento no borra casos ni habilita su borrado. El
[contrato normativo en inglés](../development/case-deletion-contract.md) fija los
puertos, el recibo y las pruebas. No cambian los bytes actuales de casos, sellos,
exportaciones ni del sobre de operaciones globales.

## Confirmación, firma y recuperación

El analista revisa título, creación, fuentes y tamaño y escribe el título exacto
o el identificador. Puede añadir un motivo de hasta 1.024 bytes UTF-8. La
aplicación comprueba las cadenas del caso y global y rechaza cualquier sello,
fichero de sello o sellado pendiente. Firma un recibo `case-deleted-v1:` con la
clave Analyst antes de borrar nada. No existe herramienta de modelo o hijo para
invocar esta operación ni para fabricar su confirmación.

El adaptador guarda la operación firmada y la intención de borrado en una sola
transacción SQLite. Desde ese instante el caso deja de aparecer como abierto,
aunque queden ficheros por limpiar. La limpieza es idempotente; su estado y sus
errores son datos operativos, mientras que la lápida firmada permanece en el log
global. Si falla la firma o la transacción de intención, el caso no cambia.

Al arrancar, el motor autentica primero toda la cadena global con el verificador
Analyst de confianza. Solo después entrega recibos autenticados a la recuperación.
Un marcador de base de datos aislado nunca autoriza borrar. Si no puede completar
la limpieza, se muestra la lápida pendiente y el motivo; el caso no reaparece
como válido y no se crea otra firma para reintentar.

Se conservan las protecciones append-only para las operaciones normales. La
excepción de eliminación queda limitada al caso no sellado de una intención
firmada y confirmada. Las operaciones globales nunca se editan ni borran.

## Puertos propuestos

`CaseLifecycleStore` es opcional y se conecta mediante
`with_case_lifecycle(Arc<dyn CaseLifecycleStore>)`, sin cambiar firmas de métodos
actuales de repositorio, auditoría, ingesta o exportación:

- `open_session(id)`: entrega un bloqueo compartido durante la sesión abierta.
- `prepare_deletion(id, cancel)`: entrega un `PreparedCaseDeletion` con inventario
  inmutable y los bloqueos exclusivos de eliminación.
- `resume_deletion(VerifiedCaseDeletion, cancel)`: reanuda una intención ya
  autenticada, con resultado completado o pendiente y error explícito.

`PreparedCaseDeletion` expone `inventory()` y `commit(SignedOperation)`. El
commit comprueba que el recibo coincide con el inventario preparado y guarda
operación e intención atómicamente. Cancelar la vista previa libera sus bloqueos
sin firmar ni escribir. `VerifiedCaseDeletion` solo se construye dentro de la
aplicación después de autenticar la cadena. Un adaptador sin este puerto no puede
borrar; nunca se devuelve éxito silencioso.

## Sesiones y concurrencia

El bloqueo actual dura una operación, no toda la sesión de TUI. Se añade una
reserva compartida de sesión usando el directorio privado de locks y `fs4` ya
existentes. El borrado exige su contraparte exclusiva no bloqueante y el bloqueo
exclusivo actual de operaciones del caso. Si otra sesión u operación los ocupa,
se explica el motivo inmediatamente.

Para borrar desde el caso actual, la interfaz cancela y espera sus tareas y
regresa al controlador de inicio antes de adquirir el bloqueo exclusivo. Un
caso sellado se rechaza sin cerrarlo. Las sesiones interactivas de CLI usan el
mismo bloqueo de duración completa.

Orden de adquisición: sesión, operación del caso, mantenimiento global de blobs
cuando sea necesario, diario global y transacción SQLite. No se borran los
ficheros de bloqueo: desvincular uno activo permitiría bloquear otro inode.

## Qué se borra y cómo se mide

La SQLite y los blobs por hash son compartidos. Solo se recorren rutas derivadas
por el adaptador de un UUID validado: árbol Parquet del caso, copias privadas,
spool, staging, pruebas, snapshots de métodos y ramas propias. Nunca se usan
rutas de originales o URI como destino. No se siguen symlinks, junctions ni
reparse points; una entrada inesperada deja la limpieza pendiente con un error.

Los blobs compartidos solo se recuperan si ningún otro caso los referencia. Su
publicación y eliminación usan un mismo bloqueo de mantenimiento a través de la
comprobación de referencias y el efecto en disco, evitando carreras. Los datos
necesarios para otro caso permanecen; los originales externos no se tocan.

La vista previa y el recibo distinguen bytes exactos de ficheros privados,
bytes lógicos referenciados en el pool compartido y contabilidad de payload
SQLite. Esta última no mide páginas asignadas. La interfaz explica la diferencia:
no promete que SQLite se reduzca ni que todos los bytes compartidos se liberen.
El recibo fija el inventario autorizado; el progreso puede indicar por separado
los bytes realmente desvinculados.

Es borrado lógico, no eliminación segura. SSD, snapshots, backups, WAL y páginas
libres pueden conservar datos. Para evidencia sensible se recomienda cifrado
completo del disco; no se afirma una sanitización forense.

## Recibo y pruebas

`CaseDeletedV1` usa JSON de estructura y orden fijos: versión 1, identificador,
título, creación, último hash, número de entradas y fuentes, los tres tamaños,
motivo opcional e instante de borrado. Contadores e instantes son u64 acotados;
el título no supera 200 bytes, el hash tiene 64 caracteres hexadecimales en
minúsculas y el instante coincide con el sobre firmado. Debe existir una entrada
al menos y no puede haber más fuentes que entradas.

Los [vectores propuestos](../development/case-deletion-vectors/receipt.json), su
[hash](../development/case-deletion-vectors/receipt.sha256) y su
[hexadecimal](../development/case-deletion-vectors/receipt.hex) fijan los bytes.
No se modifica ningún golden anterior.

La aceptación exige pruebas nativas de dos procesos y bloqueos, fallo de firma,
recibo alterado, casos sellados, cancelación, interrupciones en cada fase,
recuperación idempotente, blobs compartidos y publicación concurrente, originales
externos intactos, enlaces maliciosos, protección del texto de lápidas y modelo
falso obediente sin capacidad de borrar ni firmar. Los golden también se
comprueban con `preserve_order`.
