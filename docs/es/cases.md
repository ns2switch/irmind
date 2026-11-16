Traducción de docs/cases.md; si hay diferencias, prevalece la versión en inglés.

# Casos y borrado lógico

Un caso contiene su cadena firmada, referencias a evidencia, grafo Parquet,
snapshots de skills y ramas de subagentes. Los originales externos al directorio
de datos permanecen en sus ubicaciones registradas. Sellar hace inmutable el caso.

## Borrar un caso no sellado

Desde un caso abierto, ejecuta `/case delete`. Desde `/home`, selecciona un caso
con las flechas y ejecuta `/case delete`, o utiliza `/case delete <título o ID>`.
El pie de la lista muestra esta opción. Un caso sellado no se puede borrar. Si
está abierto u ocupado en otro proceso, primero hay que cerrarlo allí.

La pantalla muestra título, fecha de creación, fuentes, entradas e inventario de
almacenamiento. Escribe el **título o ID exacto**, añade un motivo opcional y elige
**Sign and delete**, seguido de Enter. Tab y Shift+Tab recorren campos y opciones;
Esc cancela antes de firmar. Ninguna herramienta del modelo o de un subagente
puede ejecutar esta operación.

IRMind verifica el caso, firma una lápida global del analista y la guarda junto
con una intención durable antes de eliminar contenido. Si falla la firma, no
borra nada. Una vez guardada la intención, el caso desaparece de las listas
normales. Si se interrumpe la limpieza, al arrancar se autentica el registro global
y se reanuda. `/cases deleted` muestra las limpiezas pendientes; Enter reintenta.

Se eliminan los ficheros privados y los registros del caso, incluidos spools,
originales copiados, pruebas, snapshots de skills y ramas de subagentes. Los blobs
compartidos se conservan mientras otro caso los referencie. Se mantienen los
originales externos, otros casos, skills instaladas, configuración y registro
global firmado. Los ficheros de bloqueo permanecen como objetos de coordinación.

## Auditar casos borrados

`/cases deleted` muestra solo lápidas autenticadas: identificador, título, creación
y borrado, último hash de la cadena anterior, recuentos, medidas de almacenamiento
y motivo opcional. No permite recuperar la evidencia. Cada lápida se firma antes
de limpiar y permanece en el registro global.

El inventario distingue bytes de ficheros privados, blobs compartidos y contenido
lógico de la base de datos. **No** garantiza espacio físico liberado: pueden
sobrevivir blobs compartidos y SQLite puede conservar páginas asignadas.

## No es borrado seguro

El borrado es lógico. SSD, snapshots, copias de seguridad y sistemas de ficheros
modernos pueden conservar contenido anterior. Utiliza cifrado completo de disco y
una política de retención adecuada; borrar no garantiza la eliminación física.

Consulta [configuración](configuration.md) para la barra de estado y presupuestos.
