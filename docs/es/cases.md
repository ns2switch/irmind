Traducción de docs/cases.md; si hay diferencias, prevalece la versión en inglés.

# Casos y borrado lógico

Un caso contiene su cadena firmada, referencias a evidencia, grafo Parquet,
snapshots de skills y ramas de subagentes. Los originales externos al directorio
de datos permanecen en sus ubicaciones registradas. Sellar hace inmutable el caso.

## Casos y exportaciones de una versión anterior

La versión 0.7 usa el marcador de caso 6, artefactos Parquet V3 con mapeo y la
exportación V10. Usa la versión que creó el caso para abrirlo, verificarlo o
exportarlo. Para usar la versión actual, verifica los originales con la versión
que creó el caso e ingiérelos en un caso nuevo. El caso original conserva sus
aprobaciones, hallazgos confirmados y sello.

## Publicar un informe firmado

En un caso abierto, usa `/report preview en` o `/report preview es`. El informe
incluye solo hallazgos que hayas confirmado y que apunten a una fila exacta de
evidencia. Consulta la sección de cobertura para ver la disponibilidad de las
fuentes, los huecos de las skills y las consultas que alcanzaron su límite.

Usa `/report save md en` o `/report save pdf es` para firmar y conservar
el documento en el caso. El comando muestra su SHA-256. Tras sellar el caso, la
exportación V10 incluye sus informes publicados. `/verify` comprueba la firma,
las filas de origen, la cobertura y los bytes del documento. Para publicar otra
revisión, usa un caso abierto.

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
