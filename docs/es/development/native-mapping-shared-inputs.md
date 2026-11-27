# Entradas compartidas en la identidad de los mapeos nativos

[English](../../development/native-mapping-shared-inputs.md)

**Estado.** Propuesta para v0.9. Se mantienen la receta V2 y los formatos firmados publicados.

El inventario firmado de v0.8.0-alpha.1 registra 95 grafos de producción,
correspondientes a 19 mapeos en cinco destinos. La intersección por tipo y
ruta lógica contiene 105 ficheros versionados y una ruta lógica generada
comunes a todos. El [inventario detallado](../../development/native-mapping-shared-inputs.md#measured-closure)
enumera los ficheros exactos. El manifiesto también compromete los paquetes,
las features efectivas, los checksums del registro y la configuración de
compilación. La ruta generada `outputs/private.rs` se identifica por unidad,
digest y máscara de destinos.

Desde v0.7.4 cambiaron cinco rutas comunes. Son las raíces de los tipos de
auditoría y del manifiesto de custodia en el dominio y, en los contratos de
mapeo, la validación del manifiesto, la raíz del módulo y la construcción
compartida de roles. Cambiaron las 19 identidades. ECS y OCSF también
cambiaron sus propios ficheros. El inventario de la etiqueta coincide byte a
byte con el del ensayo. [Inventario firmado](https://github.com/ns2switch/irmind/releases/download/v0.8.0-alpha.1/NATIVE-MAPPING-INPUTS.json).

## Reducir el cierre en v0.9

Concentrar en una base estable los registros de origen, los tipos y códigos
de CommonEvent, las identidades, los serializadores y las validaciones que
necesite el mapeo. Separar el registro de auditoría, la política, las
aprobaciones, las skills y los recibos de sello o de disposición física cuando
el grafo de dependencias lo permita. Mantener los roles de ECS y OCSF en
una unidad que solo compilen sus consumidores si se confirma ese alcance.
Usar el cierre que observa Cargo para seguir comprometiendo los ficheros y
generadores que se compilan.

Medir primero el cierre por destino. Comprobar con los vectores que la
serialización, los ámbitos de entidades y la custodia se conservan, con y sin
`preserve_order`. Una edición de la auditoría del caso, de skills o de
disposición física debe dejar estables las identidades. Un cambio alcanzable
y una feature de producción deben cambiar las identidades dependientes.
Comparar los cinco destinos, el tiempo en frío y el tamaño del binario.

La separación cambiará las identidades una vez al cambiar el grafo.
Si se preservan los bytes canónicos, el manifiesto V2 y los sobres firmados
pueden conservar sus formatos. Presentar el límite de paquetes, los vectores
y las notas de actualización antes de implementar.
