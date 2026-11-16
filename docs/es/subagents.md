# Investigaciones en paralelo

[English](../subagents.md)

Los subagentes dividen una investigación en tareas acotadas. Usan el modelo que
ya ha elegido el analista; no activan proveedores automáticamente. Un saludo o
una pregunta sencilla no necesita delegación.

## Revisar un plan

Pide al agente que investigue el caso o que reparta una investigación concreta
entre las fuentes pertinentes. Antes de empezar, IRMind muestra las tareas, sus
tipos incluidos, los nombres firmados de fuentes con hashes abreviados y los
tokens y llamadas reservados. Los conjuntos grandes muestran su tamaño y las
primeras dieciséis fuentes.

Si el plan reserva **más del 25 %** de los tokens o llamadas restantes del caso,
exige **Start** con firma del analista. Elige Start o Cancel con flechas y Enter,
o escribe el número y pulsa Enter. Esc cancela. Por debajo o exactamente en el
umbral, empieza después de mostrar la vista previa. En `/settings preferences`,
activa **Confirm all subagent plans** para exigir Start en todos los planes. La
preferencia queda firmada y solo el analista puede cambiarla.

Hay seis tipos incluidos: triaje, nube, endpoint, red, Kubernetes e inteligencia
de amenazas. Cada uno tiene un catálogo fijo de herramientas y skills. Esta
versión no incluye tipos comunitarios ni límites de presupuesto en dinero.

## Recuperación tras una interrupción

Un cierre brusco puede dejar un plan pendiente de revisión o una rama sin acabar.
Cierra primero las otras sesiones de IRMind de ese caso. Al reabrirlo, detén
cualquier turno con `/pause` y espera a que termine; después usa
`/subagents recover`. Revisa la explicación y confirma: Cancelar está
preseleccionado y Esc no cambia nada. Los casos sellados siguen siendo de solo
lectura.

Se usa la reconciliación firmada existente: conserva el trabajo terminado y las
reservas de uso incierto, sin repetir peticiones al modelo ni efectos de
herramientas. No reanuda hijos ni aprueba sus solicitudes. Ejecuta `/verify`.
Una segunda recuperación informa de cero planes si no queda ninguno. El
presupuesto retenido y las aprobaciones habituales siguen aplicándose a nuevos
turnos y al sello.

## Seguir y cancelar tareas

`/subagents` muestra el estado, actividad, consumo y cobertura de las tareas.
Las flechas seleccionan una tarea, Enter abre sus detalles y Esc vuelve a la
conversación. `/subagents cancel <task>` cancela una tarea usando un identificador
único del panel, de al menos ocho caracteres. `/pause` cancela la investigación
y sus hijos. Se conservan el trabajo terminado y el consumo incurrido.

El motor interactivo ejecuta hasta dos peticiones de modelo hijas en paralelo.
Mientras una espera aprobación, sus hermanas pueden continuar. Resuelve su
tarjeta o usa `/approve`, `/deny` o `/edit`; la decisión regresa a la tarea activa.
Una solicitud de una tarea terminada se puede denegar, pero no ejecuta nada en
el padre. Los hijos no aprueban solicitudes, cambian ajustes, amplían presupuestos
ni crean otros subagentes. Solo el analista confirma hallazgos.

## Fuentes, presupuestos y resultados parciales

Cada tarea recibe un subconjunto congelado de fuentes firmadas y, cuando se
asigna expresamente, un alcance remoto más estrecho. No puede consultar las
fuentes de sus hermanas ni recurrir a una consulta sin restricciones. Una fuente
adquirida queda disponible para su tarea tras firmar el decodificador, mapeo,
artefactos y recibo atribuido. Descargar objetos exige un listado previo de esa
misma tarea, versión o ETag fijado, reserva de bytes y la aprobación de
transferencia que exija la política. Usa el spool privado del caso, con borrado
automático. Esta versión no permite consultas SIEM de instancia en los hijos.

El tipo, las skills del padre y del hijo, el caso y la política de la organización
restringen las herramientas efectivas. La inteligencia externa exige un indicador
observado en un original verificado asignado y la aprobación firmada de salida
de datos. Skills y resultados siguen pasando por el guard y siendo UNTRUSTED,
aunque estén firmados.

`/budget` muestra la asignación compartida del caso. Los tokens, llamadas y bytes
de nube consumen esa asignación y los límites propios; las rondas consumen también
el límite del turno padre. El uso desconocido del proveedor queda reservado.
El coste es una estimación cuando hay consumo y precios, o figura no disponible.

Muestreo, expansión, plazos, límites de resultados y falta de cobertura producen
resultados parciales explícitos. También los adaptadores remotos que no acreditan
completitud. Un fallo nunca da paso a una lectura más amplia. El agente principal
recibe un resumen filtrado con las carencias, sin poder quitar la marca parcial.

## Verificación y exportación

Cada hijo firma una rama con la clave Agent. El caso registra checkpoints acotados
y fusiona resultados en orden determinista de tareas. `/verify`, `/seal` y
`/export` autentican ramas, aprobaciones, reservas y resultados terminales. Export
V8 incluye las ramas y pruebas de catálogo necesarias para verificar sin conexión.
Al reabrir, se conserva y cierra el trabajo interrumpido sin repetir efectos remotos.

La versión 0.5 usa marcador de caso 4 y export V8. Conserva el ejecutable creador
para casos anteriores o reingiere originales verificados en un caso nuevo; abrir
no migra. Consulta [configuración](configuration.md), el
[contrato de formato](subagents-format-contract.md) y la
[política de versiones](../development/case-migration.md).
