Traducción de docs/development/model-output-contract.md en el commit da9fe0dea299241944e2a14920b2fcf65df0c491; si hay diferencias, prevalece la versión en inglés.

# Respuestas completas y presupuesto entre peticiones

Propuesta de contrato; todavía no cambia código ni bytes firmados. La [versión
en inglés](../development/model-output-contract.md) contiene las referencias de
código y de proveedores. Esta propuesta separa la política de generación decidida
por el analista de los contratos necesarios para implementarla sin quitar
controles.

## Política de generación

Agente principal, hijos, resúmenes y compactación no reciben un máximo de salida
inferior al del modelo. Con un máximo conocido se envía el valor real en el campo
que soporte el proveedor. Si el máximo es desconocido y el campo opcional, se
omite; si es obligatorio, se pide configurarlo en `/settings model` antes de hacer
la llamada. La ventana de contexto no es el máximo de salida, ni el valor por
defecto del proveedor prueba su máximo.

El presupuesto se comprueba antes de una petición. Con saldo positivo, la
petición admitida puede terminar aunque su uso informado exceda ese saldo. Se
conservan la respuesta completa filtrada y el consumo, y la siguiente petición
se bloquea con una explicación de `/budget`. El saldo negativo se calcula desde
contadores positivos con aritmética comprobada, sin desbordar una resta sin
signo. El techo de la organización sigue decidiendo qué asignación puede firmar
el analista; el modelo no puede ampliarla.

## Estado actual

- El principal pide 2.048 tokens y resta otra reserva de 512 al saldo.
- Resúmenes y compactación piden 512 tokens.
- Los adaptadores vuelven a limitar la salida al saldo del caso.
- Un hijo reserva entrada más el menor entre 2.048 y su saldo disponible.
- Una liquidación de hijo superior a la reserva o a su asignación se rechaza
  durante la verificación. El resultado actual puede perder el texto recibido.
- El texto del hijo se reduce a 16 KiB; también hay límites de bytes en la
  colección del streaming, el transporte, el guard y los frames firmados.

Quitar una constante sin adaptar el resto no garantiza una respuesta completa.

## Perfil tipado del modelo y puerto

Se propone añadir `LlmPort::output_profile()` con un valor desconocido por defecto.
`ModelOutputProfile` declara `maximum_output_tokens: Option<NonZeroU32>` y un enum
`OutputParameterRequirement::{Optional, Required}`. Cada adaptador conserva la
propiedad del dialecto y del nombre del parámetro HTTP.

El perfil procede de una identidad exacta documentada o de un máximo declarado
por el analista en Ajustes. La consulta de modelos es una acción explícita de
configuración, no una llamada extra antes de cada inferencia. Sus metadatos son
no confiables y se validan antes de la admisión firmada. El perfil queda congelado
para la petición; un cambio incompatible invalida la previsualización de un plan.

`CompletionRequest` deja de llevar el saldo del caso al adaptador. Su máximo
numérico propio se sustituye por una decisión explícita de máximo del proveedor
o de omisión; no se usa cero ni un entero enorme como valor mágico. Este cambio
del contrato de aplicación/adaptadores necesita revisión expresa.

Un máximo opcional desconocido permite una petición del principal sin parámetro.
No permite reservar un hijo: ese hijo espera a que se conozca o declare el máximo.
La TUI indica qué falta. Nunca inventa 2.048 tokens ni amplía una porción del hijo
sin la admisión correspondiente.

OpenAI documenta `max_completion_tokens` opcional, incluido el razonamiento.
DeepSeek documenta `max_tokens` opcional y metadatos de modelos con máximos;
OpenRouter exige resolver las capacidades del modelo/proveedor y mantiene los
valores omitidos sin sustituirlos por uno propio. Anthropic necesita `max_tokens`
para generar. Los compatibles/locales usan su perfil o configuración explícita.
La tabla inglesa enlaza las fuentes oficiales; no se fijan números para familias
enteras ni se activa ninguna herramienta del servidor. El razonamiento no se
reenvía ni se muestra como respuesta; su uso se contabiliza si se informa.

## Reserva y liquidación de los subagentes

La admisión normal conserva el contrato: entrada acotada más máximo real del
modelo deben caber en la asignación del hijo, las reservas existentes y la
admisión del caso. Si no caben, no empieza esa petición. El plan completo conserva
el umbral firmado del 25 %, sus seis tipos y la intersección de herramientas y
fuentes. Una petición en curso no se cancela solo porque otra consuma el saldo.

Hay una decisión de contrato concreta: hoy el verificador rechaza que el consumo
informado supere la reserva o la porción del hijo. Reservar el máximo real elimina
el recorte ordinario de 2.048, pero no demuestra que un proveedor compatible o la
entrada oculta añadida por su servidor nunca superen la estimación.

La enmienda propuesta permite liquidar **tokens informados** superiores a la
reserva únicamente para una petición de modelo ya admitida. El evento de uso,
el prefijo de respuesta comprometido y la liquidación única deben coincidir.
Se registra el exceso y se bloquean peticiones nuevas cuando no haya saldo
admisible del caso o del hijo. No se recorta el consumo, se descarta la respuesta,
se devuelve capacidad gastada ni se reintenta una llamada ya facturada.

El uso desconocido conserva la reserva conservadora actual. Un informe inválido
o imposible de representar queda sin resolver explícitamente, nunca como cero
ni como permiso para seguir. La excepción solo afecta a tokens del modelo;
llamadas, rondas, bytes de nube, aprobaciones, fuentes, plazos y cancelación no
cambian. El verificador rechaza duplicados, excesos sin su informe comprometido,
actores/checkpoints/peticiones distintos, devoluciones de gasto y nuevas
peticiones iniciadas sin saldo.

Los campos numéricos de los registros actuales permiten representar esta regla
sin cambiar su disposición de bytes; sí cambia su interpretación y los
invariantes del verificador. Por eso se requiere la decisión antes de
implementarla y revisar los vectores de contabilidad afectados.

## Respuestas completas dentro de los límites de seguridad actuales

Se conservan el frame firmado de **1 MiB**, el límite del guard de **1.000.000
bytes** y el del stream de **2.000.000 bytes**. Se eleva la vista previa de
200.000 bytes para que no recorte una respuesta que quepa en esos límites.
No se añade almacenamiento segmentado, spool ni otra representación de exportación.

La respuesta filtrada se conserva y firma completa si cabe en el frame, contando
metadatos y sobrecoste de codificación. Si no cabe, se conserva el mayor prefijo
UTF-8 válido que permita el frame y se indica claramente «Recortada por el límite
de seguridad de IRMind». No se presenta como completa ni se confunde con el
máximo del proveedor. El guard sigue validando todo texto mostrado o conservado.

Se prueba una respuesta sintética representativa de 128.000 tokens, su firma y
exportación, además del caso que excede el frame. Tokens y bytes no son equivalentes:
una respuesta con muchos bytes por token puede alcanzar el límite de seguridad.
El resumen de 16 KiB del hijo al principal se mantiene; la respuesta completa queda
en la rama, dentro del mismo límite de frame. Cancelación, plazos y fallos de
recursos siguen siendo interrupciones visibles.

### Capacidad del payload de rama

El validador actual añade un límite de 256 KiB por payload, independiente del
frame de 1 MiB. La respuesta representativa de 640.000 bytes cabe en el frame y
en el guard, pero se rechaza en la rama. Se propone usar, solo para `ModelReply`,
la capacidad disponible en su frame de 1 MiB. Los demás payloads mantienen
256 KiB. No cambian los límites del frame, chunk, total de rama, transporte ni
guard; la respuesta y sus metadatos finales deben caber juntos. La prueba del
hijo largo muestra esta restricción adicional.

## Una continuación automática

Con `length`/`max_tokens` nativos, la TUI informa de que el modelo alcanzó su
máximo. Si hay saldo, reserva y ronda disponibles, se envía una sola continuación
sin herramientas, dentro de la misma tarjeta lógica. Se registran ambas
peticiones y sus consumos aunque la segunda también termine por límite. No se
reproduce razonamiento ni se ejecutan argumentos de herramienta incompletos.

El historial estructurado contiene la respuesta parcial ya filtrada y una
instrucción fija de continuación. Se reutiliza el contexto una vez, sin añadir
una segunda copia; el proveedor puede volver a facturarlo y se registra. Nada de
evidencia pasa a `system`. `/continue` queda para rondas o presupuesto agotados;
no se crea un bucle ilimitado de reintentos ni se borra texto para unir partes.

## Orden y pruebas

1. Revisar el puerto de capacidades y la excepción de liquidación de tokens.
2. Conservar los límites de stream, guard y frame; revisar los vectores de
   contabilidad nuevos y las pruebas de recorte de seguridad.
3. Implementar perfiles, Ajustes, admisión entre peticiones, retención íntegra y
   continuación única. No entregar solo el cambio de 2.048 dejando recortes atrás.
4. Probar respuestas largas, exceso con respuesta completada, siguiente petición
   bloqueada, máximo del hijo conocido/desconocido e insuficiente, liquidaciones
   válidas y falsas, continuación única y segundo corte, campo obligatorio sin
   máximo conocido y los dialectos de cada proveedor.
5. Cubrir principal, hijo, resumen, compactación, secretos entre segmentos,
   cancelación/disco, verificación/sello/export y una sola tarjeta continua.
   Ningún proveedor real ni clave se usa en CI.
6. Actualizar configuration en ambos idiomas y las notas de formato/release que
   correspondan. El lanzamiento público se retoma después de esta prioridad.
