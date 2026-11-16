# Contrato inicial de contabilidad de caché de prompts

Propuesta concreta del primer incremento del [diseño de contexto](../development/context-cost-design.md).
El [contrato en inglés](../development/context-cache-accounting-contract.md) y
sus [vectores sintéticos](../development/context-cache-accounting-vectors.json)
fijan el alcance; todavía no se implementa ni se afirma un ahorro real.

## Puerto y recibos firmados

Añadir `cache: Option<CacheUsage>` a `ModelUsage` y `UsageEvent`. `input_tokens`
siempre incluye toda la entrada lógica facturada: ordinaria, leída y escrita en
caché, una sola vez. La salida conserva su significado. `CacheUsage` tiene los
campos cerrados `read_input_tokens`, `write_input_tokens` (u64) y
`write_lifetime`: `not-applicable`, `five-minutes`, `one-hour` o `unknown`.
La entrada ordinaria es la resta comprobada de lectura y escritura al total.
Su suma no puede superar la entrada; desconocido se representa con `None`, nunca
con cero inventado. `not-applicable` exige cero escrituras. Una duración mixta
es desconocida y no puede usar la tarifa de cinco minutos. Constructores y
lectura validan estas invariantes.

El miembro opcional se omite si falta: el JSON sin caché mantiene sus bytes.
Cuando existe, `cache` va después de los campos actuales; los campos internos
siguen el orden anterior y las cadenas del enum están fijadas. La respuesta del
hijo y su recibo de uso deben contener el mismo desglose. El compromiso de
liquidación existente autentica esos bytes y la verificación compara también
la caché. No hay evento, marcador de caso, sección de export ni capacidad nueva:
export V8 incluye los mismos registros firmados. Frame, guard, stream y resumen
del hijo mantienen sus límites.

Esta propuesta cambia tipos públicos del puerto y campos firmados: el diseño
general no aprobaba su codificación concreta. Se revisará antes de implementarla;
las notas pre-1.0 indicarán el cambio aditivo de payload y configuración.

## Normalización de proveedores

- OpenAI: `prompt_tokens` ya es inclusivo. `prompt_tokens_details.cached_tokens`
  identifica lectura; no se factura escritura separada. Si falta el detalle,
  el desglose es desconocido.
- DeepSeek: `prompt_tokens` ya es inclusivo. Se usa `prompt_cache_hit_tokens` o
  el detalle documentado, comprobando el contador de fallos y cualquier
  representación duplicada. La escritura separada es estructuralmente cero.
- Anthropic: sumar `input_tokens`, `cache_read_input_tokens` y
  `cache_creation_input_tokens` una sola vez; conservar duración declarada o
  reportada de las escrituras.

Un desglose inconsistente no descarta una respuesta pagada. Si se conoce el total
inclusivo, se conserva con caché y coste diferenciados no disponibles. Si no se
puede conocer ese total (por ejemplo, faltan contadores Anthropic), se guarda la
respuesta con uso desconocido y se conserva la reserva incierta. Desbordamiento
nunca significa saturación ni crédito. Los snapshots acumulativos del stream
son actualizaciones, no facturas distintas; contadores contradictorios o
regresivos indican incertidumbre. No se mezclan mensajes o peticiones distintos.

## Prefijo confiable

El catálogo de herramientas actualmente permitidas mantiene orden canónico de
nombres y esquemas, con instrucciones fijas antes del contexto cambiante.
Anthropic puede marcar el final del sistema confiable y la última herramienta
permitida con `cache_control` de cinco minutos, dentro de sus cuatro puntos.
OpenAI y DeepSeek usan su caché automática: sin precalentamiento ni retención
nueva. Los compatibles no reciben controles no documentados.

La caché nunca conserva una herramienta revocada, añade permisos ni promueve
contenido a system. Los contextos de agente principal e hijos siguen separados.
Cambios de política, alcance, skills, modelo o herramientas afectan a la siguiente
petición. Se mantienen el nonce nuevo por turno e `isolate_untrusted`. No se
incluyen cápsulas históricas, paginación, nueva compactación ni modelo auxiliar.

## Presupuesto, precio y presentación

El presupuesto cobra entrada inclusiva más salida. Los hits no descuentan tokens
lógicos. Las reservas de hijos siguen cubriendo entrada completa y máximo nativo
de salida; admisión entre peticiones, deuda y liquidación única no cambian.
La caché no concede tokens, llamadas, rondas ni bytes.

Añadir tarifas opcionales de lectura y escritura de cinco minutos a los precios
del modelo y a su configuración firmada. Unidades: micro-USD enteros por millón
de tokens. Productos con u128 comprobado y división final por un millón, como
ahora. Cada contador no nulo necesita su tarifa aplicable; duración desconocida o
mixta no se valora. Con escritura estructuralmente cero no se necesita su tarifa.
Si falta un desglose o una tarifa necesarios, el coste figura no disponible.
Si alguna petición no tiene precio, el coste agregado completo tampoco: no se
presenta un subtotal como factura total. Todo precio es una estimación.

`/budget` distingue entrada ordinaria, lectura, escritura y salida, además del
total cobrado. La cobertura parcial se indica explícitamente. El segmento de
caché de la barra muestra contadores conocidos o no disponible, respetando ancho,
prioridades, escape de terminal y NO_COLOR. No se inventan tarifas ni máximos.

## Vectores, pruebas y mediciones

Los vectores fijan JSON de uso canónico y SHA-256. Antes de integrar se añaden
vectores concordantes de respuesta y liquidación de hijo; los actuales sin caché
no cambian. Pruebas: SSE de los tres proveedores, contadores ausentes/cero,
duplicados y contradictorios, sumas imposibles y overflow, precios desconocidos,
contabilidad principal/hijo, discrepancias firmadas, liquidación duplicada,
deuda, export y delimitadores hostiles actuales/antiguos. Un marcador de caché
no puede cambiar la admisión de una herramienta.

Se repiten en release los tres escenarios scripted en el mismo runner y se
publican entrada y prefijos exactos antes/después. Los proveedores automáticos
pueden reutilizarlos ya. No se afirma ahorro de dinero, latencia ni hits
facturados sin medir un proveedor real; no se realiza ninguna llamada comercial
solo para medir el diseño.
