# Coste de contexto, caché de prompts y compactación acotada

Solo diseño. El observador mide peticiones del motor actual; las transformaciones
hipotéticas se calculan fuera del producto. No se implementan marcadores de caché,
nonces nuevos, paginación, umbrales ni modelos auxiliares. Se mantiene la salida
nativa del modelo y la comprobación de presupuesto entre peticiones. No hubo
llamadas a proveedores. La [versión inglesa](../development/context-cost-design.md)
contiene también los enlaces oficiales y las referencias de código.

## 1. Base medida y reproducción

Motor base: `55331ce7dd68acbe1299e50f9548876223e00d19`. Un `LlmPort` scripted
recibe las peticiones reales de ingesta, skills, investigación, compactación y
broker. Informa uso simulado: `ceil(bytes UTF-8 del JSON neutral / 4)` para entrada
y bytes de respuesta / 4 para salida. **No es el tokenizer de ningún proveedor,
ni una cota de admisión, ni una factura real.** Incluye roles, IDs, esquemas,
nonces y mensajes reenviados. No cambia la política por defecto de 25 rondas.

| Escenario | Turnos del analista | Peticiones ordinarias | Compactaciones | Tokens de entrada simulados |
| --- | ---: | ---: | ---: | ---: |
| Conversación de 10 turnos | 10 | 10 | 0 | 73.445 |
| Investigación con skill AWS y 15 rondas útiles | 1 | 15 | 0 | 126.382 |
| Plan Windows/AWS/Kubernetes con tres hijos | 1 | 11 (2 principal + 9 hijos) | 0 | 48.655 |
| Estrés separado: investigación con notas preliminares largas | 1 | 15 | 3 | 183.594 |

Las respuestas de conversación tienen unos 1,6 KB. La investigación carga
`aws-credential-compromise` y hace trece búsquedas locales distintas, con límites
7–19, sobre veinte registros sintéticos. El estrés añade unos 4 KB de notas por
respuesta preliminar. El plan usa el episodio mixto existente y comprueba,
sella y exporta el caso. Las respuestas esperadas quedan fuera del modelo.

Entradas por turno de conversación: **5.061; 5.568; 6.076; 6.583; 7.091; 7.598;
8.106; 8.613; 9.121; 9.628**. En los escenarios de un turno, el total es el de la
tabla. [baseline.json](../development/context-cost-data/baseline.json) contiene
cada petición, actor, turno, componente y contador.
[repeats.json](../development/context-cost-data/repeats.json) registra tres
repeticiones: coinciden los agregados y las estimaciones de prefijo. La repetición sobre esta base de main conserva las cifras de la primera
medición. Las medidas son de build release, no benchmarks de tiempo ni throughput de ingesta.

```sh
sh scripts/context_cost/reproduce.sh target/context-cost/run-1
python3 -B scripts/context_cost/test_analyze.py
sha256sum --check docs/development/context-cost-data/SHA256SUMS
```

Usa un directorio nuevo para cada repetición. Los prompts sintéticos completos
quedan en la traza local; se publican contadores, sin rutas personales ni detalles
de máquina. Los checksums vinculan datos y fuentes del observador. Los IDs, nonces
y el orden de ejecución de hijos pueden variar; la medición ocurre **antes** de
normalizar nada para los cálculos hipotéticos.

## 2. Repetición frente a prefijo reutilizable

| Escenario | Sistema repetido | Catálogo repetido | Mensajes del prefijo idénticos | Techo de prefijo reutilizable |
| --- | ---: | ---: | ---: | ---: |
| 10 turnos | 1.980 | 32.256 | 0 | 33.408 / 73.445 (45,49 %) |
| 15 rondas y skill | 3.080 | 45.019 | 61.965 | 107.776 / 126.382 (85,28 %) |
| Tres hijos | 926 | 20.910 | 7.793 | 29.056 / 48.655 (59,72 %) |
| Estrés | 3.188 | 45.019 | 81.634 | 129.152 / 183.594 (70,35 %) |

Son tokens simulados. Las columnas se solapan: **no se suman**. Sistema y catálogo
repetidos son componentes idénticos enviados antes al mismo actor. El prefijo de
mensajes cuenta mensajes no system iguales al comienzo de la siguiente petición.
La conversación sí reenvía turnos firmados; sus envoltorios nuevos impiden que
ese contador los considere prefijo idéntico.

El simulador coloca herramientas antes de mensajes y busca el prefijo de bytes
más largo entre peticiones anteriores **del mismo actor**. Usa, solo como ejemplo,
un mínimo de 1.024 tokens simulados y bloques de 128. No son reglas universales.
Supone retención perfecta, ausencia de expulsión, marcadores suficientes y rutas
compatibles: los hits reales podrían ser cero. El orden de claves HTTP JSON no
es el orden interno del prompt del proveedor.

Los proveedores automáticos podrían estar aprovechando ya gran parte de un
mismo turno. Estas medidas no demuestran hits ni ahorro real: hoy no conservamos
el desglose de caché. Cargar una skill reduce el catálogo permitido; no se puede
mantener uno más amplio para conservar un hit. Un saludo sigue sin herramientas.

La compactación actual cuenta **48.000 bytes de mensajes y argumentos**, sin el
catálogo, y procesa trozos de 24.000. `raw_records` tiene además un extracto propio
de 2.000 caracteres. Los mayores mensajes Tool observados fueron 2.520 bytes en la
investigación y 4.883 en el plan, incluyendo skills/envolturas. El máximo de
10.000 bytes no significa que todos los resultados ocupen ese tamaño.

## 3. Orden estable y contenido no confiable

Plan de contexto: instrucciones confiables y catálogo permitido; cápsulas de
skills admitidas e historial antiguo inmutable; al final, estado cambiante del
caso, intercambios recientes completos, pregunta y resultados nuevos. El proveedor
puede colocar herramientas antes de system. **Skills, datos del caso, resúmenes y
texto previo del modelo siguen como contenido user/tool UNTRUSTED filtrado, nunca
system.** Las parejas assistant/tool conservan orden y enlaces por ID.

Congela nombres, descripciones, esquemas y orden de herramientas por época de
permisos. Cambiar política, alcance, perfil, modelo o skill invalida la época y su
namespace de caché; nunca conserva capacidades retiradas. Cada hijo mantiene sus
fuentes, contexto e intersección de herramientas. No se mezclan historiales.
Una carga de skill puede invalidar el prefijo una vez; se reutiliza su snapshot
admitido después. Desactivarla o cambiar permisos lo invalida inmediatamente.

### Nonces: conservar el control actual por defecto

El nonce hace impredecible el delimitador al admitir contenido. No concede
permisos ni garantiza que el modelo ignore instrucciones maliciosas. Modelo,
analista, proveedor y un atacante con acceso de observación pueden conocerlo
tras usarlo. Un nonce por caso o sesión sería predecible para evidencia posterior.

`isolate_untrusted` escapa solo los delimitadores de apertura/cierre del nonce
recibido, no todos los históricos. Un nonce anterior dentro de un turno nuevo es
texto literal y no coincide con su envoltorio. Si cada entrada se aísla contra un
nonce de caso reutilizado, los marcadores exactos también se escapan: conocerlo
**no basta para saltarse la función**. Pero elimina la imprevisibilidad de cada
turno y hace persistente una vía que accidentalmente omita aislar. El nonce de
sesión solo acorta esa exposición. Habría que demostrar cobertura de todas las
entradas, normalizaciones y límites de fragmento antes de aprobar esa opción.

Primera mejora segura: mantener nonce nuevo por turno y cachear la cabecera
confiable; dentro del turno, aprovechar el historial anexado. No hace cacheable
el historial reenvuelto entre turnos.

Alternativa posterior, con contrato propio: **cápsulas de admisión inmutables**.
Nonce aleatorio nuevo por bloque admitido; mismos bytes filtrados al reproducir;
escape acotado de todos los marcadores con forma de delimitador, también los
antiguos, tras decodificar, normalizar y concatenar. Guardar hash y versión de
política/guard; cambiarla invalida o regenera la cápsula. Una fuente mutable no
se considera válida por su hash antiguo. La evidencia nueva no hereda el nonce
de otra cápsula ni se importa contenido de otro caso/hijo. Requiere pruebas
hostiles antes de activarse.

El cálculo offline que elimina entropía/reordena **no es seguro para producción**.
Da 56.704 tokens reutilizables en conversación frente a 33.408: 23.296 adicionales
(31,72 % de entrada). No mejora las otras bases y pierde 768 tokens reutilizables
en estrés. Es la estimación de esa disposición, no una prueba de seguridad ni
una promesa de que reordenar siempre ayude. v0.5.1 no cambia nonces.

## 4. Perfiles de caché del proveedor

- **Anthropic:** `cache_control` explícito al final de prefijos estables, hasta
  cuatro puntos; las ampliaciones de retención son opt-in. El lookback documentado
  de veinte posiciones exige cuidar dónde se escribieron entradas anteriores.
  Leer `cache_read_input_tokens` y `cache_creation_input_tokens`.
  [Documentación oficial](https://platform.claude.com/docs/en/build-with-claude/prompt-caching).
- **DeepSeek:** caché automática, persistencia por prefijos y retención best-effort.
  No añadir peticiones de calentamiento. Leer `prompt_cache_hit_tokens`,
  `prompt_cache_miss_tokens` y el alias `prompt_tokens_details.cached_tokens`.
  [Guía](https://api-docs.deepseek.com/guides/kv_cache/) y
  [uso Chat](https://api-docs.deepseek.com/api/create-chat-completion/).
- **OpenAI:** prefijo estable y capacidades por modelo; los perfiles anteriores
  pueden usar `prompt_cache_key`, mientras los nuevos tienen reglas distintas de
  rutas, escrituras y vida útil. El adaptador actual es Chat Completions: no copiar
  parámetros exclusivos de Responses.
  [Guía oficial](https://developers.openai.com/api/docs/guides/prompt-caching).
- **OpenRouter:** depende del modelo y del proveedor elegido. Leer
  `prompt_tokens_details.cached_tokens` y `cache_write_tokens`; conservar solo
  marcadores admitidos. No cambiar proveedor ni residencia para lograr hits.
  [Guía oficial](https://openrouter.ai/docs/guides/best-practices/prompt-caching).
- **Compatibles/locales:** soporte desconocido por defecto. No inventar campos,
  hits ni precios; el servidor puede tener caché propia sin controles del cliente.

Namespace opaco por caso/perfil/actor donde se admita, sin títulos, evidencia,
credenciales o rutas en la clave. No es una frontera de acceso. No importar datos
de otros casos. Sin warm-up, keepalive, reintento de peticiones facturadas ambiguas,
retención ampliada o segundo endpoint sin configuración explícita. El sello del
caso no puede borrar la caché del proveedor.

## 5. Uso firmado y /budget

Normalizar categorías disjuntas: **entrada normal, lectura de caché, escritura y
salida**, conservando modelo, endpoint, disponibilidad y vida de la escritura.
En OpenAI/DeepSeek/OpenRouter la caché suele ser un subconjunto del total de
entrada: no sumarla dos veces. En Anthropic:
`entrada_total = input_tokens + cache_read_input_tokens + cache_creation_input_tokens`.
Ausente significa desconocido, no cero. Los snapshots de uso del streaming son
actualizaciones, no facturas acumulables. Un desglose incoherente impide estimar
precio, pero no elimina un total conocido ni la respuesta pagada.

El presupuesto cobra **cada token lógico de entrada una vez**, también reads y
writes, más salida. Los multiplicadores cambian dinero, no la identidad del token:
un read a precio 0,1× no convierte diez tokens en uno de presupuesto. La reserva
del hijo cubre toda la entrada, sin suponer hits. Se mantienen admisión entre
peticiones, liquidación de exceso y deuda sin capacidad.

Con tarifas completas: `normal * tarifa_entrada + read * tarifa_read + write * tarifa_write + salida * tarifa_salida`.
Las escrituras pueden costar más. Sin tarifas/desglose suficientes, coste no
disponible; nunca cero inventado. /budget muestra categorías, total cobrado y
estimación conocida; la barra de estado sigue compacta.

Ampliar `ModelUsage`/`UsageEvent`, informes de ramas y vínculos firmados requiere
contrato concreto y nuevos vectores. Los lectores actuales de uso firmado rechazan campos
extra: no añadir claves de JSON sin revisar el esquema. El uso desconocido no
libera una reserva pendiente. Este documento no aprueba ese formato.

## 6. Compactación por perfil

Perfil de contexto separado del de salida: ventana documentada/declarada,
capacidad de conteo/tokenizer, procedencia y umbral del analista. En
`/settings model`: **Ventana de contexto**, **Compactar al** y **Objetivo después
de compactar**, separados del máximo de salida. Cambios como configuración firmada;
ninguna herramienta del modelo puede aplicarlos. El método aditivo propuesto
`LlmPort::context_profile()` devuelve desconocido por defecto. Antes de implementarlo,
el contrato concretará rangos enteros, validación de ambos umbrales, framing y
techos; no inferir ventana a partir del máximo de salida. Techos prudentes
propuestos: **cota superior de 128.000 tokens de entrada y 512.000 bytes del JSON
completo**, con herramientas y envoltorios; gana la ventana inferior del proveedor.
Mantener margen y máximo nativo de salida. Un perfil incompatible produce error
accionable, no una respuesta más corta ni la retirada de instrucciones de seguridad.

Conteo exacto compatible donde exista; si no hay tokenizer aprobado, cota
conservadora de bytes/framing. La estimación de cuatro bytes no es una garantía
de admisión. Dependencias de tokenizer o llamadas de conteo necesitan revisión.
Con ventana desconocida, conservar la conducta conservadora actual y explicar
cómo configurar el perfil. Candidato: disparar al 75 % y bajar al 45 % después,
para evitar compactaciones sucesivas en el mismo borde.

Una petición sobre un bloque grande solo si cabe en la ventana, bytes y presupuesto
del resumidor; en caso contrario, lotes jerárquicos acotados. Conservar intercambios
recientes completos, referencias exactas, hallazgos confirmados y preguntas
pendientes; validar citas con el caso. La respuesta completa filtrada sigue firmada
dentro del límite de seguridad. Acotar el resumen usado como contexto posterior
no recorta la respuesta pagada que se conserva.

Ahorro de compactación en las tres bases: **cero**. En estrés son tres peticiones
en dos episodios, 12.317 tokens de entrada. Unir el pequeño resto al bloque previo,
suponiendo el mismo resumen scripted, deja dos peticiones y ahorra **154 tokens
(0,084 % del total)**. Una ventana mayor puede reenviar más historial y gastar más;
no es una optimización de coste por sí sola. Conservar citas por una instrucción
al modelo no demuestra completitud semántica: hacen falta pruebas y validación.

## 7. Resúmenes de herramientas y páginas

La mayoría de resultados ordinarios se guardan completos con hash de evidencia y
referencia `ToolResult` firmada antes del extracto para el modelo. Reutilizar esos
bytes inmutables, sin repetir consultas. Skills y resúmenes de hijos conservan su
procedencia propia; no sustituirlos silenciosamente.

Proponer resumen tipado con cobertura, truncado, hashes, IDs útiles y referencia,
con presupuesto inicial de unos 1 KiB más 160 bytes de metadatos. Herramienta Read
para una página de ese resultado exacto. Cursor vinculado a caso, hash, llamada
original autorizada, fuentes, orden y época. Comprobar alcance/techo actuales;
un hash no concede permiso. Cada página consume llamada, es cancelable y conserva
taint, procedencia y guard. Un cursor local no oculta lecturas remotas nuevas.

Mantener adquisición de 5 MB, entrada del guard de 1 MB y política de resultado
para modelo de 10.000 bytes. Primera versión: solo texto lógico completo que se
pueda filtrar con el guard actual. Objetos mayores/binarios no se exponen por
trozos para sortear el límite. No filtrar secretos partidos entre páginas ni
crear retención, páginas o llamadas sin límite. La lectura local acotada puede
necesitar un puerto; vocabulario, autorización y cursor requieren contrato previo.

La hipótesis **solo de tamaño**, sin páginas adicionales, ahorra 8.055 tokens
(6,37 %) en investigación, 6.810 (3,71 %) en estrés y cero en los otros escenarios.
Excluye skills y resúmenes delegados y no demuestra que el resumen sea útil.
En el máximo de 10 KB, 1,18 KB evita hasta alrededor del 88 % de bytes de *ese
resultado*, no de todo el caso. Si el 25 % de trece resultados requiere otro turno,
cuatro peticiones con contexto completo pueden superar los 8.055 tokens ahorrados.
Medir demanda de páginas 0/25/100 % y calidad/citas antes de elegir un valor por
defecto. Una referencia no permite afirmar que el modelo leyó la evidencia.

## 8. Modelo auxiliar opcional

Sección **Modelo auxiliar** en `/settings model`, con el flujo de proveedor, URL,
modelo y credencial enmascarada. Perfil firmado para resumir/compactar, desactivado por defecto; sin él se usa el
principal. Proveedor, URL, modelo, capacidades, referencia del SecretBackend y rol
son explícitos. Otro endpoint remoto exige confirmación de salida de datos propia;
sin claves ambientales ni fallback silencioso. Resumir sigue sin herramientas,
con guard y modelo/uso reales firmados. Modelo opcional del hijo visible en el plan
y congelado antes de reservar; no cambia su presupuesto ni herramientas en marcha.

Cambiar modelo no ahorra **tokens lógicos**. A mitad de tarifa de entrada, los
resúmenes ahorrarían 0 % en las bases y 3,35 % en estrés, sin contar diferencias de
salida/tarifa/caché. Los hijos consumen 37.795 / 48.655 tokens de entrada: a mitad
de precio, techo de reducción del coste de entrada del 38,84 %. Son sensibilidades,
no modelos recomendados ni facturas observadas. La caché del segundo modelo está
fría y puede perderse calidad. Registro de perfiles, configuración y contabilidad
por petición necesitan revisión.

## 9. Orden, esfuerzo y criterios de salida

| Orden | Propuesta | Oportunidad medida | Esfuerzo y complejidad |
| --- | --- | --- | --- |
| 0 | Normalizar uso y mostrar caché | Sin ahorro directo; permite conocer la factura | Medio: adaptadores, recibos, verificador y TUI |
| 1 | Cachear cabecera permitida y anexado elegible | Precio de entrada ilustrativo: −40,66/32,61/33,75 % en las tres bases | Bajo/medio después de contabilidad; el proveedor automático podría hacerlo ya mejor |
| 2 | Resumen y páginas autorizadas | 0/6,37/0 % de tokens sin páginas extra | Medio/alto: referencias, guard, permisos y evaluación de calidad |
| 3 | Umbrales por perfil y bloques mayores | Cero en bases; 154 tokens y una petición en estrés | Medio; más contexto puede aumentar coste |
| 4 | Cápsulas históricas/skills inmutables | 23.296 tokens reutilizables adicionales optimistas en conversación | Alto: contrato de nonce/escape, procedencia, protocolo e invalidación |
| 5 | Resumidor auxiliar y modelo opcional de hijos | 0 % de resumen base; 3,35 % de entrada en estrés a mitad de precio | Medio/alto: perfil/egreso, caché fría, calidad y reservas |

La ilustración de cabecera usa entrada normal 1×, reads 0,1×, writes 1,25×,
escritura inicial fría y ninguna expulsión. No reduce tokens enviados ni estima
el ahorro adicional frente a una caché automática ya caliente. Las reglas y
precios reales pueden eliminar el ahorro.

Tras revisar el diseño: contratos de puertos/uso y vectores; contabilidad y
marcadores con streams sintéticos; prefijo sin cambiar nonces; después páginas,
cápsulas y perfiles auxiliares revisados por separado. Ningún hit especulativo
financia reservas ni reaparece un tope de salida propio.

Pruebas: uso ausente/incoherente, snapshots repetidos, normalización reads/writes,
expulsión/rutas, nonce antiguo malicioso, evidencia alterada, separación de roles,
parejas tool válidas, fuentes de hijos, secretos entre páginas, presupuesto agotado
y export completo. Calidad y uso pagado reales solo en una evaluación explícita
del analista.

## Alcance de implementación aprobado

El primer incremento implementa la contabilidad de caché del proveedor y los
marcadores del prefijo confiable según [el contrato](context-cache-accounting-contract.md).
Las cápsulas inmutables y cambios de nonce, resúmenes y paginación de resultados,
perfiles de contexto/compactación por modelo y el modelo auxiliar quedan aplazados
hasta después del lanzamiento público. Se mantienen los nonces por turno y el
aislamiento del contenido no confiable.

## Mediciones release del primer incremento

Tres repeticiones antes y después en el mismo runner reproducen los mismos
valores. El observador usa el motor de producción y bytes JSON UTF-8 / 4,
redondeando hacia arriba; no simula facturas ni llama a proveedores comerciales.

| Escenario | Peticiones | Entrada antes / después | Techo de prefijo reutilizable |
| --- | ---: | ---: | ---: |
| Conversación de diez turnos | 10 | 73.445 / 73.445 | 33.408 (45,49 %) |
| Investigación con skill, 15 rondas | 15 | 126.382 / 126.382 | 107.776 (85,28 %) |
| Tres subagentes | 11 | 48.655 / 48.655 | 29.056 (59,72 %) |

Este incremento añade marcadores nativos de Anthropic y contadores del proveedor;
no reduce el contexto enviado. Los proveedores automáticos podrían estar
reutilizando ya ese prefijo. Los aciertos, la latencia y el ahorro facturado
siguen sin medir hasta una evaluación explícita del analista.
[Mediciones](../development/context-cost-data/cache-phase1-measurements.json) y
[vector de liquidación del hijo](../development/context-cost-data/child-cache-settlement.json),
cubiertos por el fichero de checksums.
