Traducción de docs/development/hunteval-model-benchmark.md en el commit 050c01156cc3c45f5229306b88051eb22ed68348; si hay diferencias, prevalece la versión en inglés.

# Benchmark manual de modelos con HuntEval

El [arnés de desarrollo](../development/hunteval-model-benchmark.md) prepara #95;
no constituye un ranking publicado. Usa los 18 episodios públicos fijados en el
commit 4cbb555a56bc17cb03b988ad2f15b1374eecf183 y verifica sus SHA-256. Ningún modelo
real se ejecuta en CI. Las respuestas privadas se abren **después de terminar todos
los modelos** y nunca pasan a casos, herramientas o contexto del modelo.

Configura un directorio desechable distinto por modelo mediante `/settings model`,
con su confirmación de salida de datos y clave solo en el keystore. Cierra la TUI.
Clona HuntEval aparte y haz checkout del commit fijado. Crea un JSON privado sin
secretos, con models y, para cada entrada, label, module, model, revision y home;
[el ejemplo inglés](../development/hunteval-model-benchmark.md) muestra la estructura.
El modelo y módulo deben coincidir con la configuración guardada. La revisión es
un dato del operador: usa «no informado» si el proveedor no la revela.

```sh
python3 scripts/hunteval_benchmark.py --hunteval-root <checkout> --models <modelos-privados.json> --binary <irmind-verificado> --output <directorio-nuevo>
```

Solo muestra el plan, sin llamadas. Para autorizar las 18 × número de modelos
posibles ejecuciones con coste:

```sh
python3 scripts/hunteval_benchmark.py --hunteval-root <checkout> --models <modelos-privados.json> --binary <irmind-verificado> --output <directorio-nuevo> --execute
```

Pide la passphrase una vez por llavero file y la transmite por stdin, descriptor 0;
solo se deja vacía con backends exclusivamente del sistema. Las claves de proveedor
las lee IRMind del SecretBackend, nunca el script, el entorno, argumentos o ficheros
del repositorio. No concede aprobaciones ni confirma hallazgos. Cada episodio usa
un turno CLI secuencial del agente principal con el mismo prompt; no mide el flujo
interactivo de subagentes.

Produce report.json, report.md y SHA256SUMS, con fecha UTC, versión y hash del
binario, ID y revisión declarada del modelo, estado por episodio, latencia,
llamadas, tokens y coste estimado en microUSD. Si faltan uso o precios se indica
no disponible, no cero. Los fallos e incumplimientos del formato de respuesta
siguen en el informe, sin convertirse en casos superados ni desaparecer.

La precisión es coincidencias/predicciones y la exhaustividad coincidencias/
esperados de IDs de evento, entidades y ATT&CK. Las predicciones inventadas o
benignas cuentan como falsos positivos. Retrieval mide referencias de origen y
valores completos en resultados crudos firmados, **antes del guard y recorte para
el modelo**: no demuestra qué recibió o atendió el modelo. Si el observador alcanza
su tope, retrieval_complete queda false.

La métrica event_supported_finding_proxy solo comprueba IDs maliciosos y hashes
firmados conocidos. No establece corrección semántica de los hallazgos. Revisa las
afirmaciones y citas en los casos y rellena human_correct_findings y
human_false_positive_findings antes de publicar. Los hallazgos siguen propuestos.
Publica solo resultados saneados con modelo, revisión, fecha, fallos, límites y
método; nunca claves, rutas personales ni diagnósticos crudos. Repite si comparas
modelos no deterministas y no extrapoles estos episodios pequeños a incidentes reales.

## Piloto para estimar duración y coste

Antes de los dieciocho episodios, elige uno por nube. Repite la opción de selección de episodio para
seleccionar un subconjunto sin duplicados; se conserva el orden del corpus
fijado. Revisa primero el plan sin llamadas y añade la opción de ejecución solo después de
aprobar ese gasto. Sin selección explícita siguen ejecutándose los dieciocho.
El informe del piloto indica 3/18, nunca una evaluación completa.

```sh
python3 scripts/hunteval_benchmark.py --hunteval-root <checkout> --models <modelos-privados.json> --binary <irmind-verificado> --output <piloto-nuevo> --episode aws-iam-001 --episode azure-iam-001 --episode gcp-iam-001
```

Por modelo, multiplica por seis la suma de `elapsed_seconds` de sus tres episodios
completados; revisa también 18 veces el mínimo y el máximo. Si todos tienen uso
y precios completos, multiplica por seis la suma de `estimated_cost_microusd`
y divide por un millón para obtener USD. Son extrapolaciones, no límites ni
garantías: rondas, fallos, razonamiento, caché, tamaños y tarifas pueden variar.
Con errores o datos incompletos, el coste permanece no disponible, nunca cero
inventado. No se han hecho llamadas comerciales para preparar la guía; no hay
cifras supuestas por modelo. Conserva versión/revisión, fecha y filas del piloto.

Cada episodio crea su caso: revisa su presupuesto y el techo de la organización.
Una respuesta admitida puede superar el saldo al completarse; la siguiente
petición queda bloqueada hasta ampliar el presupuesto de forma autorizada.
