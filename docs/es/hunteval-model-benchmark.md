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
