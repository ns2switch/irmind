Traducción de docs/development/real-validation.md en el commit 050c01156cc3c45f5229306b88051eb22ed68348; si hay diferencias, prevalece la versión en inglés.

# Validación con servicios reales en unas dos horas

Recorrido para el analista con la versión preliminar verificada bajo prueba, Elasticsearch local y un
modelo elegido explícitamente. Usa solo las muestras públicas de laboratorio
fijadas; no se incorporan datasets al repositorio. Este recorrido puede aportar
el resultado que falta para [#63](https://github.com/ns2switch/irmind/issues/63) y los
pasos de H5 pendientes en [validación manual](manual-validation.md). No marques
ningún paso como observado antes de ejecutarlo y registrar su resultado.

## 0–20 minutos: instalación y laboratorio desechable

Verifica binario, auxiliar, checksums firmados y attestations con la
[guía de plataformas](platforms.md). Anota versión, commit, sistema y terminal.
Necesitas Docker Compose v2, Python 3.11+, unos 4 GB de RAM y al menos 5 GB
libres. El laboratorio acotado usa umbrales absolutos de espacio libre: 2 GB
para el umbral bajo, 1 GB para el alto y 512 MB para el de inundación. La
protección de disco sigue activada.
Desde el checkout revisado:

```sh
python3 tools/real-validation/lab.py prepare
docker compose --env-file target/real-validation/compose.env -f tools/real-validation/compose.yml up -d
```

Elige una contraseña de administrador desechable de al menos 16 caracteres; la
entrada está oculta. La imagen Elasticsearch 9.5.6 está fijada por digest para
amd64 y arm64. El contenedor escucha solo en `127.0.0.1:9200`, con TLS, sin red
saliente. El servicio de certificados crea una CA local y un certificado con SAN
para localhost, es y 127.0.0.1. No reutilices la CA ni la contraseña. Copia solo
el certificado público:

```sh
docker compose --env-file target/real-validation/compose.env -f tools/real-validation/compose.yml cp es:/usr/share/elasticsearch/config/certs/ca/ca.crt target/real-validation/ca.crt
curl --cacert target/real-validation/ca.crt -u elastic https://localhost:9200
```

curl pide la contraseña. Espera si el servicio aún está arrancando. Sin la CA la
verificación debe fallar; no uses la opción que desactiva TLS. Registra ambos
resultados y nunca desactives la comprobación de nombre de host.

Algunas versiones de Docker no publican puertos de una red `internal: true`.
Si `docker compose ... port es 9200` no muestra una asignación válida y la
conexión a localhost se rechaza, conserva la red interna e inicia este
reenviador opcional de desarrollo en otro terminal:

```sh
python3 tools/real-validation/port_forward.py
```

Solo escucha en `127.0.0.1:9200` y transmite bytes sin interpretarlos mediante
el servicio Compose a su puerto de loopback. TLS, la comprobación de nombre,
las credenciales y la CA se siguen verificando entre el cliente y Elasticsearch.
El contenedor no obtiene salida a la red. El auxiliar rechaza un puerto ocupado,
limita a ocho las conexiones concurrentes y a 60 segundos cada conexión.
Detenlo con Ctrl+C al limpiar el laboratorio. Es una herramienta de desarrollo,
no una parte de IRMind.


## 20–40 minutos: muestras fijadas y carga

```sh
python3 tools/real-validation/lab.py fetch
python3 tools/real-validation/lab.py load --windows-utc-offset +00:00
```

Confirma tú el offset del export de Windows: +00:00 es una interpretación explícita
del laboratorio, no un dato descubierto. El cargador conserva texto original, hash,
identidad de proyección y offset confirmado. Carga como máximo 500 documentos en
`irmind-validation-events`; una segunda carga falla en vez de sobrescribir.

El [manifiesto](../../tools/real-validation/datasets.json) fija commit, URL, tamaño y
SHA-256 de un export AWS y otro de Windows de Splunk attack_data (Apache-2.0), y
un EVTX pequeño de EVTX-ATTACK-SAMPLES (GPL-3.0). El descargador comprueba los bytes
completos de Git LFS, no solo el puntero. Nunca ejecuta contenido descargado.
El cargador es una proyección ECS limitada al laboratorio, no un conversor general:
los resultados explícitos de login AWS se mapean; Windows mantiene resultado
unknown. El EVTX se ingiere por separado con el auxiliar aislado de IRMind.

Crea una API key de cuatro horas, en un fichero privado **fuera del checkout**:

```sh
python3 tools/real-validation/lab.py create-key --key-output ../irmind-lab-key.txt
```

Comprueba sus permisos según tu sistema, copia el valor al formulario de secretos
de IRMind y borra esa copia de trabajo. Solo tiene read y view_index_metadata sobre
el índice concreto; ningún permiso de escritura ni de clúster. La contraseña de
administrador solo se usa en estos auxiliares de desarrollo.

## 40–60 minutos: conector y modelo

Ejecuta `irmind --home <directorio-desechable>` y completa el asistente con file.
En `/settings connectors`, configura Elastic:

| Campo | Valor |
| --- | --- |
| URL | `https://localhost:9200` |
| Source ID | `elastic-lab` |
| Indices | `irmind-validation-events` |
| Account field | `labels.validation_account` |
| Alert space | `default`; este laboratorio no carga alertas |
| CA PEM | Certificado público `target/real-validation/ca.crt` |
| API key | Solo en Llavero y credenciales de `/settings` |

Compara la huella de la CA con SHA-256 calculado localmente y guarda la operación
firmada. Guarda cada cambio y desbloquea de nuevo si la configuración pide
reiniciar. Guarda la API key en el campo oculto de Elastic en Llavero y
credenciales; después activa el conector revisando la confirmación numerada.
PgUp/PgDn permite leer la propuesta completa, incluso con 80 columnas. Guardar
la CA pública con el conector desactivado no exige una confirmación de salida;
activarlo sí conserva la revisión habitual. Una CA incorrecta debe fallar. `lab-evaluation` es una etiqueta explícita
de selección del laboratorio, no una cuenta AWS. Copia `policy.toml`
al directorio desechable y conserva sus límites y permisos; en `[scope]` permite
solo la fuente `elastic-lab`, la cuenta `lab-evaluation` y el intervalo observado
de las muestras. Inicia con `--policy` apuntando a ese fichero: no añadas
comodines ni cambies niveles de riesgo denegados. Crea un caso con fuente
elastic-lab, cuenta lab-evaluation y una ventana de **un día del dataset cada vez**:
el conector limita cada consulta a 24 horas. Revisa `/scope` y el techo de la
organización; no lo amplíes para evitar un rechazo. Ingiere el EVTX original local
con `/ingest`; si el autotest de aislamiento falla, no lo omitas. Conserva originales. El EVTX fijado contiene un FILETIME cero, que se muestra
como 1601-01-01 junto a eventos de 2020: es una salvedad de calidad de la fuente,
no un motivo para ampliar a 1601 las consultas remotas. Las muestras AWS cubren
varios días de 2022 y el export de texto Windows es de 2021.

En `/settings model`, selecciona proveedor y modelo, guarda su clave solo en el
SecretBackend, revisa la confirmación de salida de datos y prueba la conexión sin
datos del caso. Registra identificador exacto, revisión conocida, razonamiento y
precios si se usan. No publiques claves ni rutas personales.

Para el ensayo sin GPU, una instalación local de Ollama puede usar Qwen2.5-1.5B.
Descarga el modelo explícitamente antes de aislar la red y anota versión y digest.
Su [máximo nativo documentado](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct)
es de 8192 tokens. Ejemplo de `Modelfile.lab`:

```text
FROM qwen2.5:1.5b
PARAMETER num_thread 4
PARAMETER num_ctx 16384
PARAMETER num_predict 8192
```

```sh
ollama pull qwen2.5:1.5b
ollama create lab-qwen --file Modelfile.lab
ollama show lab-qwen --parameters
```

[Referencia oficial de Modelfile](https://github.com/ollama/ollama/blob/main/docs/modelfile.mdx).
Selecciona el perfil en la TUI, declara máximo nativo 8192 y parámetro opcional.
El servidor debe escuchar solo en loopback. Cuatro hilos son una configuración
reproducible de laboratorio, no un óptimo universal: demasiados hilos pueden
agotar el plazo de la prueba. Dimensiona memoria, contexto y peticiones de hijos;
un servidor que las serializa puede devolver resultados parciales por tiempo.
No amplíes los plazos de seguridad de IRMind para ocultarlo. Una conexión correcta
no demuestra calidad de investigación: los modelos pequeños pueden confundir
Windows y AWS o inventar conclusiones. Revisa cada original antes de confirmar.

## 60–100 minutos: investigación, skill, plan y aprobación

1. Saluda y observa si responde naturalmente sin herramientas innecesarias.
2. Invoca `/windows-triage` sobre el EVTX y pide una cita del hash. Pide por separado
   una búsqueda estructurada en Elastic sobre un día. Registra consulta, recuento,
   hash firmado y cobertura parcial. Comprueba que una lectura fuera de alcance
   se deniega.
3. Haz una pregunta de seguimiento que dependa de la anterior, observa el streaming
   y revisa la cita y el original con `/evidence` o su tarjeta. Confirma solo los
   hallazgos sustentados; una skill o alerta no demuestra un ataque.
4. Activa «Confirmar todos los planes» en Preferencias. Pide un plan acotado con un
   hijo Windows sobre el EVTX y uno de nube sobre evidencia AWS ya adquirida por el
   agente principal. Las fuentes de los hijos están congeladas; un hijo no hereda
   silenciosamente evidencia nueva de otro. Revisa fuentes y reservas antes de
   Start y sigue `/subagents`.
5. Cancela un hijo y comprueba que el trabajo terminado sigue verificando. Para
   probar la firma del plan, cancela también una previsualización y acepta otra
   explícitamente. Una lectura SIEM dentro del alcance no tiene por qué pedir la
   aprobación de enriquecimiento externo. Registra una aprobación de herramienta
   solo si ocurre realmente; no la inventes ni la concedas automáticamente.

Si el modelo no delega o cita mal, registra ese resultado. No cambies su respuesta
para convertirlo en una prueba superada.

## 100–120 minutos: custodia y exportación

Los originales locales no copiados se resuelven solo bajo el directorio elegido
explícitamente. Las respuestas del conector retenidas en el caso se comprueban
en su ubicación firmada, por tamaño y SHA-256: no necesitan otra copia externa
ni repetir la consulta. Una copia retenida ausente o alterada falla sin recurrir
a otro fichero.


Ejecuta `/verify <directorio-origen>` y `/verify-graph <directorio-origen>`, revisa
`/report`, hallazgos y tareas pendientes. Termina o cancela trabajo antes de
`/seal`, confirma hash y huella exactos y usa `/export`, con originales si quieres.
En un proceso y directorio independientes:

```sh
irmind verify-export <paquete> --expected-key <huella-del-analista-guardada-independientemente>
```

La clave esperada procede del registro previo, no del paquete que intentas confiar.
Verifica sin el directorio del caso ni el llavero. Guarda resultados privados y
publica solo un resumen saneado; actualiza H5 y #63 únicamente con lo observado.
Para limpiar, ejecuta docker compose con el mismo fichero y env-file, seguido de
`down -v`. Borra contraseña, copia de API key, muestras y casos desechables cuando
no sean necesarios; conserva el ejecutable creador de los casos que retengas.

## Registro de resultados

| Comprobación | Resultado y observación exacta | Referencia privada o evidencia |
| --- | --- | --- |
| Fecha, SO, terminal, versión y commit | Pendiente | |
| Proveedor, modelo, revisión y razonamiento | Pendiente | |
| Pins, hashes, offset y documentos cargados | Pendiente | |
| TLS falla sin CA / funciona con CA aprobada | Pendiente | |
| Consulta de solo lectura y hash firmado | Pendiente | |
| Fuera de alcance denegado | Pendiente | |
| Saludo sin herramientas innecesarias | Pendiente | |
| Cita correcta del hash, seguimiento y streaming | Pendiente | |
| Recibo de skill y cobertura real | Pendiente | |
| Plan, Start firmado y resultados de hijos | Pendiente | |
| Cancelación y aprobaciones observadas | Pendiente | |
| Verify, reconstrucción, sello y export con clave fijada | Pendiente | |
| Fallos, límites y coste estimado | Pendiente | |

Las [referencias oficiales y el procedimiento en inglés](../development/real-validation.md)
explican el origen de las muestras y los permisos mínimos.

Los ejemplos proceden de ejercicios y años distintos: no son un único ataque
causal. La ventana del caso debe cubrir las fechas observadas; cada consulta
estructurada al conector sigue limitada a un día, como máximo 24 horas.

El servicio de certificados descarta la clave privada de la CA después de emitir
el certificado del servidor. Para renovar el laboratorio, recrea sus volúmenes.
