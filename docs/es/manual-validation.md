Traducción de docs/development/manual-validation.md en el commit 8da2130e1c826feb8708ab2882aabe9a6bd06e62; si hay diferencias, prevalece la versión en inglés.

# Validación manual del MVP

Esta guía permite al analista registrar las pruebas manuales. Usa solo los archivos sintéticos de `examples/`. Una prueba automatizada no sustituye una comprobación manual.

## H5: modelo DeepSeek real

1. Compila el binario por defecto desde `main` y abre `irmind` con un directorio de datos de prueba nuevo. Completa el asistente del llavero file y guarda la huella del analista fuera de ese directorio. En `/settings model`, elige DeepSeek, introduce el modelo aprobado y la clave en el campo enmascarado y ejecuta **Test connection**. Confirma el aviso de salida de datos; la prueba no contiene evidencia del caso.
2. Crea un caso con `/new` e ingiere `examples/cloudtrail-alert.json` con `/ingest`. Conserva el original para la verificación completa.
3. Escribe `hola` y comprueba que responde con naturalidad sin herramientas innecesarias. Después pide que explique los eventos sintéticos `ConsoleLogin` y `AssumeRole`, cite el hash e indique la incertidumbre. Comprueba que las herramientas respetan la política y que no inventa evidencia.
4. Haz una pregunta de seguimiento sobre la respuesta anterior. Comprueba la continuidad, el streaming y que no repite peticiones de resultados. Ejecuta `/verify` con la raíz de los originales. Una respuesta cortada por el límite debe permanecer visible y ofrecer continuar.

Registra el identificador del modelo, fecha, commit, comportamiento de las herramientas, avisos de redacción o inyección y resultado de verificación. No publiques la clave ni la respuesta completa del proveedor.

## Conector: contenedor de Splunk Enterprise

Esta prueba usa un servicio desechable. Consulta la [configuración oficial de Docker](https://splunk.github.io/docker-splunk/SETUP.html) y la [guía de carga de datos](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.4/how-to-get-data-into-your-splunk-deployment/upload-data).

1. Crea un archivo temporal privado con la aceptación de licencia y una `SPLUNK_PASSWORD` robusta, siguiendo la guía oficial. Arranca `splunk/splunk` y publica los puertos 8000 y 8089 solo en `127.0.0.1`. Borra el archivo tras arrancar y el contenedor al terminar. En ARM, usa una arquitectura admitida o una máquina amd64.
2. Carga `examples/splunk-cloudtrail-events.ndjson` en un índice de prueba, como un evento JSON por línea, con `eventTime` como instante. La búsqueda `alert_id=demo-alert-role` debe devolver un evento en `2026-10-23T10:17:00Z`. Comprueba la extracción de `recipientAccountId` y `eventName` antes de probar IRMind.
3. Emite un token dedicado de solo búsqueda, limitado al índice. Configura HTTPS en el puerto de gestión con una CA de laboratorio y un SAN que coincida con el host de la URL. En `/settings connectors`, introduce el PEM público, comprueba su huella SHA-256 y firma el cambio. La clave privada de la CA queda fuera de IRMind. No desactives TLS ni la comprobación del nombre. Consulta la [guía TLS de Splunk](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.0/secure-splunk-platform-communications-with-transport-layer-security-certificates/configure-tls-certificates-for-inter-splunk-communication).
4. Activa Splunk con el origen HTTPS, source `lab-splunk`, índice de prueba, campo de cuenta `recipientAccountId` y campo de alerta `alert_id`. Guarda `IRMIND_SPLUNK_TOKEN` en `/settings keystore` y reinicia la sesión cuando lo solicite. El token no debe mostrarse.
5. Limita el techo de política a `lab-splunk`, cuenta `000000000000` y ventana `2026-10-23T10:00:00Z`–`2026-10-23T11:00:00Z`. Crea un caso que termine a las `10:15:00Z`. Pide una búsqueda estructurada de `ConsoleLogin` dentro del alcance. Registra el resultado acotado y su hash; si el modelo no propone la consulta, indícalo sin afirmar que pasó.
6. Ejecuta `/siem-alert lab-splunk 000000000000 demo-alert-role 2026-10-23T10:00:00Z 2026-10-23T11:00:00Z`. Supera la ventana del caso, pero no el techo: debe pedir aprobación firmada. Revisa los argumentos, aprueba y comprueba un resultado `AssumeRole`. Ejecuta `/verify`. Una llamada por encima del techo debe denegarse incluso si se intenta aprobar.

El ejemplo usa una cuenta de documentación y una IP reservada. Borra los datos temporales al terminar. Consulta la [configuración de Splunk](modules.md#splunk).

## Alternativa: bucket S3 de pruebas

Usa un bucket desechable y una identidad con `s3:ListBucket` en un prefijo y `s3:GetObject` en sus objetos. Sube `examples/cloudtrail-alert.json`. En `/settings connectors`, configura S3 con source ID, región, bucket y endpoint HTTPS si es compatible con S3. Si usa una CA propia, aprueba el PEM y su huella. Guarda las credenciales dedicadas en `/settings keystore`. Añade el prefijo exacto y la ventana UTC a la política y al caso. Previsualiza con `/objects`, aprueba `/object-read` y ejecuta `/verify` con acceso al original. Registra el hash del manifiesto, los bytes y el resultado; elimina después el bucket y las credenciales.

## Registro de resultados

Guarda los registros detallados de validación en privado. El resumen público debe contener solo la versión del producto, el proveedor, el comportamiento observado y las pruebas pendientes. No publiques identificadores del equipo, rutas personales, credenciales ni salidas completas del proveedor o de incidentes.

| Comprobación de compatibilidad | Resumen público |
| --- | --- |
| Saludo con DeepSeek, IRMind 0.1.2 | Se observó una respuesta natural sin herramientas innecesarias. |
| Investigación, cita de hash, seguimiento, streaming y `/verify` | No constan como observados. |
| Conector real | La validación sigue pendiente. |

## Evaluación opcional con HuntEval y modelo real

Es una comprobación manual con datos sintéticos, posterior a la evaluación determinista semanal. No se ejecuta en CI ni envía las respuestas ocultas al modelo. Usa un directorio de prueba dedicado y un modelo configurado en `/settings model`. La CLI puede pedir desbloquear el archivo: introduce la passphrase en el terminal, nunca en argumentos ni variables de entorno.

1. Obtén [HuntEval](https://github.com/ns2switch/HuntEval) en el commit `4cbb555a56bc17cb03b988ad2f15b1374eecf183`. Desde ese checkout, ejecuta `sha256sum -c ../irmind/scripts/hunteval.sha256` en Linux. El script verifica el origen público antes de la ejecución y la respuesta privada después.
2. Compila IRMind, configura el modelo en el directorio dedicado y ejecuta el comando de desarrollo. Crea un caso, ingiere solo `source/events.json`, solicita hallazgos respaldados, verifica custodia y compara identificadores. Nunca aprueba herramientas automáticamente.

```sh
python3 scripts/hunteval_model_eval.py \
  ../HuntEval \
  aws-iam-001 \
  target/debug/irmind \
  ../irmind-evaluation \
  llm-deepseek
```

3. Registra precisión y exhaustividad de eventos, entidades y técnicas ATT&CK; revisa manualmente las afirmaciones y hashes. La comparación exacta puede omitir paráfrasis correctas y no prueba el respaldo de una afirmación. Resuelve las aprobaciones en la TUI solo si lo deseas y repite la prueba. Borra los datos temporales al terminar.

| Episodio / commit / modelo | P/R eventos | P/R entidades | P/R ATT&CK | Citas y notas |
| --- | --- | --- | --- | --- |
| | | | | |
