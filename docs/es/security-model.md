Traducción de docs/security-model.md en el commit 095cd1db66e6dec2b51c6115d4fd44de6981e6a4; si hay diferencias, prevalece la versión en inglés.

# Modelo de seguridad

Esta página es para analistas y revisores que evalúan si IRMind sirve para sus datos. Explica qué aplica la versión actual y qué no puede garantizar.

> IRMind está en desarrollo. No lo uses todavía para incidentes reales ni datos sensibles.

## Límite de confianza

El modelo puede proponer una llamada a una herramienta, pero no ejecutarla. La aplicación valida la herramienta y sus argumentos, comprueba el alcance y los límites del caso y registra una decisión firmada. Solo una llamada autorizada llega a un conector remoto. Las lecturas deben estar dentro del alcance. El enriquecimiento externo espera la aprobación firmada del analista. La contención está deshabilitada.

El analista controla el caso, su alcance, las aprobaciones y su clave de firma. Archivos, logs, resultados remotos, texto del grafo y salida del modelo no son confiables. Pueden contener instrucciones escritas por un atacante.

## Garantías de esta versión

- **Custodia:** La evidencia original se guarda en local por SHA-256. Los cambios del caso y la actividad de herramientas entran en una cadena de auditoría SQLite de solo anexado, con firmas Ed25519. La verificación detecta entradas y bytes de evidencia modificados.
- **Identidades separadas:** Analyst y Agent tienen claves distintas en el backend elegido. Solo la firma del analista puede resolver una aprobación pendiente. Un caso sellado tiene una cadena operativa firmada aparte para cancelaciones; las migraciones entran en una cadena operativa global firmada.
- **Entrada protegida del modelo:** El texto externo se normaliza, se examina en busca de inyección de instrucciones, se redacta según patrones conocidos de secretos y datos personales, se limita y se envuelve como dato no confiable. El original queda en local. Un autotest de arranque bloquea la aplicación si falla el corpus conocido del guard.
- **Conectores limitados:** Las credenciales llegan desde el backend de secretos elegido a través de la raíz de composición. Los clientes remotos exigen HTTPS, salvo HTTP sin clave hacia un servicio de modelo explícito en loopback. Las redirecciones están desactivadas y las respuestas tienen límites.
- **Presentación segura:** La TUI elimina controles del terminal de la salida del modelo, los resúmenes de evidencia y los nombres de archivo. Los diálogos de aprobación muestran los argumentos exactos tras escaparlos para el terminal.

Un paquete exportado contiene el log firmado, el sello, la evidencia y la clave pública. Usa `verify-export --expected-key` con una huella obtenida por otro canal de confianza.

## Amenazas consideradas

| Actor u origen | Riesgo principal | Defensa actual |
| --- | --- | --- |
| Autor de los logs investigados | Instrucciones ocultas, roles falsos, nombres de archivo maliciosos | Datos marcados como no confiables, guard, política independiente del modelo, escape de terminal |
| Proveedor o red comprometidos | Exposición de datos, respuestas alteradas, redirecciones inseguras | TLS, sin redirecciones, respuestas limitadas, evidencia local firmada, selección explícita del proveedor |
| Proceso con permisos del analista | Leer o alterar archivos locales y usar el llavero | Los permisos y la verificación detectan algunos cambios; el proceso aún puede actuar como el usuario |
| Archivo o paquete malformado | Rutas maliciosas, JSON profundo, agotamiento de recursos | Ingesta y exportación acotadas, enlaces simbólicos no seguidos por defecto, validación de rutas |

## Límites conocidos

- La redacción y la detección de inyecciones se basan en patrones. Pueden pasar por alto datos sensibles o instrucciones maliciosas. No las tomes como permiso para enviar datos regulados a un proveedor.
- Un proceso que controle la cuenta y la clave del analista puede sustituir la cadena completa de un caso. Guarda la huella de la clave pública fuera de este equipo; aún no hay anclaje externo de sellos.
- Los permisos de archivos no protegen una sesión de usuario completamente comprometida. Algunos componentes de una ruta pueden cambiar entre el recorrido del directorio y la apertura del archivo.
- El enriquecimiento en VirusTotal expone el IOC consultado a un servicio externo. Siempre necesita aprobación. Un conector de solo lectura también depende de los permisos reales concedidos por su servicio.
- El grafo es un índice derivado, no la evidencia original. Verifícalo o reconstruye desde entradas firmadas cuando importe su exactitud.
- Los binarios de CI tienen checksums, pero no firma de código, notarización ni firma Authenticode. Consulta [plataformas](platforms.md).
- Los backends del sistema y de archivo cifrado se eligen expresamente; no hay cambios automáticos. El archivo funciona por SSH, pero depende de una passphrase sólida y de la integridad de la máquina. Perder la clave de firma puede impedir continuar un caso.

## Uso recomendado

Empieza por el [ejemplo sintético](getting-started.md). Limita el alcance remoto, usa credenciales de servicio dedicadas de solo lectura y aprueba solo llamadas cuyos argumentos entiendas. Si sospechas una vulnerabilidad, usa el proceso privado de [SECURITY.md](../../SECURITY.md) en lugar de abrir un issue público.
