Traducción de docs/skills.md en el commit 47276f54ac795bfa97cf0986999ecbc166d81404; si hay diferencias, prevalece la versión en inglés.

# Skills forenses

Esta página ayuda a los analistas a aplicar un método de investigación repetible sin ampliar los permisos del agente. Una skill es una carpeta pequeña y versionada de metodología y referencias. No contiene código ejecutable.

## Usar un método incluido

Abre un caso, configura un modelo en `/settings model` y escribe `/` para ver los métodos activos. El binario incluye 13 métodos. Todos son experimentales y se prueban con episodios sintéticos; no validan por sí solos una conclusión forense.

| Comando | Para qué sirve | Fuentes necesarias | Cobertura |
| --- | --- | --- | --- |
| `/windows-triage` | Accesos, ejecución y actividad posterior de Windows. | EVTX o exportaciones de Hayabusa, EZTools, Velociraptor/plaso. | Parcial: depende de los canales y artefactos recogidos. |
| `/linux-triage` | Autenticación, privilegios y ejecución. | auth.log/secure, auditd y journald. | Núcleo de autenticación/ejecución mapeado; otra actividad puede tener solo extracción. |
| `/aws-credential-compromise` | Credenciales y cambios de privilegios. | Eventos de administración de CloudTrail. | Solo operaciones mapeadas; la falta de eventos de datos limita el seguimiento. |
| `/aws-s3-data-exfiltration` | Exposición, permisos y lecturas inusuales de S3. | CloudTrail de administración **y eventos de datos de S3**. | Parcial: GetObject se clasifica como `api/access`; políticas y ACL requieren campos originales. |
| `/azure-entra-identity-compromise` | Accesos, MFA, roles, OAuth y credenciales de aplicaciones. | Entra/Azure normalizado a ECS o UDM de Chronicle configurado; JSON nativo para revisión original. | Parcial: no hay mapeo semántico nativo de Entra. IRMind no convierte automáticamente una descarga del portal en ECS. |
| `/gcp-service-account-abuse` | Claves, suplantación y cambios IAM. | Cloud Audit Logs JSON; ECS normalizado por el productor, opcional. | IAM/IAM Credentials y operaciones documentadas de política de proyecto con tipos; faltan cobertura si no hay estado o identidad o el servicio no tiene mapeo. |
| `/windows-ransomware` | Inhibición de recuperación, propagación e impacto posible. | EVTX/Sysmon y observaciones de ficheros, recuperación y defensas. | Parcial: un comando no demuestra cifrado ni un cambio efectivo de defensas. |
| `/windows-lateral-movement` | RDP, SMB/PsExec, WMI, WinRM y uso de credenciales. | Security, System, Sysmon y registros operativos de origen/destino. | Núcleo de accesos/servicios mapeado; un acceso tipo 3 nunca prueba por sí solo pass-the-hash. |
| `/windows-persistence` | Servicios, tareas, claves Run y suscripciones WMI. | EVTX y exportaciones de configuración/DFIR. | Parcial: 4698 y las suscripciones WMI no tienen reglas semánticas actuales. |
| `/linux-webshell` | Peticiones web correlacionadas con ejecución del usuario web. | nginx/Apache common/combined, auditd y evidencia del directorio web. | Núcleo HTTP/execve mapeado; pueden faltar host, ID de petición o causalidad. |
| `/linux-persistence` | Cron, systemd, claves SSH, cuentas y sudoers. | Registros Linux y configuración recogida o exportaciones DFIR. | Parcial: pocos registros no reconstruyen todo el estado de configuración. |
| `/network-c2-beaconing` | Flujos periódicos, DNS y alertas. | Zeek y Suricata EVE; ECS ya normalizado, opcional. | Parcial: los mapeos nativos extraen entidades y campos sin categorías ni roles. |
| `/malware-execution-triage` | Origen, ejecución y actividad observada de un binario. | Sysmon 1/3/11 y PECmd/AmcacheParser u otras exportaciones DFIR. | Parcial: presencia en Amcache no prueba ejecución; los artefactos binarios necesitan exportación. |

Consulta la [guía de parsers](parsers.md) y la [configuración de módulos](modules.md) antes de recoger datos. Las skills solo declaran las herramientas locales que necesitan. Ninguna ejecuta recolectores, accede a proveedores, instala mapeos ni amplía el alcance.

### Recoger evidencia suficiente

Cada método incluye una sección de cobertura y una tabla de referencia. Explica qué fuentes y mapeos necesita, cómo puede obtenerlos el analista y qué queda sin observar. La recogida de Windows usa procedimientos aprobados de KAPE o Velociraptor y exportaciones de herramientas como EZTools; IRMind no analiza directamente todos los artefactos binarios. En nube hacen falta los tipos de auditoría y la retención pertinentes, no solo configurar un conector.

Empieza con `graph_summary` y los registros originales antes de filtrar por el esquema común. Los filtros `event_category`, `event_type`, `event_outcome` y `entity_role` solo devuelven cobertura mapeada coincidente y pueden excluir registros sin clasificar. Para fuentes con solo extracción, usa búsqueda acotada, timelines de entidades cuando existan y registros originales. Ninguna skill inventa un rol ni un resultado ausente. Pide al analista lo que falta y registra la limitación.

Los métodos incluyen falsos positivos y condiciones para proponer técnicas ATT&CK. La proximidad temporal, una arista, una alerta o una línea de comandos no confirman por sí solas un ataque. Solo el analista confirma hallazgos.

Puedes añadir una pregunta: `/linux-triage Revisa los accesos fallidos de este caso.` El agente también puede elegir un método por su descripción. Una skill no activa modelos ni conectores remotos. Puedes inspeccionarlas sin configurar un modelo.

Al principio el modelo solo recibe nombres y descripciones activos. Cuando pide `skill_read`, IRMind comprueba la política, fija el paquete aprobado en el caso, filtra el recurso y firma un recibo con la clave Agent antes de mostrar el texto. La conversación incluye una tarjeta plegable de metodología. Ctrl+O o `/expand` muestran sus detalles.

## Gestionar paquetes locales

Abre `/skills` desde el inicio o un caso. Las flechas eligen el método, Tab recorre las acciones y Enter las abre. También puedes escribir el número de opción y pulsar Enter.

1. **Inspect** muestra versión, hash del paquete, herramientas y recursos declarados.
2. **Install/update** abre un campo de carpeta. Elige una carpeta local con `SKILL.md`, revisa la vista previa y firma la instalación o sustitución.
3. **Enable/disable** firma el cambio de activación. Desactivar impide cargas futuras y conserva los recibos del caso.
4. **Restore approved file** restaura explícitamente el paquete instalado desde su registro firmado si los ficheros han cambiado o desaparecido.

Esc vuelve sin aplicar la vista previa. Estas acciones usan la clave Analyst y la cadena operativa global firmada. Los paquetes modificados, ausentes o no soportados quedan inactivos. IRMind nunca los sustituye en silencio por un método incluido. La demo permite inspeccionar sin cambiar las instalaciones reales.

Descarga los paquetes comunitarios explícitamente y verifica sus hashes publicados antes de revisarlos y firmarlos. IRMind no los descarga automáticamente. La firma aprueba unos bytes concretos; no convierte sus afirmaciones en hechos ni sus instrucciones en contenido confiable.

## Límites y seguridad

Cada paquete contiene `SKILL.md` y hasta 16 recursos, con un máximo total de 128 KiB y 32 KiB por recurso. Puede haber 32 métodos activos. Por turno se cargan como máximo cuatro instantáneas distintas y ocho recursos, hasta 64 KiB de metodología filtrada y dentro de los límites inferiores de contexto y tokens. Alcanzar un límite produce un recibo firmado; el contenido no se trunca en silencio.

La metodología siempre es contenido no confiable. Nunca entra en mensajes de sistema, no es evidencia y su hash no puede citarse como evidencia. Las herramientas declaradas limitan las llamadas del método. Siguen vigentes la política, el alcance, el techo de la organización, las comprobaciones de contenido contaminado, las aprobaciones y los presupuestos. Una skill no confirma sus propios hallazgos. La ausencia de mapeos significa cobertura incompleta, no permiso para inventar una clasificación.

El caso conserva el paquete original y los rangos filtrados realmente cargados. La exportación V7 incluye las pruebas de instalación referenciadas para verificarla sin llavero. Autentica el uso de la metodología registrado; no reproduce una respuesta del modelo ni garantiza una conclusión forense.

Antes de la 1.0, las versiones menores pueden cambiar los formatos sin migración. Conserva la versión que creó cada caso. Consulta el [modelo de seguridad](security-model.md), la [configuración](configuration.md) y el [diseño de desarrollo en inglés](../development/skills-design.md).

## Referencias metodológicas

Los métodos usan texto propio bajo la licencia del proyecto. Sus fuentes públicas incluyen
[la auditoría de S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html),
[los eventos de datos de S3](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-s3-data-events-governance.html),
[la exportación de Entra](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-download-logs),
[las actividades auditadas de Entra](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities),
[la auditoría IAM de GCP](https://docs.cloud.google.com/iam/docs/audit-logging),
[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
[las conexiones de Zeek](https://docs.zeek.org/en/current/logs/conn.html),
[Suricata EVE](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
y [MITRE ATT&CK](https://attack.mitre.org/). Los enlaces viven aquí porque
el texto cargado de las skills pasa por el mismo guard que otro contenido no confiable.
