Traducción de docs/skills.md en el commit d99da3a179ee34783395f39696642ed26f8bb934; si hay diferencias, prevalece la versión en inglés.

# Skills forenses

Esta página ayuda a los analistas a aplicar un método de investigación repetible sin ampliar los permisos del agente. Una skill es una carpeta pequeña y versionada de metodología y referencias. No contiene código ejecutable.

## Usar un método incluido

Abre un caso, configura un modelo en `/settings model` y escribe `/` para ver los métodos activos. La versión 0.4 incluye:

| Comando | Método |
| --- | --- |
| `/windows-triage` | Revisar inicios de sesión, ejecución, persistencia, movimiento lateral y posible exfiltración en datos de Windows recogidos por el analista. |
| `/linux-triage` | Revisar autenticación, cambios de privilegios, ejecución y persistencia en Linux. |
| `/aws-credential-compromise` | Revisar en CloudTrail el uso de credenciales, los cambios de privilegios y los recursos afectados. |

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
