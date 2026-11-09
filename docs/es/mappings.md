Traducción de docs/mappings.md en el commit e5d05eba95c43a9856bee26acf4e8e6150866a66; si hay diferencias, prevalece la versión en inglés.

# Módulos de mapeo de fuentes

Esta página explica a analistas y colaboradores cómo los mapeos opcionales interpretan los logs decodificados. Los parsers leen el formato; los mapeos clasifican eventos y asignan roles a las entidades. Clasificar no concede permisos ni confirma un hallazgo.

El escritor común es experimental y opcional durante la incorporación de decodificadores. Antes de la 1.0, los formatos pueden cambiar entre versiones menores sin migración: conserva la versión creadora de IRMind o reingiere los originales verificados en un caso nuevo. Los mapeos nuevos se aplican a ingestas nuevas; para cambiar la interpretación, reingiere los originales verificados en un caso nuevo. Consulta el [diseño del pipeline](../development/source-mapping-design.md) y el [modelo de seguridad](security-model.md).

| Módulo | Entrada | Implementación | Feature de Cargo | Estado |
| --- | --- | --- | --- | --- |
| CloudTrail | JSON de CloudTrail mediante `json-source-v1` | TOML incluido, con hash fijado | `mapping-cloudtrail` | Experimental; contratos sintéticos |
| Compatibilidad JSON genérico | Otros JSON sin `eventVersion` | Nativo, solo extracción | `mapping-json-compat` | Experimental; sin categorías ni roles inferidos |
| Compatibilidad journald | JSON original de journald | Nativo, solo extracción | `mapping-journald-compat` | Experimental; sin categorías ni roles inferidos |
| Autenticación Linux | auth.log y secure: sshd, sudo y su | TOML incluido, con hash fijado | `mapping-linux` | Experimental; contratos sintéticos |
| Linux auditd | Miembros originales agrupados SYSCALL y EXECVE | Nativo, proyección acotada entre miembros | `mapping-linux` | Experimental; contratos sintéticos |
| Acceso HTTP | Common/combined de nginx y Apache | TOML incluido, con hash fijado | `mapping-linux` | Experimental; contratos sintéticos |

## CloudTrail

La definición incluida selecciona explícitamente la versión V2 del intérprete de tablas. Usa nombres exactos de servicio y operación. Para `ConsoleLogin`, los valores documentados `Success` y `Failure` de `responseElements.ConsoleLogin` indican el resultado; si falta, queda desconocido. Solo clasifica el resultado de las operaciones API enumeradas cuando `eventType = AwsApiCall`: la presencia de `errorCode` indica fallo y su ausencia, éxito. Las operaciones no enumeradas quedan sin clasificar.

| Servicio | Operaciones |
| --- | --- |
| Inicio de sesión | ConsoleLogin |
| IAM | CreateUser, DeleteUser, CreateAccessKey, DeleteAccessKey, UpdateAccessKey, CreateLoginProfile, UpdateLoginProfile, AttachUserPolicy, DetachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy, AddUserToGroup, CreatePolicyVersion, SetDefaultPolicyVersion |
| STS | AssumeRole, AssumeRoleWithSAML, AssumeRoleWithWebIdentity, GetCallerIdentity |
| EC2 | RunInstances, StartInstances, StopInstances, AuthorizeSecurityGroupIngress |
| S3 | GetObject, PutObject, DeleteObject |
| CloudTrail | StopLogging, StartLogging, UpdateTrail, DeleteTrail |

Las identidades del actor usan el espacio de su cuenta. Un usuario objetivo solicitado usa la cuenta receptora. El mismo nombre en ambos roles conserva dos observaciones, sin crear identidades globales. Los parámetros API nunca se convierten en identidades de proceso. Las particiones por cuenta y región conservan la normalización y los límites existentes.

Solo una IP válida ocupa `source.ip`. Un nombre de servicio en `sourceIPAddress`, un campo tipado inválido o una representación no admitida generan una proyección explícitamente sin clasificar mediante el límite común del mapeo. El registro original sigue disponible. Nunca se inventan valores ausentes.

Los selectores del catálogo compilado son excluyentes: CloudTrail exige `eventVersion`; la compatibilidad genérica exige que falte. Un valor nulo no coincide con ninguno. Se rechaza una definición instalada que se solape; no hay prioridad ni alternativa silenciosa. El constructor amplio de compatibilidad sigue disponible para los benchmarks fijados.

El hash canónico de la definición queda fijado en el módulo. Cambiar su interpretación exige revisar la versión y el hash. El perfil y el recibo V3 existentes enlazan su identidad exacta con el esquema común. Las definiciones no reciben acceso a archivos, red, reloj ni secretos.

Referencias: [campos de CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html), [eventos de inicio de sesión](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html) y [eventos IAM/STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html).

## Marcadores opcionales de valor ausente

Un campo de una definición puede declarar `omit_text = ["", "-"]` para marcadores documentados de la fuente. Una cadena original coincidente omite solo ese campo proyectado y su observación de entidad. La evidencia original no cambia. La comparación es exacta y distingue mayúsculas; los valores inválidos no enumerados siguen rechazándose. Se admiten hasta ocho literales distintos, sin caracteres de control y de un máximo de 256 bytes UTF-8 cada uno. Consulta el [diseño del intérprete acotado](../development/mapping-optional-fields.md).

## Autenticación Linux, auditd y HTTP

`parser-linux` decodifica los campos originales mediante `linux-source-v1`. Conserva mensajes originales, instantes exactos y ubicaciones de los miembros; nunca asigna categorías, resultados ni roles. Los instantes clásicos de auth.log/secure siguen requiriendo confirmar año y offset UTC para cada ingesta. La CLI y la TUI usan el mismo detector y flujo de confirmación.

Cinco módulos de mapeo comparten la feature `mapping-linux`. Los módulos sshd, sudo, su y HTTP usan definiciones TOML incluidas con hashes canónicos fijados. Cada uno tiene su manifiesto y un selector de dataset sin solapamientos. auditd usa código nativo porque debe combinar un conjunto acotado de miembros SYSCALL/EXECVE originales; una tabla finita de campos no puede hacerlo. Journald conserva su mapeo de solo extracción mediante el mismo decodificador Linux, sin inventar clasificaciones.

- Los valores `Accepted`, `Failed` e `Invalid` de SSH seleccionan resultados de autenticación explícitos. Los mensajes desconocidos quedan sin clasificar. El usuario de un acceso correcto es el actor; la cuenta intentada en un fallo es el objetivo.
- Las tablas PAM usan los valores explícitos de sesión `opened` y de autenticación `failure`. Cerrar una sesión no implica un resultado nuevo de autenticación. Una solicitud de comando sudo tiene resultado desconocido: solicitarlo no demuestra que se ejecutara correctamente.
- Las identidades de usuario usan el espacio de nombres del host declarado. Los PID reutilizados tienen identidades del registro de origen, salvo que exista un identificador real de vida del proceso. El mismo usuario como actor y objetivo conserva una identidad con dos observaciones.
- auditd usa `success=yes/no` solo en grupos completos. El estado ausente y los grupos parciales quedan como desconocidos. Se conservan arquitectura, syscall y argumentos originales; no se inventa una interpretación dependiente de arquitectura ni un comando de shell.
- Los estados HTTP 2xx/3xx indican éxito, 4xx/5xx fallo y 1xx resultado desconocido. El marcador original de usuario `-` se conserva y `omit_text` evita convertirlo en identidad. Los logs HTTP no establecen el nombre del servidor: el mapeo no inventa una partición de host.

Las IP, puertos y otros valores tipados inválidos conservan el diagnóstico de valor no soportado y el registro original de la frontera compartida. Los mapeos no deducen resultados a partir de fragmentos arbitrarios del mensaje ni conceden permisos a las herramientas.
