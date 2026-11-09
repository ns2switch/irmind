Traducción de docs/mappings.md en el commit 5c3a759132c226123b85e8b65278be851a10dacc; si hay diferencias, prevalece la versión en inglés.

# Módulos de mapeo de fuentes

Esta página explica a analistas y colaboradores cómo los mapeos opcionales interpretan los logs decodificados. Los parsers leen el formato; los mapeos clasifican eventos y asignan roles a las entidades. Clasificar no concede permisos ni confirma un hallazgo.

El escritor común es experimental y opcional. Los casos V1 y V2 siguen siendo legibles sin migración. Los mapeos nuevos se aplican a ingestas nuevas; para cambiar la interpretación, reingiere los originales verificados en un caso nuevo. Consulta el [diseño del pipeline](../development/source-mapping-design.md) y el [modelo de seguridad](security-model.md).

| Módulo | Entrada | Implementación | Feature de Cargo | Estado |
| --- | --- | --- | --- | --- |
| CloudTrail | JSON de CloudTrail mediante `json-source-v1` | TOML incluido, con hash fijado | `mapping-cloudtrail` | Experimental; contratos sintéticos |
| Compatibilidad JSON genérico | Otros JSON sin `eventVersion` | Nativo, solo extracción | `mapping-json-compat` | Experimental; sin categorías ni roles inferidos |
| Compatibilidad journald | JSON original de journald | Nativo, solo extracción | `mapping-journald-compat` | Experimental; sin categorías ni roles inferidos |

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
