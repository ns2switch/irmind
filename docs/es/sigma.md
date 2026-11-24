# Detección local con Sigma

[English](../sigma.md)

IRMind evalúa un subconjunto acotado de reglas Sigma sobre los artefactos Parquet locales autenticados de un caso abierto. El análisis firmado registra los bytes de las reglas admitidas, el alcance de fuentes, la tabla de campos revisada, las reglas omitidas y las filas exactas de evidencia. Usa la evidencia local y se ejecuta sin modelo ni conexión de red.

## Ejecutar un pack

1. Guarda las reglas YAML revisadas, con un solo documento por fichero, en un directorio local. Comprueba la procedencia y la licencia de las reglas de terceros antes de importarlas.
2. Ejecuta `/sigma inspect <directorio>` y revisa el SHA-256 del manifiesto. Usa `/sigma import --license <id-licencia> <directorio>` y confirma ese hash para firmar la admisión.
3. Ejecuta `/sigma run <SHA-256 del manifiesto> <inicio UTC> <fin UTC>` con dos instantes UTC crecientes, como `2026-11-01T00:00:00Z 2026-11-02T00:00:00Z`.
4. Revisa los hallazgos propuestos y las referencias a sus filas. Confirma cada hallazgo con `/confirm <id-hallazgo>` antes de publicar el informe.
5. Ejecuta `/verify` para verificar el caso y el material firmado de Sigma. Sella el caso antes de exportarlo en V10. El destinatario puede verificar el paquete con la huella esperada de la clave del analista.

Se omiten las reglas cuyo logsource o campos no tienen correspondencia exacta. Una regla debe resolver sus campos en todas las clases inscritas que le apliquen dentro del caso. Un análisis cancelado o que alcance un límite de trabajo, tamaño o tiempo queda como parcial. Sin coincidencias en una ejecución parcial o en una fuente omitida, la actividad correspondiente queda sin determinar.

## Cobertura y campos por fuente

Usa el `product` y `service` indicados en el logsource de Sigma. El selector de categoría acota las clases indicadas. Los nombres de campo distinguen mayúsculas y minúsculas. Respeta el tipo de cada valor.

| Producto y servicio | Eventos admitidos | Ejemplos de campos |
| --- | --- | --- |
| `windows/security` | Canal Security e IDs inscritos; `process_creation` para 4688 | `EventID` y `LogonType` como texto, `Channel`, `Computer`, `SubjectUserName`, `TargetUserName`, `IpAddress`, `SourceIp` (IP); 4688 añade `Image`, `ParentImage`, `CommandLine` |
| `windows/sysmon` | Microsoft-Windows-Sysmon/Operational, IDs 1, 3, 11, 13, 22 | `Image`, `CommandLine`, `ParentImage` y `ProcessGuid` en creación de procesos; `SourceIp`, `DestinationIp`, `TargetFilename`, `TargetObject` y `QueryName` en sus clases |
| `windows/powershell` | Microsoft-Windows-PowerShell/Operational, módulos 4103 y bloques 4104 | `EventID` (texto), `Payload`, `ContextInfo`, `ScriptBlockText`, `ScriptBlockId`, `Path` según clase |
| `linux/sshd`, `linux/sudo`, `linux/su` | Autenticación mapeada de auth.log o secure; ejecución de sudo | `Outcome`, `Hostname`, `User`, `TargetUser`, `Message`, `Process`, `PID`; SSH añade `Verb`, `LoginUser`, `SourceIP`, `SourcePort` |
| `linux/auditd`, `linux/ecs` | Eventos agrupados de auditd, autenticación y procesos de ECS en Linux incluido Elastic ECS | `Syscall`, `Serial` y `Node` en auditd; `Image` y `ProcessId` tipados en procesos; autenticación ECS añade `SourceIP` y `Outcome` |
| `aws/cloudtrail` | Operaciones de la tabla revisada de CloudTrail | `eventName`, `eventSource`, `sourceIPAddress` (texto original), `source.ip` (IP), `awsRegion`, `recipientAccountId`, `userIdentity.principalId`, `userIdentity.arn`, `errorCode`, `readOnly`, `Outcome` |
| `zeek/dns`, `zeek/http`, `zeek/conn` | DNS, HTTP y conexiones en JSON y TSV | `id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`, `proto`, `query`, `qtype_name`, `rcode_name`, `host`, `uri`, `method`, `status_code` según clase |
| `suricata/dns`, `suricata/http`, `suricata/flow`, `suricata/alert` | DNS, HTTP, flujos y alertas en EVE | `src_ip`, `dest_ip`, `src_port`, `dest_port`, `event_type`, `dns.rrname`, `http.hostname`, `http.status`, `alert.signature`, `alert.signature_id` según clase |
| `azure/signinlogs`, `azure/auditlogs`, `azure/activitylogs` | Exportaciones de inicio de sesión y auditoría de Entra, tabla AzureActivity | `ResultType` (texto), `IPAddress` (IP), `UserPrincipalName`, `AppId`, `OperationName`, `Result`, `InitiatedBy.user.userPrincipalName`, `OperationNameValue`, `ActivityStatusValue`, `CallerIpAddress` según formato |
| `m365/audit`, `m365/exchange` | Unified Audit Log y carga Exchange explícita | `Operation`, `Workload`, `UserId`, `ClientIP`, `ObjectId`, `ResultStatus`, `Outcome` |
| `okta/okta` | Okta System Log | `eventType`, `outcome.result`, `actor.alternateId`, `client.ipAddress`, `SourceIP`, `Outcome` |
| `gcp/gcp.audit` | Cloud Audit Logs | `protoPayload.methodName`, `protoPayload.serviceName`, `protoPayload.authenticationInfo.principalEmail`, `protoPayload.requestMetadata.callerIp`, `protoPayload.status.code` (entero, ausente si falta) |
| `kubernetes/audit` | Auditoría de Kubernetes, EKS y AKS; proyección exacta de recursos en GKE | `objectRef.resource`, `objectRef.namespace`, `Outcome`; Kubernetes, EKS y AKS añaden `verb`, `user.username`, `responseStatus.code`, `PrimarySourceIP`, `stage`; GKE añade `protoPayload.methodName` |
| `windows/defender` | Creaciones de proceso y conexiones de Defender con plataforma Windows explícita | `CommandLine`, `ParentCommandLine`, `FileName`, `FolderPath`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`; red `LocalIP`, `RemoteIP`, `LocalPort`, `RemotePort` |
| `windows/crowdstrike` | Process rollup y conexiones IPv4 o IPv6 de FDR en Windows | `Image`, `CommandLine`, `ParentBaseFileName`, `TargetProcessId` y `ParentProcessId` con ámbito del proveedor, `aid`, `cid`; `LocalAddressIP4` / `RemoteAddressIP4` o sus equivalentes IPv6 |
| `macos/eslogger` | Notificaciones de exec y creación de fichero de eslogger v1 | `Image` del destino de exec, `Arguments` como lista, `ProcessId`, `TargetFilename` y `ActorExecutable` según clase |

Quedan fuera los objetos de parámetros de Microsoft 365, la lista completa `sourceIPs` de Kubernetes y el código numérico original de estado de GKE. La proyección actual de Defender tampoco ofrece rutas verificadas `Image` o `ParentImage` compuestas de sus dos campos. CrowdStrike y eslogger tienen campos separados para el nombre del padre o la ruta del actor. Una regla que pida un campo sin equivalencia exacta queda omitida.

Las tablas revisadas detallan los campos admitidos, las rutas originales, las columnas tipadas y los selectores. [CloudTrail](../../crates/infra/src/sigma_pack/cloudtrail-v1.toml) · [Windows](../../crates/infra/src/sigma_pack/windows-v1.toml) · [Linux](../../crates/infra/src/sigma_pack/linux-v1.toml) · [Red](../../crates/infra/src/sigma_pack/network-v1.toml) · [Identidad cloud](../../crates/infra/src/sigma_pack/cloud-identity-v1.toml) · [Endpoint](../../crates/infra/src/sigma_pack/endpoint-v1.toml)
