# Detección local con Sigma

[English](../sigma.md)

IRMind evalúa un subconjunto acotado de reglas Sigma sobre los artefactos Parquet locales autenticados de un caso abierto. El análisis firmado registra los bytes de las reglas admitidas, el alcance de fuentes, la tabla de campos revisada, las reglas omitidas y las filas exactas de evidencia. Usa la evidencia local y se ejecuta sin modelo ni conexión de red.

## Ejecutar un pack

1. Guarda las reglas YAML revisadas, con un solo documento por fichero, en un directorio local. Comprueba la procedencia y la licencia de las reglas de terceros antes de importarlas.
2. Ejecuta `/sigma inspect <directorio>` y revisa el SHA-256 del manifiesto. Usa `/sigma import --license <id-licencia> <directorio>` y confirma ese hash para firmar la admisión.
3. Ejecuta `/sigma run <SHA-256 del manifiesto> <inicio UTC> <fin UTC>` con dos instantes UTC crecientes, como `2026-11-01T00:00:00Z 2026-11-02T00:00:00Z`.
4. Revisa los hallazgos propuestos y las referencias a sus filas. Confirma cada hallazgo con `/confirm <id-hallazgo>` antes de publicar el informe.
5. Ejecuta `/verify` para verificar el caso y el material firmado de Sigma. Sella el caso antes de exportarlo en V10. El destinatario puede verificar el paquete con la huella esperada de la clave del analista.

Sigma compila la regla completa para cada clase de fuente aplicable y la ejecuta donde todos los campos tienen correspondencia exacta. La ejecución firmada registra los pares de regla y clase omitidos, y distingue los huecos de cobertura de las filas indeterminadas y los escaneos interrumpidos. Un resultado vacío deja sin determinar la actividad de las clases omitidas.

En la release fijada de SigmaHQ r2026-07-01, 3.301 de 3.302 ficheros pasaron la admisión y 1.022 compilaron para todas las clases aplicables de la tabla revisada. Consulta los [recuentos y motivos de rechazo por familia](../development/benchmarks/sigmahq-v070-admission.md).

La [auditoría de tablas de v0.7.3](../development/benchmarks/sigmahq-v073-reviewed-fields.md) compiló 1.159 de las mismas 3.302 reglas con el evaluador V2. La auditoría recoge el efecto de cada bloque por separado.

La [auditoría V3 de nube y macOS](../development/benchmarks/sigmahq-v073-cloud-bindings.md) mide la tabla ampliada en cinco ejecuciones acumuladas. Las correspondencias usan campos explícitos conservados de cada proveedor. Los campos que requieren otra representación se recogen en la [propuesta de proyección](../development/sigma-structured-original-paths-proposal.md).
Consulta la [comparación de admisión y ejecución entre V2 y V3](../development/benchmarks/sigma-v073-source-classes.md) sobre la misma tabla revisada.

## Cobertura y campos por fuente

Usa el `product` y `service` indicados en el logsource de Sigma. El selector de categoría acota las clases indicadas. Los nombres de campo distinguen mayúsculas y minúsculas. Respeta el tipo de cada valor.

| Producto y servicio | Eventos admitidos | Ejemplos de campos |
| --- | --- | --- |
| `windows/security` | Canal Security e IDs inscritos; `process_creation` para 4688 | `EventID` y `LogonType` (enteros), `Channel`, `Computer`, `SubjectUserName`, `TargetUserName`, `IpAddress`, `SourceIp` (IP); 4688 añade `Image`, `ParentImage`, `CommandLine` |
| `windows/sysmon` | Microsoft-Windows-Sysmon/Operational, IDs 1, 3, 11, 22 | `Image`, `CommandLine`, `ParentImage`, `ProcessGuid`, `OriginalFileName`, `Hashes` e `IntegrityLevel` en creación de procesos; `SourceIp`, `DestinationIp`, `TargetFilename` y `QueryName` en sus clases |
| `windows/sysmon` | Carga de imagen ID 7 y registro IDs 12–14 | `ImageLoaded`, `OriginalFileName`, `Signed` y `SignatureStatus` para cargas de imagen. `TargetObject`, `EventType`, `Details` o `NewName` según la clase de registro |
| `windows/powershell` | Microsoft-Windows-PowerShell/Operational, módulos 4103 y bloques 4104 | `EventID` (entero), `Payload`, `ContextInfo`, `ScriptBlockText`, `ScriptBlockId`, `Path` según clase |
| `linux/sshd`, `linux/sudo`, `linux/su` | Autenticación mapeada de auth.log o secure; ejecución de sudo | `Outcome`, `Hostname`, `User`, `TargetUser`, `Message`, `Process`, `PID`; SSH añade `Verb`, `LoginUser`, `SourceIP`, `SourcePort` |
| `linux/auditd`, `linux/ecs` | Eventos agrupados de auditd, autenticación y procesos de ECS en Linux incluido Elastic ECS | `Syscall`, `Serial` y `Node` en auditd; `Image` y `ProcessId` tipados en procesos; autenticación ECS añade `SourceIP` y `Outcome` |
| `aws/cloudtrail` | Operaciones de la tabla revisada de CloudTrail | `eventName`, `eventSource`, `sourceIPAddress` (texto original), `source.ip` (IP), `awsRegion`, `recipientAccountId`, `userIdentity.principalId`, `userIdentity.arn`, `errorCode`, `readOnly`, `Outcome`, `requestParameters.userName`, `requestParameters.roleArn`, `requestParameters.policyArn`, `responseElements.ConsoleLogin` |
| `zeek/dns`, `zeek/http`, `zeek/conn` | DNS, HTTP y conexiones en JSON y TSV | `id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`, `proto`, `query`, `qtype_name`, `rcode_name`, `host`, `uri`, `method`, `status_code` según clase |
| `suricata/dns`, `suricata/http`, `suricata/flow`, `suricata/alert` | DNS, HTTP, flujos y alertas en EVE | `src_ip`, `dest_ip`, `src_port`, `dest_port`, `event_type`, `dns.rrname`, `http.hostname`, `http.status`, `alert.signature`, `alert.signature_id` según clase |
| `windows/iis` | IIS W3C, `webserver` | `cs-method`, `cs-uri-stem`, `cs-uri-query`, `sc-status`, `cs-user-agent`, `cs-username`, `cs-host`, `cs-referer`, `cs-content-type`, `c-ip` |
| `aws/route53`, `windows/dns-debug` | Route 53 Resolver y DNS debug de Windows, `dns` | `query`, `record_type`, `rcode`, `source.ip` y `destination.ip` para DNS debug de Windows |
| `azure/signinlogs`, `azure/auditlogs`, `azure/activitylogs` | Exportaciones de inicio de sesión y auditoría de Entra, tabla AzureActivity | `ResultType` (texto), `IPAddress` (IP), `UserPrincipalName`, `AppId`, `OperationName`, `Result`, `InitiatedBy.user.userPrincipalName`, `OperationNameValue`, `ActivityStatusValue`, `CallerIpAddress` según formato |
| `m365/audit`, `m365/exchange` | Unified Audit Log y carga Exchange explícita | `Operation`, `Workload`, `UserId`, `ClientIP`, `ObjectId`, `ResultStatus`, `Outcome`; Exchange también admite `Parameters` |
| `okta/okta` | Okta System Log | `eventType`, `outcome.result`, `actor.alternateId`, `client.ipAddress`, `SourceIP`, `Outcome` |
| `gcp/gcp.audit` | Cloud Audit Logs | `protoPayload.methodName`, `protoPayload.serviceName`, `protoPayload.authenticationInfo.principalEmail`, `protoPayload.requestMetadata.callerIp`, `protoPayload.status.code` (entero, ausente si falta) |
| `kubernetes/audit` | Auditoría de Kubernetes, EKS, AKS y GKE | `objectRef.resource`, `objectRef.namespace`, `Outcome`; Kubernetes, EKS y AKS añaden `verb`, `user.username`, `responseStatus.code`, `PrimarySourceIP`, `sourceIPs` (lista de IP), `stage`; GKE añade `protoPayload.methodName` y `protoPayload.status.code` (entero) |
| `windows/defender` | Creaciones de proceso y conexiones de Defender con plataforma Windows explícita | `Image`, `ParentImage`, `CommandLine`, `ParentCommandLine`, `FileName`, `FolderPath`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`; red `LocalIP`, `RemoteIP`, `LocalPort`, `RemotePort` |
| `windows/crowdstrike` | Process rollup y conexiones IPv4 o IPv6 de FDR en Windows | `Image`, `CommandLine`, `ParentBaseFileName`, `TargetProcessId` y `ParentProcessId` con ámbito del proveedor, `aid`, `cid`; `LocalAddressIP4` / `RemoteAddressIP4` o sus equivalentes IPv6 |
| `macos/eslogger` | Notificaciones de exec y creación de fichero de eslogger v1 | `Image` del destino de exec, `Arguments` como lista, `ProcessId`, `TargetFilename` y `ActorExecutable` según clase |

En las reglas de Exchange, `Parameters` con `Name` y `Value` exige que ambos estén en la misma entrada de parámetro. `Image` y `ParentImage` de Defender usan la ruta original cuando ya incluye el ejecutable y su nombre coincide con el campo correspondiente. Si solo viene el directorio, el campo queda ausente.

Una fila queda indeterminada cuando una regla necesita un campo exacto que no puede evaluar. Kubernetes, EKS y AKS conservan el evento si `sourceIPs` contiene más de 32 entradas, valores duplicados, IP no válidas o un tipo inesperado. GKE también conserva los eventos cuyo código de estado original tiene un tipo inesperado o queda fuera del rango admitido. Consulta los recuentos por fuente y regla en la TUI y revisa la evidencia original. Estos valores pueden indicar manipulación de la fuente. El informe cita la ejecución firmada y explica la cobertura parcial.

Las tablas revisadas detallan los campos admitidos, las rutas originales, las columnas tipadas y los selectores. [CloudTrail](../../crates/infra/src/sigma_pack/cloudtrail-v1.toml) · [Windows](../../crates/infra/src/sigma_pack/windows-v1.toml) · [Linux](../../crates/infra/src/sigma_pack/linux-v1.toml) · [Red](../../crates/infra/src/sigma_pack/network-v1.toml) · [Identidad cloud](../../crates/infra/src/sigma_pack/cloud-identity-v1.toml) · [Endpoint](../../crates/infra/src/sigma_pack/endpoint-v1.toml)
