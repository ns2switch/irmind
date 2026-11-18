# Extensiones de consultas posteriores a v0.6

[English](../development/source-queries-deferred.md)

**Solo diseño futuro; excluido de v0.6.** No autoriza implementación, sección del export actual ni permisos.

## Consultas desde subagentes

Para vincular fuentes remotas y reservas del plan completo, proponer
SubagentPlanV2, nueva etiqueta/dominio `irmind-subagent-plan-v2`: todos los
miembros V1 y `query_resources` obligatorio; format_version pasa a 2.
Payload V2 usa J y su dominio nuevo, sin reinterpretar el codec V1. Array por task_id con
`task_id,sources,scope,scan_bytes,retained_rows,retained_bytes`; hasta 32 fuentes
configuradas únicas por hijo, nunca hashes locales ficticios. Los task ID
mantienen su cálculo actual, sin hash de vuelta al plan padre. Aprobación,
reserva y checkpoint existentes referencian la nueva identidad en sus campos
hash sin cambiar codec. Así el consentimiento cubre toda la asignación antes de
arrancar. Sin entrada de recursos, el hijo no consulta fuentes remotas. Plan V2
y umbral ampliado son puntos explícitos de revisión.

La consulta consume llamadas y escaneo/retención. Cada hijo usa la misma bolsa.
Extensión propuesta del 25%: comparar la reserva del plan completo en escaneo,
filas y bytes retenidos con sus asignaciones restantes; superar cualquiera exige
consentimiento Analyst. Demanda positiva con saldo cero se rechaza; Analytics
sin demanda de escaneo no inventa 0/0. Siguen los umbrales de tokens/llamadas/bytes
y la preferencia de confirmar todos los planes. Un hijo nunca se autoaprueba.


## Reverificación remota de versión exacta

RemoteOriginalVerificationV1: version,case_id,admission,seal,source_manifest,object,method,
observed_at,outcome,observed,sha256,transfer_bytes,reason,nonce. object fija versión
inmutable. Métodos metadata/sha256; resultados identity_match,digest_match,changed,
missing,denied,unavailable,cancelled. Metadatos nunca digest_match; ETag no es
SHA-256 y 403 ambiguo no es missing. Hash distinto es changed aunque coincidan
ETag y tamaño.

Envoltura `{payload,public_key,signature}`: payload es hex de J, clave pública y
firma Ed25519 en hex. Desafío
`"irmind-remote-original-verification-v1" || 00 || u64(len(J)) || J`.
ID=SHA-256 del desafío. Comparar clave con Analyst/sello esperado, no solo con
la propia envoltura. Nonce nuevo de 32 bytes, distinto de delimitadores UNTRUSTED.
No inferir caducidad ni reemplazo de recibos anteriores.

Antes de comprobar, Analyst firma operación global
remote-original-verification-admission-v1: con hex(J({version,case_id,seal,
source_manifest,object,method,transfer_bytes,policy,at,nonce})). admission del
recibo es el hash de esa operación, incluida como prueba en export V9. Fija
objetivo/método/máximo/política antes de la red; metadata no autoriza sha256.

El broker único conserva reservas/uso separado bajo el bloqueo caso/sello,
partiendo del saldo de transferencia/llamadas autenticado al sellar y restando
comprobaciones pendientes y uso separado previo entre procesos. No duplica el
presupuesto. Transferencias inciertas mantienen o cargan su cota hasta reconciliar;
un timeout no libera capacidad. Agotar bloquea nuevas comprobaciones, sin
ampliación implícita tras sellar ni excepción de deuda de tokens.

No reabrir/añadir a cadena sellada. Guardar recibo independiente del sello fijo;
incluirlo requiere otro fichero de export, nunca sobreescribir el anterior. Un
recibo solo prueba la observación en su instante. No exportar credenciales. GET
posterior usa el saldo restante en esa sesión admitida, sin editar el ledger
sellado; el recibo conserva uso firmado y manda el techo de organización.


## Vectores de la propuesta anterior

[Vectores aplazados](../development/source-query-format-vectors/deferred/README.md), conservados para una revisión futura; no pertenecen al formato ni a las pruebas de v0.6.
