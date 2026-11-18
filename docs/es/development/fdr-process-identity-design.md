# Identidad de procesos de Falcon FDR

Estado: contrato propuesto; sin implementación. [English](../../development/fdr-process-identity-design.md).

## Requisito y límite actual

FDR correlaciona procesos y actividad mediante TargetProcessId, ContextProcessId y
ParentProcessId dentro de aid; son identificadores del proveedor, distintos del
PID del sistema. El [ejemplo oficial](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Combine%20ProcessRollup2%20and%20NetworkConnectIP4%20Events.md)
expresa esa unión. cid también debe separar los tenants.

El dominio actual admite procesos con ámbito de registro o vida de proceso y
rechaza Host/Account genéricos. process_lifetime sigue reservado al ProcessGuid
de Sysmon en los mapeos incluidos. No se reutilizará ese ámbito ni una identidad
sin tipo para eludir el contrato con IDs, PIDs, nombres o instantes de FDR.

## Ámbito cerrado propuesto

Añadir EntityIdentityScope::ProviderProcess { provider, tenant, host }, con un enum
de proveedor cerrado que inicialmente solo incluye CrowdStrikeFdr. El valor de la
entidad es el ID nativo canónico; tenant/host proceden de cid/aid originales, con
32 caracteres hexadecimales cada uno. Se conserva su escritura sin aplicar una
regla implícita de cambio de mayúsculas. Valores ausentes o inválidos se conservan
con aviso de cobertura y no crean uniones entre registros.

Solo process.entity_id (subject) y process.parent.entity_id (parent) pueden usarlo;
los campos PID no. La clave de orden es (provider_process, provider, tenant, host, 0)
más el valor de la entidad, como ahora. Otro proveedor, tenant, host o ámbito
produce una identidad distinta aunque coincida el número.

La aplicación comprueba el ámbito frente al SourceRecord original: decodificador
y formato exactos, cid/aid y campo nativo permitido para el tipo de registro.
ProcessRollup2/SyntheticProcessRollup2 usan TargetProcessId/ParentProcessId; la
actividad documentada usa ContextProcessId. RawProcessId permanece en ámbito de
registro. Otros pares de evento/campo necesitan una entrada explícita respaldada
por documentación.

La verificación de dominio/export comprueba ámbito, campo, valor y host. Sin los
originales se autentica la afirmación firmada de ese ámbito; la reconstrucción
completa además la reproduce desde el original y sus versiones exactas. No se
reconstruye SourceRecord a partir del texto normalizado.

## Ampliaciones finitas del intérprete

Añadir provider_process, con proveedor y rutas explícitas de tenant/host. Su uso
inicial queda restringido a parser-fdr, fdr-source-v1, su formato y los campos
nativos aprobados. La validación en ejecución comprueba los valores originales y
rechaza usar un PID o un instante como identidad del proveedor.

Añadir u64_id para texto decimal o número JSON entero: rango 1..=u64::MAX,
representación decimal canónica, sin flotantes ni expresiones. Fracciones,
exponentes, negativos, cero, desbordamiento y otros tipos conservan el original
con aviso, sin observación en este ámbito. Clasificación, resultado y roles siguen
en TOML finito. No se añade E/S, red, reloj, estado global ni lenguaje arbitrario.

## Custodia y formatos

Es una ampliación del formato firmado que requiere variante y golden nuevos.
Los [bytes de ámbito](../../development/fdr-process-vectors/scope.json), su
[SHA-256](../../development/fdr-process-vectors/scope.sha256) y los
[casos](../../development/fdr-process-vectors/cases.json) son vectores propuestos,
no una afirmación de soporte en el motor actual.

V3 ya almacena el descriptor canónico de ámbito: no se añaden columnas, sobres,
secciones de export ni cambios de sello. Los bytes y golden actuales se conservan;
los nuevos quedan cubiertos por hash, identidad del mapeo, reconstrucción y export.
El CHANGELOG de v0.5.5 debe avisar de que versiones anteriores no interpretan este
ámbito. No se usa el marcador de caso 5 ni export V9, reservados a consultas en
origen. El hash del mapeo vincula tablas, ámbito y conversión. Rige la política
pre-1.0; definiciones que necesiten una primitiva no disponible se desactivan con
un aviso, sin impedir el arranque.

## Pruebas de aceptación

- TargetProcessId/ContextProcessId y ParentProcessId se unen solo con el mismo
  cid/aid; no hay mezcla entre hosts o tenants.
- PIDs reutilizados y ámbitos de registro, Sysmon y proveedor permanecen distintos.
- Se rechaza el ámbito en campos PID, tipos no proceso, otros parsers, versiones,
  proveedores o rutas nativas no aprobadas.
- Se prueban u64 máximo, ceros iniciales, datos inválidos y metadatos ausentes, sin
  alternativa global/host/PID.
- No cambian originales, procedencia, taint, política, techo, 32 observaciones,
  frames de 1 MiB ni límites de fuentes y consultas.
- Golden actuales/nuevos, preserve_order, igualdad 1/2/4/N, reconstrucción, sello,
  export e investigación sintética de endpoint.

## Alternativa

Mantener los procesos de FDR en ámbito de registro, con los IDs nativos solo como
campos originales consultables. No requiere ampliar el formato, pero no ofrece
el grafo de procesos entre registros pedido y debe declararse cobertura parcial.
