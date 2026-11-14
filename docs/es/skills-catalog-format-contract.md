Traducción de docs/development/skills-catalog-format-contract.md en el commit 62587a090941cf0919207e7dafae763bcfb22037; si hay diferencias, prevalece la versión en inglés.

# Contrato del índice firmado, admisión y caso/export del catálogo

Propuesta de la [arquitectura aprobada](../development/skills-catalog-install.md).
Solo documentación y vectores: no crea repositorio, clave real, secreto,
dependencia, puerto ni implementación. Primero revisión del contrato; después
implementación y creación de `irmind-skills`.
[English](../development/skills-catalog-format-contract.md)

## Alcance

Se reutilizan Ed25519 estricto, SHA-256, compilador/almacén de skills, clave Analyst
y envelope global. El publicador no es un Actor ni una clave de caso. No cambian
desafíos de firma, Parquet V3, sello V2 ni `export_case`. Sigstore y procedencia
son comprobaciones externas, no un paso o dependencia de IRMind.

Puntos concretos de revisión: índice/paquete/prueba V1, instalación e instantánea
V2 para todos los orígenes y cola V8 compartida con subagentes. V7 y golden actuales
no se modifican. La implementación tendrá un único formato actual V2, sin lectores
históricos. Payloads antiguos no soportados quedan desactivados con aviso, sin
impedir autenticar la cadena global u otras operaciones. Readmitir es explícito,
no migrar. SkillLoadV1 conserva sus bytes y validaciones y referencia la nueva
instantánea. El marcador de formato/creador rechaza casos no soportados al abrir.

Marcador compartido propuesto: CaseCreated.version=4, con los mismos campos
ordenados version,title,severity,scope,budget y presupuesto inicial obligatorio.
Sin otros cambios al evento o desafío. Versión 3/desconocida se rechaza antes
del trabajo, con guía para usar el ejecutable creador o reingerir, sin inventar
su patch exacto. case-created-v4.json fija bytes; el código actual no cambia.

## Claves y confianza

Lista compilada de 0–8 claves públicas Ed25519 de 32 bytes; cero significa catálogo
no disponible. ID = SHA-256 minúsculo de la clave pública, 64 hex. Orden y unicidad
por ID; rechazar claves débiles/inválidas. No se acepta una clave del índice,
paquete, comando o fichero instalado. Firma exactamente 64 bytes, verificador
estricto actual; sin negociación de algoritmo ni fallback.

Digest de keyset: SHA256(`irmind-catalog-keyset-v1\0` || u64(count) || claves32 en
orden de ID). Registra una decisión; no es una raíz descargada. Añadir claves no
invalida un recibo si su clave concreta sigue admitida. Retirarla bloquea nuevas
admisiones y uso activo. La historia Analyst puede seguir autenticándose;
arranque desactiva la skill con explicación y permite desactivarla explícitamente,
sin corromper toda la historia ni cambiar el origen. La verificación completa de
caso/export rechaza confianza de catálogo no disponible. Diagnósticos de firmas
no deben confundir autenticación Analyst con confianza del publicador.

La retirada requiere actualizar IRMind: los ejecutables antiguos conservan sus
claves. No hay reloj, feed de revocación ni refresco de raíces. La clave privada
real se configura después de aprobar el contrato, solo en el environment protegido
del publicador de tags. Semilla32 codificada como 64 hex minúsculos, leída en memoria
y contrastada con el ID público esperado; nunca Git, argumentos, logs ni assets.
Ensayos de ramas usan claves sintéticas y no acceden al secreto real. Las claves
de vectores nunca se compilan como confianza de producción.

## Índice canónico y firma

Assets `index.json` y `index.ed25519` (firma64 raw). JSON UTF-8 exacto, orden fijo,
sin espacios innecesarios ni salto final; enteros y null explícito donde proceda.
Rechazar desconocidos/duplicados/no canónico con límites previos. Se firman los
bytes originales:
`UTF8("irmind-skill-catalog-index-v1") || 00 || u64be(len) || index_bytes`.
Se firma esa preimagen completa. index_sha256 es SHA-256 ordinario del JSON.

Orden de cabecera: format_version (1), catalog (`ns2switch/irmind-skills`), key_id,
release_tag, release_commit, release_sequence, entries. Tag SemVer `vMAJOR.MINOR.PATCH`
con prerelease acotada opcional, sin build metadata, rutas/controles ni ceros
numéricos iniciales, ≤64 ASCII. Commit40 hex minúsculos: afirmación del publicador,
no verificación interna de procedencia GitHub. Secuencia u64 positiva. Congelar
tag, commit firmado y digest durante toda la operación. De 0 a 1.024 entradas,
nombres únicos ordenados.

Orden de entrada: name,version,package_sha256,asset,asset_sha256,asset_bytes,
minimum_irmind_version,target_schema,interpreter,sources,mappings,coverage.
Nombre/versión usan constructores actuales; asset es basename ASCII ≤128 de
letras/dígitos/`._-`, sin punto inicial, `..`, dispositivo o alias. SHA minúsculo64;
asset positivo ≤1 MiB. Versión mínima SemVer no sustituye soporte de intérprete o
esquema. Fuentes/mapeos: arrays ordenados únicos de hasta 32 IDs/64 bytes.
Fuentes coinciden con metadatos del paquete; mapeos/cobertura son requisitos del
publicador contrastados con módulos compilados y perfiles reales del caso, no
prueba de cobertura. Coverage ordena status (complete/partial/unavailable) y
description (≤512 UTF-8), saneada al mostrarse.

Índice ≤1 MiB, profundidad 8, 100.000 valores escalares/contenedores y sin URLs
arbitrarias. Analizar cabecera solo para localizar la clave; no confiar en entradas,
rutas o vista previa antes de verificar. Errores acotados sin contenido del paquete.

## Paquete y prueba completa

Asset JSON de datos, por ejemplo synthetic-triage-1.skill.json: format_version=1,
files ordenados de `{path,contents}`. SKILL.md más hasta 16 recursos; ≤1 MiB de
transporte y ≤128 KiB de texto original. Se mantienen los límites de fichero,
frontmatter y ruta, sin extractor ni dependencia nueva. Rechazar campos ajenos,
duplicados, alias, extras y recursos no permitidos.

Verificar tamaño/SHA del asset antes de compilar, construir el mismo SkillPackage
y comprobar el compromiso irmind-skill-package-v1. Nombre/versión/esquema/
intérprete/fuentes deben coincidir. Hash de transporte y compromiso lógico son
distintos. ContentGuard puede bloquear un paquete firmado; nada se ejecuta ni
entra en system.

ID de prueba: SHA256(`irmind-skill-catalog-proof-v1\0` || u64(index_len) || índice
completo || firma64). Conservar todo el índice: la entrada sola no verifica su
firma. ID de entrada: Id(irmind-skill-catalog-entry-v1, JSON), con
Id(D,J)=SHA256(UTF8(D)||00||JSON_canónico).

CatalogProofStore es privado e inmutable por hash, con hasta 256 pruebas/64 MiB
globales y 256/16 MiB por caso. Límites de paquetes/historia siguen separados.
Si se llena, rechazar admisiones; sin expulsar referencias. Staging con permisos
actuales/ACL, espacio previo, sync, cancelación y limpieza. Prueba ausente desactiva
uso/recuperación; restaurar requiere importación local o descarga explícita, nunca
red en segundo plano.

## Puertos y transacción

Firmas completas en inglés; se proponen:

- SkillCatalogSource::index(AnalystCatalogRequest,cancel) → PortFuture de
  CatalogIndexBytes; package(VerifiedCatalogRelease,CatalogAsset,cancel) →
  PortFuture de BoundedPackageBytes.
- CatalogIndexVerifier::verify(bytes,FrozenCatalogRelease) → VerifiedCatalogIndex;
  puro, sin E/S, reloj, secretos ni admisión, usando Ed25519 existente.
- CatalogProofStore::publish(VerifiedCatalogIndex,cancel) → CatalogProofId;
  read(id,cancel) → CatalogIndexBytes. Leer no concede confianza: se reverifica.

Capacidades verificadas tienen constructores privados, sin deserializador del
modelo. El request solo nace de la instalación del analista. Offline invoca el
mismo verificador y nunca el puerto de red. No hay compilador alternativo.

Por operación: 4 MiB descargados incluyendo metadatos, cuerpos índice/paquete,
firma64, hasta tres redirecciones/petición y 30 segundos/petición. HTTPS y saltos
validados bajo assets del repo GitHub fijo, sin reenviar credenciales. Sin hosts
arbitrarios, datos del caso, credenciales ambientales o token GitHub almacenado.
No hay red de arranque, modelo, cancelación de preview ni importación offline.

Compilar/sanear, mostrar origen/clave/tag/hashes/herramientas/contenido/diff,
comprobar colisiones, revalidar bajo bloqueo global. Persistir prueba verificada,
firmar snapshot completo y publicar paquete atómicamente con recuperación actual.
Fallo de firma no autoriza; fallo posterior de publicación deja recuperación
visible. Revalidar prueba/clave/compilador/nombres al activar o recuperar. El modelo
no instala, actualiza, activa ni elige el origen.

La historia firmada fija tag/commit/secuencia/digest aceptados. Mismo tag o
secuencia con bytes distintos es equivocación y se rechaza. Bajar secuencia o
versión exige diff y consentimiento específico; el máximo aceptado no disminuye,
incluso al desactivar. El primer índice offline no prueba frescura.

## Instalación V2 y caso

Operación skill-installation-v2:hexJSON. Orden:
format_version=2,name,skill_version,package_sha256,origin,active,
previous_operation,catalog,files. Orígenes globales organization/analyst/catalog;
bundled y nombres del núcleo se rechazan. No catálogo → catalog null. Catálogo →
recibo completo. Se mantienen enlaces por skill, ficheros originales, firma global
Analyst y límite de payload codificado de 768 KiB.

Recibo: catalog,release_tag,release_commit,release_sequence,key_id,index_sha256,
proof_sha256,entry_sha256,asset,asset_sha256,asset_bytes,verification_policy,
keyset_sha256,offline,downgrade_confirmed. Política compiled-ed25519-v1. Booleans
reflejan el flujo real. ID con dominio irmind-skill-catalog-receipt-v1. Todo coincide
con el índice/entrada verificados; ni origen declarado ni cosign manual lo sustituyen.

SkillSnapshotV2, etiqueta skill-snapshot-v2 y dominio irmind-skill-snapshot-v2:
format_version=2,name,skill_version,target_schema,interpreter,package_sha256,origin,
release_inventory_sha256,admission_operation_sha256,catalog_receipt_sha256,files.
Actor Analyst, evidence null. Bundled exige inventario y otros null; analista/
organización exigen admisión V2 y otros null; catálogo exige admisión, recibo y
prueba completa con inventario null. Siguen igualdad de paquete, límites acumulados
y prohibición de colisión con el núcleo.

El recibo es metodología, no EvidenceHash. Copiar prueba verificada al caso antes
del primer contenido expuesto. Instantáneas en uso/históricas no se mutan.
SkillLoadV1 conserva campos/codificación, apunta al snapshot nuevo y mantiene firma
Agent, rangos, hashes de guard y límites compartidos.

## Export V8 y verificador

Misma cabecera/magic y secciones que el contrato de subagentes. La sección de
admisiones contiene los envelopes SignedOperation actuales con payloads V2
referenciados. Después, contador u64 de catálogo y sus descriptores/chunks, y
contador u64 de chunks de subagentes. Siempre ambos, incluso cero; sin sección de
tipos comunitarios. Extensión no soportada no vacía falla.

Descriptores ordenados por proof ID: proof_sha256,index_sha256,key_id,signature,
index_bytes,chunks. Firma hex64, índice ≤1 MiB. Chunks ordenados:
`{proof_sha256,ordinal,bytes_hex}`, hasta 256 KiB decodificados; exactamente
ceil(index_bytes/256 KiB), de 1 a 4. Sin huecos/alias. Longitudes u64 big-endian,
frame serializado ≤1 MiB. Verificar en streaming con tope de 16 MiB de pruebas del
caso. Solo pruebas exactamente referenciadas, deduplicadas.

Comprobar claves Analyst/Agent, firma global, paquete/metadatos, enlaces de
snapshot/load, índice canónico/firma/clave, entrada/asset, recibo y conjunto exacto
de pruebas. Rechazar ausentes/extras/duplicados/reordenados/modificados, claves
retiradas y bytes finales. Offline sin red, raíces, verificador externo, modelos
o código descargado. Saneado al mostrar. El sello compromete referencias actuales;
no convierte afirmaciones del catálogo en evidencia.

## Vectores y puerta

[Vectores](../development/catalog-format-vectors/README.md): índice sintético
Ed25519 válido, paquete con compromiso actual conocido, instalación firmada con
el desafío global actual, snapshot nuevo, load sin cambiar forma y fragmentos V8.
SHA256SUMS cubre ficheros. Pruebas negativas: claves desconocidas/retiradas, campos
duplicados, cambios, tags incorrectos, prueba completa ausente, colisión con núcleo,
downgrade/equivocación. Nunca son claves de producción.

Son fragmentos, no casos/archives completos. Implementación probará instalación,
update/reinicio, carga, verify, sello/export independiente, confianza ausente,
recuperación y ausencia de red en offline/arranque/modelo. Sin alterar golden
actuales o añadir lectores históricos. Repositorio y environment/clave reales
se crean después de aprobar este contrato, no en esta PR.
