# Paquetes instalables de reglas Sigma

[English](../../development/sigma-package-installation-contract.md)

**Estado:** el analista aprobó compartir el repositorio y la clave. Quedan
por revisar los vectores finales y el transporte de reglas de SigmaHQ.

## Catálogo y clave de firma

| Opción | Ventajas | Inconvenientes |
| --- | --- | --- |
| **Aprobada** · reutilizar `irmind-skills` y su clave Ed25519 | Un repositorio, un proceso de contribución, un entorno protegido y una clave que mantener. Se reutiliza el flujo de publicación. | La misma clave autoriza ambos catálogos. Un incidente en la clave o el workflow puede afectar a las dos clases de paquetes. La rotación y la publicación quedan acopladas. Cada catálogo necesita sus propios nombres de artefactos y su secuencia. |
| Usar un catálogo separado con clave propia generada por el mantenedor | La confianza, los plazos de publicación, las licencias, el historial de versiones y la revocación quedan separados. | Otro repositorio y entorno protegido, workflows separados, generación de la clave y una release de IRMind que incluya su clave pública. |

Sigma usa el directorio `sigma/` de `ns2switch/irmind-skills`, con
`sigma-index.json`, `sigma-index.ed25519`, nombres de artefactos
propios y una secuencia independiente. La publicación conserva el
entorno protegido `release` y el secreto `CATALOG_ED25519_SEED_HEX`.
Los dos índices usan el mismo conjunto de claves y distintos dominios
de firma. Los vectores verifican cada índice en su dominio y lo rechazan
al intercambiarlos. La rotación o retirada de una clave afecta a ambos
catálogos y exige una release de IRMind. La CI de Sigma utiliza la
admisión, el compilador y las tablas de IRMind en un job separado del
de las skills.

## Índice y origen de los paquetes

El fichero local o comunitario contiene metadatos JSON canónicos,
el manifiesto `SigmaPackManifestV1` y el YAML original en el orden
de ese manifiesto. La instalación comprueba nombres, licencia,
procedencia, tamaños y hashes, y pasa las reglas por la admisión y
el compilador existentes. Conserva los techos de 4.096 reglas, 64 KiB
por regla y 64 MiB en total. Todo es dato. No se extraen rutas a disco.

El índice Sigma firmado fija repositorio, clave, tag, commit y secuencia.
Cada entrada fija versión, versión mínima de IRMind, licencia, manifiesto,
origen y cobertura declarada. Para una release de SigmaHQ, el índice
registra la URL oficial, SHA-256 y atribución DRL 1.1. La selección
revisada contiene solo coordenadas y hashes. El catálogo no redistribuye
el YAML de SigmaHQ. El fichero ZIP original se verifica antes de leerlo.
Una selección explícita permite omitir reglas fuera del subconjunto
admitido y la vista previa muestra cuántas quedaron fuera. La ruta oficial queda pendiente de la [comparación de transportes](../../development/sigmahq-package-transport-review.md) y de su aprobación.
[Release fijada de SigmaHQ](https://github.com/SigmaHQ/sigma/releases/tag/r2026-07-01) ·
[Licencia](https://github.com/SigmaHQ/sigma/blob/552f3fee420ef232a8e5790c4fae591847e32347/LICENSE).

## Operaciones del analista

- `/sigma list` y `/sigma info <nombre>` consultan datos locales. Dentro
  de un caso, `info` muestra las reglas que compilan en todas, algunas o
  ninguna de las clases disponibles y por qué se omiten. Distingue la
  previsión local de la cobertura declarada por el editor.
- `/sigma install catalog:<nombre>` usa la red por acción expresa.
  También se admite la instalación sin conexión con el índice, su firma
  y el fichero exacto descargados previamente, o desde un paquete local
  con su origen declarado como tal. El analista revisa licencia,
  procedencia, versiones y hashes antes de firmar.
- `/sigma update <nombre>` muestra las diferencias de reglas, licencia,
  cobertura y origen. El retroceso de versión y la reutilización de
  una secuencia, tag o versión con contenido distinto se rechazan.
- `/sigma remove <nombre>` firma la desactivación. Se conservan los
  máximos de versión y secuencia y las pruebas que ya cita un caso.
  La recuperación de una instalación interrumpida usa los bytes
  locales autenticados.

Las skills pueden recomendar un nombre o una versión. Instalar no
concede permisos ni ejecuta reglas. El modelo, las skills y los
subagentes carecen de autorización para instalar, confirmar o acceder
al catálogo. Cada ejecución conserva los límites y la política del
caso y requiere su propia admisión firmada.

## Custodia y pruebas

La propuesta añade la operación global firmada
`SigmaPackageInstallationV1` y el registro de caso
`SigmaCaseRunAdmissionV1`. El segundo fija la instalación exacta,
el manifiesto, el inventario y las fuentes, la ventana, la tabla,
las reglas compiladas y el presupuesto. El checkpoint de la ejecución
apunta a esa admisión. Ambos registros de caso y los hallazgos se
publican juntos. El export V10 usa tres nuevos tipos de objeto dentro
de la sección Sigma para la instalación firmada, la prueba de catálogo
y los metadatos. El destinatario puede verificar sin red las reglas
ejecutadas y la procedencia firmada, incluso tras actualizar o eliminar
el paquete. Se conservan la cabecera, los recibos históricos y los
límites actuales.

La CI del catálogo comprueba la licencia declarada y usa la misma
admisión, el mismo compilador y las mismas tablas que IRMind para
publicar la cobertura. Los PRs de forks usan permisos de solo lectura.
La versión inglesa fija el detalle del wire y las pruebas negativas.
Los [vectores finales](../../development/sigma-package-vectors/wire.json) cubren ambas firmas, la instalación, la admisión de caso y los tres objetos nuevos de V10. Los registros esperan su revisión.
