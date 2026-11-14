Traducción de docs/development/catalog-case-proof-storage.md en el commit cc578084698c2a81cd78ad1ed7408163488d1f18; si hay diferencias, prevalece la versión en inglés.

# Almacenamiento de pruebas de catálogo por caso

Este documento complementa el [contrato del catálogo](skills-catalog-format-contract.md)
con una frontera explícita por caso. Las codificaciones del índice, recibo,
instalación, snapshot y exportación siguen siendo las del contrato.
[English](../development/catalog-case-proof-storage.md)

## Dos ámbitos de almacenamiento

La instalación conserva el índice firmado y verificado en el almacén global.
Antes de su primer snapshot o carga en un caso, IRMind verifica esa prueba con
las claves públicas compiladas actuales y la copia al almacén privado del caso.
La copia conserva la misma identidad de contenido. No pasa a ser evidencia,
una firma de admisión ni una raíz de confianza adicional.

La verificación y exportación leen expresamente la copia del caso. Si falta, no
la recuperan del almacén global ni de la red. Una actualización o reinstalación
global no puede sustituir la prueba histórica de un caso.

## Frontera aditiva de aplicación

Se mantienen `CatalogProofStore::publish` y `read` para la instalación global.
Se añaden dos métodos con un `CaseId` validado y explícito:

```rust
fn publish_for_case(
    &self,
    case: &CaseId,
    proof: &VerifiedCatalogIndex,
    cancel: &CancellationToken,
) -> Result<CatalogProofId, AppError>;

fn read_for_case(
    &self,
    case: &CaseId,
    id: &CatalogProofId,
    cancel: &CancellationToken,
) -> Result<CatalogIndexBytes, AppError>;
```

Las implementaciones predeterminadas devuelven un error claro de disponibilidad.
Un adaptador que implemente solo el ámbito global puede instalar paquetes, pero
no habilitarlos en un caso hasta disponer del almacén por caso. No hay caso
actual implícito, contexto ambiental mutable ni alternativa mediante los métodos
globales.

La aplicación proporciona el caso activo después de su verificación y bloqueo
habituales. Los argumentos del modelo no permiten elegir otro caso ni una ruta.
El verificador sigue siendo puro y no adquiere acceso al sistema de ficheros.

## Publicación y verificación

- El límite global sigue en 256 pruebas y 64 MiB. Cada caso tiene sus propios
  límites de 256 pruebas y 16 MiB. Cada identidad cuenta una vez por ámbito.
- Los nombres se derivan del hash dentro del directorio privado del caso, con
  los permisos Unix y las ACL de usuario de Windows existentes. Se comprueba
  espacio antes del staging, se atiende la cancelación y se sincroniza al publicar.
- La copia inmutable se publica antes del primer `SkillSnapshotV2`. Un fallo de
  publicación no permite cargar la skill. Un fallo posterior de auditoría puede
  dejar una prueba privada sin referencia, pero nunca un método admitido.
- La lectura está acotada, comprueba la identidad y verifica de nuevo el índice
  completo con las claves compiladas actuales. El nombre del fichero no basta.
- Si falta la copia o cambia, se impiden el uso de la skill y la verificación o
  exportación completas, con un error que explica qué hacer. No se descarga nada.
- El export V8 incluye exactamente las pruebas del caso referenciadas, con los
  descriptores y frames aprobados. El verificador independiente no necesita
  almacén ni red. Las skills incluidas y las instaladas sin catálogo no necesitan
  estas pruebas.

No se añade ninguna dependencia, credencial, campo firmado, etiqueta de evento,
reto de firma, marcador de caso ni límite de frame. El catálogo sigue siendo
opcional; sin claves públicas compiladas aparece como no disponible.

## Tests de contrato

1. Una prueba publicada globalmente y en A no se puede leer desde B.
2. Si se borra o altera la copia de A, aunque la global siga intacta, fallan la
   carga, la verificación completa y la exportación de A, sin recuperación global
   ni por red.
3. Cambiar la instalación global conserva la prueba y el snapshot históricos de A.
4. Se prueban publicación repetida, ambos límites, cancelación, espacio y fallos
   antes o después de publicar, con limpieza privada.
5. Una clave retirada se rechaza en admisión, uso en el caso y verificación V8.
   Autenticar solo la operación del analista sigue siendo una garantía distinta.
6. Los vectores V8 con pruebas se verifican sin conexión. Faltas, extras, cambios
   de orden, truncamientos y alteraciones se rechazan sin cambiar bytes golden.
