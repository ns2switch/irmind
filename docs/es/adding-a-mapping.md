Traducción de docs/development/adding-a-mapping.md en el commit 050c01156cc3c45f5229306b88051eb22ed68348; si hay diferencias, prevalece la versión en inglés.

# Añadir un mapeo de origen

El decodificador conserva campos originales y procedencia. Un módulo identificado
separado los interpreta como eventos comunes validados. Consulta [el inventario](mappings.md)
y [la guía de módulos](../development/adding-a-module.md); no añadas semántica al parser.

1. Selecciona SourceDecoder, dataset/canal y versiones exactas. Añade un fixture
   SourceRecordV1 sintético. Lo ausente sigue ausente; resultado desconocido es unknown.
2. Prefiere tablas TOML finitas en el crate mapping correspondiente. Usa como ejemplo
   [sshd.toml](../../crates/modules/mapping-linux/src/sshd.toml) y el
   [contrato de tablas](../development/mapping-tables.md). No hay expresiones,
   scripts, E/S, reloj, red ni clasificación implícita por texto libre.
3. Define ID, versión, esquema y selectores disjuntos. El build fija el hash de las
   tablas incluidas; las instaladas requieren admisión firmada. Solaparse es error.
4. Usa constructores de dominio para categorías, tipos, resultados, roles y ámbitos.
   No mezcles el mismo nombre en cuentas, hosts o clústeres distintos. PID no es
   lifetime; process_lifetime requiere un identificador documentado como ProcessGuid.
5. Prueba éxito, fallo, estado ausente, actor/objetivo, dos roles con el mismo valor,
   namespaces, reutilización de PID y campos hostiles. Añade contratos, bytes
   deterministas, reconstrucción y episodio sintético; las respuestas esperadas
   quedan exclusivamente en el evaluador.
6. Registra módulo y feature, actualiza inglés y español y justifica Rust nativo
   solo cuando las tablas no puedan expresar una lógica acotada. Mantén cobertura
   solo de extracción cuando no se pueda clasificar.

Ejecuta tests afectados, contratos app/dominio, fmt, Clippy estricto y preserve_order.
Nuevos puertos, dependencias o formatos firmados requieren otra decisión de diseño.
El contenido del mapeo es no confiable y nunca amplía permisos.
