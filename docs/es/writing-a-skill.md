Traducción de docs/development/writing-a-skill.md en el commit 050c01156cc3c45f5229306b88051eb22ed68348; si hay diferencias, prevalece la versión en inglés.

# Escribir una skill forense

Una skill es metodología, no código ni evidencia. Consulta [la guía de uso](skills.md)
y [el diseño](../development/skills-design.md). Escribe texto propio bajo MIT OR
Apache-2.0. Crea una carpeta con SKILL.md y recursos de consulta/referencia admitidos.
La [guía en inglés](../development/writing-a-skill.md) contiene un frontmatter mínimo
completo; usa [linux-triage](../../skills/linux-triage/SKILL.md) como ejemplo actual.

El frontmatter TOML va entre líneas +++ e incluye format irmind-skill-v1, name,
description, version, author, license, target_schema, tools, sources, categories e
invocable. Declara solo herramientas mínimas conocidas. Una lista no concede permisos.

Incluye fuentes y mapeos necesarios, recogida autorizada, método ordenado, consultas,
explicaciones alternativas, condiciones para un hallazgo y referencias ATT&CK si
están justificadas. Una fuente ausente produce un aviso de cobertura: no inventes
roles, resultados o ataques. Las referencias respaldan el método, no las conclusiones.

El paquete admite 128 KiB, hasta 16 recursos y 32 KiB por recurso y metodología.
Comprueba la lista de extensiones del compilador actual: md, toml, json, csv, yaml,
yml. Nada de scripts, ejecutables, enlaces simbólicos ni descargas automáticas.

Instala una carpeta local desde `/skills` en un directorio desechable, revisa contenido
y firma su admisión. Invoca el nombre como comando. Puedes validar sin instalar con
el ejemplo validate_skill del binario: usa el lector y compilador reales de IRMind.
Añade un episodio scripted con ingesta, carga de skill, consultas, confirmación del
analista, verify, sello y exportación independiente. Respuestas esperadas separadas.
Añade el modelo falso obediente con evidencia hostil: ni metodología ni evidencia
pueden eludir política, alcance, herramientas declaradas o aprobaciones.

Las contribuciones requieren DCO, pruebas afectadas y documentación bilingüe. El
catálogo comunitario es independiente del núcleo; su publicación sigue pendiente
de la clave de producción. No dupliques nombres incluidos en el binario.
