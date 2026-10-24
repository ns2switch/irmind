# Decisiones de arquitectura aceptadas

`docs/PLAN.md` define los hitos H0–H8 y sus criterios de cierre. Estas decisiones precisan tres desviaciones aceptadas.

## ProposedCall no incluye risk

El nivel de riesgo lo determina `Tool` en el dominio. Así, una propuesta del modelo no puede rebajar el riesgo de la herramienta que solicita. La política evalúa el riesgo derivado del tipo de herramienta.

## DuckDB para el grafo

El grafo derivado de evidencias usa DuckDB para consultas analíticas locales sobre registros y relaciones. SQLite conserva los casos y el log firmado; el grafo se puede reconstruir desde las evidencias originales.

## Actor y procedencia separados

`Actor` identifica al firmante, `Analyst` o `Agent`, con claves distintas. La procedencia concreta del evento se registra aparte en `origin`. Esto permite verificar quién firmó cada acción sin confundir identidad criptográfica con el origen lógico del dato o la operación.
