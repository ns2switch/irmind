# Configurar la clave de firma del catálogo

Procedimiento del mantenedor para el [contrato firmado](https://github.com/ns2switch/irmind/pull/287).
La clave de producción se genera en tu máquina, fuera de cualquier clon de Git.
IRMind y el agente de desarrollo solo necesitan la clave pública y su `key_id`.
No compartas la semilla ni la clave privada.

## Generación local

Necesitas Python 3 y OpenSSL 3. Ejecuta el bloque de
[generación de la guía en inglés](../development/catalog-key-setup.md#generate-locally),
que es la receta compartida. Crea un directorio privado nuevo, rechaza sobrescribir
material existente y guarda `catalog-key-material/catalog-seed.hex` con permisos
0600. Ese fichero contiene exactamente 64 caracteres hexadecimales minúsculos:
la semilla aleatoria de 32 bytes. No es una clave privada expandida de 64 bytes.

La clave privada DER solo pasa a OpenSSL por stdin; no se escribe en un fichero
ni aparece en argumentos. Se imprimen únicamente `public_key` y `key_id`.
La clave pública son 32 bytes raw representados con 64 hex; no un PEM o DER.
El identificador es SHA-256 de esos bytes públicos, no de su representación textual.

## Environment y secreto

En Settings → Environments de `ns2switch/irmind-skills`, crea `release` con
revisión obligatoria del mantenedor y despliegues permitidos solo desde **tags**
`v*`, nunca desde ramas. El job de publicación real referencia ese environment;
los ensayos manuales usan claves sintéticas y no piden acceso a él. Véase la
[guía de GitHub](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

Guarda la semilla como secreto de ese environment, no del repositorio ni de la
organización. Desde el directorio que contiene `catalog-key-material`:

```sh
gh secret set CATALOG_ED25519_SEED_HEX --repo ns2switch/irmind-skills --env release < catalog-key-material/catalog-seed.hex
```

El valor se lee por stdin. Conserva una copia de seguridad protegida según tu
política de claves y elimina el fichero local sin cifrar después de configurar
el secreto y su respaldo. Nunca lo pongas en Git, chat, argumentos, logs o assets.

Comparte únicamente los dos valores públicos para revisar el cambio de la clave
esperada del publicador y la lista compilada en IRMind. Ninguna clave sintética de
test se admite como confianza real. La publicación queda inhabilitada hasta
configurar los valores públicos y el environment protegido. Añadir o retirar una
clave pública exige una release de IRMind; el índice no instala raíces nuevas.
