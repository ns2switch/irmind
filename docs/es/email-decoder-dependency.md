# Dependencia para el decodificador de correo acotado

[English](../development/email-decoder-dependency.md)

Se propone `mail-parser = "=0.11.9"`, sin features por defecto, solo en
parser-email. Licencia MIT / Apache-2.0 y archivo publicado con SHA-256
`4ec00bda90c6e645a54506c630c2820cd6b1890cfd2b0a169b50f74b2b8c7c86`.
El código revisado no contiene bloques unsafe. Su única dependencia obligatoria
es la macro de compilación hashify 0.2; encoding, serde y archivo opcionales
permanecen desactivados. Revisar resolución exacta antes de integrar, sin
excepciones a la política de dependencias. La rama 1.0 exige Rust 1.98 y este
proyecto usa 1.95; no se propone actualizar Rust ni copiar o bifurcar el parser.

Usar **solo el parser de cabeceras**, no el recorrido MIME completo sin límites.
IRMind controla un recorrido iterativo: hasta 32 MiB por fuente, 1.024 cabeceras
totales, 64 KiB por bloque de cabeceras, 16 contenedores anidados y 256 partes.
Rechazar estructuras inválidas o excesivas con motivo visible. Conservar orden
y offsets de cabeceras, especialmente Received, y firmar el original completo.
Base64/quoted-printable se decodifican con cotas; nunca ejecutar ni descomprimir
adjuntos. Solo metadatos y SHA-256 de sus bytes decodificados. URLs literales sin
seguirlas; sin renderizar HTML. Charset/cuerpos no admitidos quedan en el original
con aviso de cobertura. Tainted, ContentGuard y procedencia sin cambios; sin
capacidades nuevas de red, shell, política o process_lifetime.

La alternativa sin dependencia es implementar la gramática RFC soportada en
IRMind: más código de direcciones, folding, palabras codificadas y parámetros,
más mantenimiento y corpus de conformidad; nunca presentar cobertura incompleta
como completa. Pruebas de cabeceras y MIME malformados, nombres codificados,
orden de Received, adjuntos grandes, URLs sin red, inyección, cancelación,
fuzzing ASan de diez minutos y benchmark release.

[Crate publicado](https://crates.io/crates/mail-parser/0.11.9),
[código oficial](https://github.com/stalwartlabs/mail-parser),
[RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html).
