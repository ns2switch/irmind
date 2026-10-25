# Avisos de dependencias

IRMind está bajo `MIT OR Apache-2.0`. Las dependencias conservan sus propias licencias; el inventario de versiones está en `Cargo.lock` y la política de licencias permitidas en `deny.toml`.

## `option-ext` 0.2.0

`option-ext` está bajo [MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/). Forma parte de una obra mayor sin cambiar la licencia del código de IRMind. El código fuente de la versión usada se obtiene en [crates.io](https://crates.io/crates/option-ext/0.2.0) o en su [repositorio](https://github.com/soc/option-ext). Los archivos de `option-ext` mantienen MPL-2.0; esta licencia no se sustituye por la de IRMind.

Antes de una distribución binaria externa formal se debe generar y revisar un inventario completo de avisos de terceros para la versión exacta publicada, incluidos los componentes nativos de SQLite y DuckDB. El pase de `cargo-deny` comprueba expresiones de licencia permitidas, pero no sustituye esa revisión de avisos.
