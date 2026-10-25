# Contribuir a IRMind

IRMind está en desarrollo. Usa solo datos sintéticos en issues, pull requests, tests y ejemplos; no adjuntes evidencias reales, credenciales ni datos personales de incidentes. Para vulnerabilidades, sigue [SECURITY.md](SECURITY.md).

## Licencia y DCO

Toda contribución enviada intencionadamente al proyecto se ofrece bajo **MIT OR Apache-2.0**, sin condiciones adicionales, como indica el [README](README.md#contribution).

Cada commit de un pull request debe incluir un tráiler `Signed-off-by` con el nombre y correo del autor. El tráiler certifica el [Developer Certificate of Origin 1.1](https://developercertificate.org/); el check de CI compara el correo del tráiler con el correo del autor del commit.

```text
Signed-off-by: Nombre Apellido <correo@example.com>
```

Para añadirlo al crear el commit, usa `git commit -s`. Para corregir el último commit local, usa `git commit --amend -s`; en un PR con varios commits, firma cada uno antes de actualizar la rama. No firmes en nombre de otra persona.

## Comprobaciones locales

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --all-features --locked --test-threads 1
cargo deny check
```

Describe en el PR los cambios de seguridad, las pruebas ejecutadas y las limitaciones. Los módulos nuevos siguen las guías de `docs/`, una vez que se reabra esa fase del plan.
