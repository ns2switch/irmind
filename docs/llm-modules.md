# Módulos LLM de IRMind

Cada proveedor es un crate compilado en el binario. Ninguno se habilita por defecto: el analista elige uno con `--llm-module`. El modelo solo devuelve texto y propuestas; la aplicación valida cada propuesta, aplica la política y registra la decisión antes de despachar una herramienta.

## Proveedores disponibles

| Selección | Feature | Modelo (variable no secreta) | Clave (cuenta del llavero) | Protocolo |
| --- | --- | --- | --- | --- |
| `llm-openai-compatible` | incluida | `IRMIND_MODEL` | `OPENAI_API_KEY` para la API oficial; `IRMIND_LLM_API_KEY` para otra URL | Chat Completions; URL opcional en `IRMIND_LLM_BASE_URL` |
| `llm-anthropic` | `llm-anthropic` | `IRMIND_ANTHROPIC_MODEL` | `ANTHROPIC_API_KEY` | Messages |
| `llm-deepseek` | `llm-deepseek` | `IRMIND_DEEPSEEK_MODEL` | `DEEPSEEK_API_KEY` | Chat Completions |
| `llm-openrouter` | `llm-openrouter` | `IRMIND_OPENROUTER_MODEL` | `OPENROUTER_API_KEY` | Chat Completions |

Las variables de la tabla sirven como nombres de configuración, no como vías para pasar secretos. La raíz de composición lee las claves del llavero del sistema con servicio `irmind-module` y cuenta igual al nombre indicado. Las credenciales nunca se leen de variables de entorno dentro de un módulo. En Linux se requiere un servicio de secretos persistente.

```bash
cargo build --release --features llm-anthropic,llm-deepseek,llm-openrouter
IRMIND_ANTHROPIC_MODEL=<MODELO_APROBADO> ./target/release/irmind --llm-module llm-anthropic ask <CASE_ID> "Investiga esta alerta"
```

`--llm-module` también admite `IRMIND_LLM_MODULE`. Ollama local puede usar HTTP sin clave solo en loopback, y el mismo adaptador acepta HTTPS si Ollama está servido con TLS. Los servicios remotos requieren HTTPS y una clave específica del destino. Los clientes no siguen redirecciones y rechazan streams incompletos. Antes de activar un servicio externo, confirme su región, retención y tratamiento de datos con el responsable de cumplimiento. La redacción basada en patrones no garantiza detectar toda información sensible.

## Contrato para un proveedor nuevo

1. Cree `crates/modules/llm-<nombre>/` con `#![forbid(unsafe_code)]`, edición y lints del workspace. Declare un `MODULE_ID` estable y un `ModuleManifest` con `ModulePort::Llm`, sin herramientas y con cada campo de configuración tipado como secreto o no secreto.
2. Implemente un constructor `from_config(&ModuleConfig)` que valide el endpoint, modelo y credenciales inyectadas. La raíz de composición lee la configuración no secreta del entorno y los secretos del llavero. El módulo no consulta ni el entorno ni el llavero.
3. Implemente `Module::register(self: Box<Self>, registry: &mut ModuleRegistry, config: &ModuleConfig) -> Result<(), AppError>` y registre el puerto con `registry.add_llm(MODULE_ID, self)`. `ModuleRegistry` valida el manifiesto y la configuración antes de llamar a `register`.
4. Implemente el único método de `LlmPort`: `async fn complete(&self, request: CompletionRequest, cancel: &CancellationToken) -> Result<ModelStream, AppError>`. `CompletionRequest` contiene mensajes con rol, el catálogo de `ToolSpec` con JSON Schema, `max_output_tokens` y `remaining_case_tokens`. El adaptador traduce esos datos al protocolo remoto y emite `ModelEvent::Progress` y exactamente un `ModelEvent::Completed { response, usage }`.
5. Reconstruya los fragmentos de tool calling antes de generar `ProposedCall`. Use `Tool::parse`, limite bytes y tiempo, rechace respuestas incompletas y no ejecute herramientas desde el adaptador. La aplicación vuelve a comprobar esquema, alcance y política. La cancelación debe cortar la lectura HTTP y producir `AppError::Cancelled`.
6. Devuelva en `descriptor()` el ID de módulo, modelo y hash del endpoint, sin secretos. Añada una feature y selección explícita en `crates/bin`; el dominio y la aplicación no cambian para incorporar otro proveedor.
7. Añada respuestas grabadas para texto, tool calls fragmentadas, error, truncación y cancelación. Ejecute `irmind-testkit::run_llm_contract` además de `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` y `cargo nextest run --workspace --all-features`.

Para proveedores de Chat Completions, `irmind-llm-chat-completions` aporta el cliente y parser comunes; no es un módulo registrable. Anthropic implementa su protocolo Messages por separado.
