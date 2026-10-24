# Módulos LLM de IRMind

Cada proveedor es un crate compilado con el binario. El agente usa únicamente `LlmPort`: recibe un `CompletionRequest` con el contexto ya cribado y el catálogo de herramientas activas, y devuelve texto, propuestas de llamadas y uso de tokens. El modelo no ejecuta herramientas; `irmind-app` valida cada propuesta, aplica política, pide aprobación si corresponde y firma la auditoría.

## Proveedores disponibles

| `--llm-module` | Feature de Cargo | Modelo | Clave | Protocolo |
| --- | --- | --- | --- | --- |
| `llm-openai-compatible` | incluido | `IRMIND_MODEL` | `OPENAI_API_KEY` para el endpoint oficial, o `IRMIND_LLM_API_KEY` para uno personalizado | Chat Completions, base `IRMIND_LLM_BASE_URL` (por defecto `https://api.openai.com/v1/`) |
| `llm-anthropic` | `llm-anthropic` | `IRMIND_ANTHROPIC_MODEL` | `ANTHROPIC_API_KEY` | Messages nativo, `https://api.anthropic.com/v1/messages` |
| `llm-deepseek` | `llm-deepseek` | `IRMIND_DEEPSEEK_MODEL` | `DEEPSEEK_API_KEY` | Chat Completions, `https://api.deepseek.com/chat/completions` |
| `llm-openrouter` | `llm-openrouter` | `IRMIND_OPENROUTER_MODEL` | `OPENROUTER_API_KEY` | Chat Completions, `https://openrouter.ai/api/v1/chat/completions` |

Los tres módulos nuevos se compilan explícitamente. Ejemplos:

```bash
cargo build --release --features llm-anthropic,llm-deepseek,llm-openrouter
IRMIND_CASE_ID=... # ID devuelto por `irmind case new`
ANTHROPIC_API_KEY=... IRMIND_ANTHROPIC_MODEL=... ./target/release/irmind --llm-module llm-anthropic ask "$IRMIND_CASE_ID" "Investiga esta alerta"
DEEPSEEK_API_KEY=... IRMIND_DEEPSEEK_MODEL=... ./target/release/irmind --llm-module llm-deepseek tui "$IRMIND_CASE_ID"
OPENROUTER_API_KEY=... IRMIND_OPENROUTER_MODEL=... ./target/release/irmind --llm-module llm-openrouter ask "$IRMIND_CASE_ID" "Investiga esta alerta"
```

`--llm-module` también admite `IRMIND_LLM_MODULE`. La opción va antes del subcomando. Si la feature no está compilada o falta su clave o modelo, IRMind falla antes de enviar datos. Las claves no se comparten entre proveedores. Las llamadas a DeepSeek, Anthropic y OpenRouter usan endpoints fijos HTTPS, sin redirecciones. El módulo compatible permite HTTPS remoto con clave propia o HTTP en loopback; nunca reutiliza `OPENAI_API_KEY` para un endpoint personalizado.

Antes de usar un servicio externo, compruebe sus condiciones de retención, región de tratamiento y enrutamiento con su responsable de datos. OpenRouter puede enviar la solicitud a un proveedor subyacente según el modelo y la configuración de la cuenta. IRMind redacta patrones conocidos antes de enviar contexto, pero esa redacción no garantiza eliminar todos los secretos o datos personales.

## Cómo crear otro módulo LLM

1. Cree `crates/modules/llm-<nombre>/` con su `Cargo.toml` y `src/lib.rs`, y añádalo a `members` en el `Cargo.toml` del workspace. Use edición y lints del workspace y `#![forbid(unsafe_code)]`.
2. Declare un `MODULE_ID` estable y un `ModuleManifest` con `ports: &[ModulePort::Llm]`, `tools: &[]` y cada variable de configuración con `secret: true` cuando corresponda. El manifiesto se incorpora a la huella firmada de módulos activos.
3. Implemente `Module` y registre `self` con `registry.add_llm(MODULE_ID, self)`. `ModuleRegistry::register` comprueba que el módulo aporta exactamente el puerto declarado, que su ID no se repite y que el registro fallido no altera los módulos activos.
4. Implemente `LlmPort::complete_request(&CompletionRequest)` para traducir `request.context` y `request.tools` al formato del proveedor. Cada `ToolSpec` tiene nombre, descripción y JSON Schema. No defina las herramientas de investigación dentro del adaptador: el catálogo común está en `crates/app/src/tool_catalog.rs` y la aplicación ya lo filtra por conectores activos. Devuelva `ModelResponse { text, calls, raw }` y `ModelUsage { input_tokens, output_tokens }`. Use `Tool::parse` para los nombres devueltos y convierta los argumentos en `ProposedCall`; la aplicación vuelve a validar esquema, alcance y política antes de ejecutar.
5. Devuelva en `descriptor()` el ID de módulo, el ID del modelo y un hash SHA-256 del endpoint. Ese descriptor entra en el log firmado; no incluya claves, cabeceras de autenticación ni URLs que puedan contener secretos. Lea credenciales del entorno o llavero y guárdelas en `SecretString`.
6. Añada la dependencia opcional y una feature `llm-<nombre>` en `crates/bin/Cargo.toml`; añada la rama correspondiente en la selección de `crates/bin/src/main.rs`. El binario es la única raíz de composición. El dominio, la política y los casos de uso no cambian al incorporar otro proveedor.
7. Pruebe el formato de la petición, un stream completo con texto y tool calling fragmentado, los eventos de error y la truncación. Limite los bytes recibidos, exija terminación correcta y uso de tokens, y rechace herramientas o argumentos desconocidos. Ejecute `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` y `cargo nextest run --workspace --all-features`.

Fragmento mínimo del registro (junto a la definición de `MANIFEST` y la implementación de `LlmPort` descritas arriba):

```rust
pub const MODULE_ID: &str = "llm-ejemplo";

impl Module for Ejemplo {
    fn manifest(&self) -> &'static ModuleManifest { &MANIFEST }

    fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
        registry.add_llm(MODULE_ID, self)
    }
}
```

`complete_with_usage` tiene una implementación predeterminada que llama a `complete`; para admitir también la invocación directa, impleméntelo delegando a `complete_request` con `irmind_app::tool_catalog::catalog()`, como hacen los módulos incluidos. El parser debe rechazar streams incompletos antes de devolver propuestas al motor.

Si el proveedor ofrece Chat Completions, puede reutilizar `irmind-llm-chat-completions` mediante un perfil de petición, como hacen los módulos OpenAI compatible, DeepSeek y OpenRouter. Este crate común no implementa `Module` ni se registra por sí solo. Si el proveedor usa otro protocolo, implemente el adaptador y parser dentro de su crate, como Anthropic. Evite SDKs que ejecuten herramientas automáticamente: el puerto solo debe devolver propuestas.

Las respuestas de Anthropic usan eventos `message_start`, `content_block_*`, `message_delta` y `message_stop`; los argumentos de `tool_use` se reconstruyen antes de convertirlos en `ProposedCall`. El recuento de entrada suma `input_tokens`, `cache_read_input_tokens` y `cache_creation_input_tokens` para el presupuesto del caso. Los perfiles DeepSeek y OpenRouter comparten el parser de Chat Completions, pero envían solo los parámetros documentados para cada API.

Referencias de protocolo: [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create), [Anthropic streaming](https://platform.claude.com/docs/en/build-with-claude/streaming), [DeepSeek Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/), [OpenRouter Chat Completions](https://openrouter.ai/docs/api/api-reference/chat/create-a-chat-completion).
