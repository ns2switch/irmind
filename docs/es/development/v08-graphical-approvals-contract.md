# Aprobaciones gráficas en la API local del motor

[English](../../development/v08-graphical-approvals-contract.md)

**Estado.** El analista eligió la aprobación en la GUI que inicia IRMind el
27 de noviembre de 2026. El protocolo, el modelo de amenazas y las
dependencias propuestos quedan para revisión. Por ahora, las decisiones
siguen en `/approvals` de la TUI.

## Alcance y confianza

El cliente inicia directamente el binario instalado con
`irmind serve <case_uuid>`, usa dos tuberías privadas y completa la admisión
local que ya exige IRMind. En POSIX se cierran los extremos sobrantes
y se marca el resto para que no se herede en otros procesos. Windows
restringe la herencia a los handles de ese hijo. Los frames no pasan por
shell, proxy, transcripción de terminal ni herramientas de depuración.
La sesión queda ligada a un caso. La etiqueta del cliente y el PID del
padre no acreditan identidad. Socket Unix y named pipe quedan para un
contrato propio.

La GUI muestra la acción, el UUID del caso, cada argumento con su nombre,
el alcance efectivo, la caducidad UTC, la decisión y el código recibidos
de IRMind. Usa texto plano con escape reversible de controles, caracteres
direccionales invisibles y delimitadores. La vista recoge los valores
literales de los argumentos. No muestra originales, extractos, adjuntos,
resultados de herramientas, HTML ni enlaces activos. Si ContentGuard o
los límites impedirían mostrar un valor exacto, la solicitud se remite
a la TUI.

La primera revisión cubre una solicitud de herramienta de la cola actual
de `/approvals`. Una solicitud de un hijo conserva la vinculación a su
tarea activa y su ruta de resolución. Presupuestos, configuración,
keystore, instalación y admisión de planes conservan su interfaz actual.

## Protocolo propuesto

`IRMIND-RPC-V2` y NUL, con `hello` versión 2, conservan J, el
enmarcado, los límites y los cinco métodos actuales. V1 sigue usando la
TUI para decisiones. Todos los campos de la tabla son obligatorios,
también los que aceptan `null`. Los identificadores y estados son
canónicos y cerrados.

| Método | Parámetros | Respuesta |
| --- | --- | --- |
| `approval_prepare` | `{case_id,request_id,decision}`. `request_id` es el hash de la solicitud o `null` para la pendiente más antigua por secuencia firmada. `decision` es `approve` o `deny`. | `{presentation,view,view_sha256,code,methods}`. Una sola presentación por sesión. Si la vista exacta no cabe o queda fuera del alcance del cliente, devuelve el error 8, que remite a la TUI. |
| `approval_submit` | `{case_id,presentation,view_sha256,method,passphrase_hex}`. Métodos `touch_id`, `windows_hello` y `keystore_passphrase`. La frase solo admite hex en minúsculas de hasta 4.096 bytes UTF-8 decodificados. Con los métodos nativos el campo es `null`. | `{state:"authenticating"}`. Consume el intento. IRMind invoca el diálogo o verifica la frase. |
| `approval_status` | `{case_id,presentation}` | `{state}` con `ready`, `authenticating`, `approved`, `denied`, `reauth_failed`, `expired`, `stale` o `cancelled`. El estado informa de la decisión confirmada. La ejecución de la herramienta conserva sus eventos propios. |
| `approval_cancel` | `{case_id,presentation}` | `{cancelled:bool}`. Cierra el intento. Para una denegación firmada, se prepara `deny` y se verifica la reautenticación. |

La vista incluye exactamente
`{action,args,case_id,decision,effective_scope,expires_at,request_id}`.
El alcance es una cadena en la sintaxis canónica actual. Resulta de
las restricciones de caso, organización, fuente y tarea aplicables. Si una restricción no se puede mostrar de forma
inequívoca, se deriva a la TUI. La caducidad se expresa en segundos UTC.
La GUI devuelve el digest completo de la vista calculado por IRMind.
El código abreviado liga vista, presentación, sesión y nonce aleatorio
de 32 bytes. El código sirve para cotejar pantallas y no concede permisos. Los
errores 1 a 7 conservan su significado. El error 8 indica que hay que
revisar la solicitud en `/approvals`. Si ya hay una presentación activa,
preparar otra solicitud devuelve ocupado. Un identificador sustituido
siempre devuelve caducado.
La [especificación exacta del digest y del código](../../development/v08-graphical-approvals-contract.md#proposed-protocol)
fija sus dominios.

## Reautenticación y firma

1. IRMind verifica la solicitud bajo el bloqueo del caso. Fija el desafío
   original, la vista, el alcance, la política, la clave Analyst y, cuando
   corresponda, la tarea y su lease. Caduca tras 60 segundos o al vencer
   la solicitud original, lo que suceda antes. El reloj monotónico impide
   que un ajuste del reloj amplíe el plazo.
2. Cada presentación admite un intento. IRMind libera el bloqueo del caso
   mientras espera a la persona o verifica la frase. Los fallos tienen un
   máximo de tres por minuto por sesión. Elegir otro método requiere un
   nuevo intento explícito sujeto a la caducidad original.
3. IRMind vuelve a tomar el bloqueo, verifica la cadena y comprueba de nuevo
   la solicitud y sus argumentos, política, alcance, clave, tarea y plazo.
   Comprueba que no hubo cancelación, sello, cambio de solicitud, decisión
   simultánea en TUI ni reemplazo de la clave. Valida y consume el intento
   bajo el mismo bloqueo que la escritura del recibo, con la clave Analyst.
   El permiso de ejecución se entrega después de confirmar la escritura.
4. La salida, el reinicio y la cancelación invalidan los intentos pendientes.
   Una decisión ya confirmada se consulta en el caso. Se reutilizan los
   registros firmados de aprobación y denegación actuales. La verificación
   del export acredita la decisión y su solicitud, sin acreditar el
   dispositivo de autenticación.

| Plataforma | Reautenticación |
| --- | --- |
| macOS | IRMind crea un `LAContext` nuevo con política biométrica, comprueba que el tipo es Touch ID, desactiva la reutilización y el botón de alternativa del sistema. El diálogo de Apple muestra el texto exacto generado por IRMind, incluido el código. Apple usa la razón como título del diálogo. La ruta se habilita solo si todo el texto cabe y es legible en las configuraciones nativas verificadas en Intel y Apple Silicon. Si no cabe, ofrece frase explícita cuando proceda o TUI. |
| Windows | IRMind muestra la vista exacta en una ventana propia y solicita Windows Hello usando el HWND de esa ventana con `RequestVerificationForWindowAsync`. Solo acepta `Verified` de esa llamada. Hello puede usar un PIN configurado. Requiere Windows 11, compilación 22000 o posterior, y una sesión de escritorio activa en la que se compruebe la ventana. |
| Linux y alternativa en macOS y Windows | La frase del keystore cifrado de archivos se teclea en un campo enmascarado y llega solo al proceso admitido por stdin. IRMind verifica de nuevo con Argon2id y el descifrado autenticado actuales y comprueba la clave Analyst del mismo almacén. El backend de almacén del sistema no tiene esa frase. En ese caso se usa el diálogo nativo cuando está disponible o la TUI. |

La GUI y el motor procesan el campo secreto fuera del historial y los
logs. El decodificador específico valida el frame acotado y descodifica
directamente en memoria que se limpia al liberarse, incluidos error,
timeout y cancelación. La frase se excluye del portapapeles, autocompletado,
argumentos, variables de entorno, telemetría, diagnósticos, contexto del
modelo, cadena, export y volcados de error. No se habilita esta vía si el
cliente no puede garantizar ese tratamiento de entrada.

Fuentes de las plataformas.
[`LAContext`](https://developer.apple.com/documentation/localauthentication/lacontext)
· [Texto del diálogo macOS](https://developer.apple.com/documentation/localauthentication/lacontext/localizedreason)
· [Windows Hello para aplicaciones de escritorio](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync)

## Modelo de amenazas

| Amenaza | Control y límite |
| --- | --- |
| GUI comprometida | IRMind usa la solicitud autenticada para construir el texto nativo y acepta solo el resultado del sistema de su propio intento. El analista coteja acción y código en la superficie nativa. Una GUI comprometida puede falsear su vista y capturar una frase tecleada en ella. Stdio y la limpieza de memoria no evitan la captura en ese extremo. La ruta de frase exige confiar en la GUI. |
| Otro proceso local | Los extremos de las tuberías son privados, la sesión se liga a un solo caso y cada intento requiere reautenticación. No se aceptan handles, tokens del sistema ni resultados de autenticación enviados por la GUI. La protección depende del aislamiento local del sistema operativo. Un proceso capaz de leer memoria de IRMind, inyectar código o controlar el escritorio queda fuera de esa garantía. |
| Evidencia hostil | Los argumentos se muestran como texto literal escapado. Los datos no se interpretan como autoridad ni como código. IRMind aplica ContentGuard y coteja los valores exactos con la solicitud firmada antes de actuar. |
| Repetición o sustitución | Vínculo a sesión, caso, vista, decisión y caducidad. Un intento y un commit por solicitud firmada. Si se pierde la respuesta tras el commit, se consulta el estado autenticado del caso. La GUI nunca reintenta la aprobación ni el envío automáticamente. |

## Dependencias nativas

La medición se hizo con un manifiesto Cargo aislado y Rust 1.97.1. Cuenta
dependencias normales y de compilación, incluidos proc macros, y compara
nombres y versiones con el lockfile de `0756bc29`. Los tamaños son de
caché y de fuentes descomprimidas.

| Opción | Cierre total y nuevo | Archivos nuevos, comprimidos / expandidos | Licencias |
| --- | --- | --- | --- |
| Touch ID con `objc2-local-authentication 0.3.2` | 6 paquetes, 5 nuevos en cada arquitectura macOS | 697.427 / 4.491.919 bytes | Zlib, Apache-2.0 o MIT para el binding. MIT para los crates auxiliares nuevos. |
| Windows Hello con `windows 0.62.2` | 15 paquetes, 10 nuevos en Windows x86-64 | 9.502.897 / 114.869.304 bytes | MIT o Apache-2.0 para los nuevos. `unicode-ident`, ya presente, incluye Unicode-3.0. |
| Capa propia sobre el SDK del sistema | 0 paquetes de registro nuevos. Añade una unidad de compilación nativa y una frontera FFI propia. | 0 bytes de archivos de registro. Tamaño enlazado pendiente. | Código propio bajo la licencia del proyecto y SDK según los términos de cada fabricante. |

La [revisión completa](../../development/v08-graphical-approvals-contract.md#native-dependency-review)
enumera versiones, features, paquetes, fuentes y cifras totales. Se
proponen bindings Rust tipados y limitados a cada plataforma. El aumento
del binario enlazado sigue sin medir. La PR de implementación deberá medir
antes y después en release en los tres destinos nativos, comprobar que
Linux no adquiere dependencias y validar SBOM, licencias, imports y
reproducibilidad. El cierre observado encaja en la lista de licencias
actual. La CI del lockfile de producción sigue siendo un requisito.

## Validación antes de activar

- Pruebas nativas con diálogos reales en Windows 11, macOS Intel y Apple
  Silicon, incluida la presentación exacta y sin recortes, las locales
  admitidas, ausencia de hardware, cancelación y callback tardío.
- Casos sintéticos firmados de aprobación y denegación con la GUI, incluido
  un hijo activo, resolución simultánea desde la TUI y pérdida de conexión
  después del commit. Ninguna ejecución se entrega antes de ese commit.
- Intentos de cambio de argumentos, alcance, política, clave o lease entre
  la vista y la firma. Repeticiones entre sesiones y tras reinicio, frames
  mal formados y resultado nativo falsificado por el cliente.
- Comprueba que caracteres de control y texto de evidencia son inertes y
  que los secretos sintéticos no aparecen en la cadena, el export, los
  diagnósticos ni la configuración de volcados.
