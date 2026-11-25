# SigmaHQ admission in v0.7.0

The release-profile audit read the 3,302 YAML files in `sigma_all_rules.zip`
from SigmaHQ `r2026-07-01` (revision
`552f3fee420ef232a8e5790c4fae591847e32347`). The archive SHA-256 is
`5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085`.
The Detection Rule License 1.1 applies. This audit publishes aggregate
counts. Rule bytes were kept outside the tracked tree and release assets.
[SigmaHQ release](https://github.com/SigmaHQ/sigma/releases/tag/r2026-07-01) ·
[License](https://github.com/SigmaHQ/sigma/blob/552f3fee420ef232a8e5790c4fae591847e32347/LICENSE).

The audit ran the same directory admission used by `/sigma inspect` on
each file, then ran the release compiler against every source class selected
by its logsource. A successful compile requires exact bindings in all
applicable classes, as it would in a case with all of those classes enrolled.
There was no case, evidence, model or rule evaluation. Counts measure
compatibility with this table and corpus. A case with fewer source classes
can compile rules that this audit rejects. Family is the logsource product,
or the service or category when the product is absent.

Each file ran in a separate process with 512 MiB of address space, a
two-second CPU limit and a two-second elapsed limit. No process hit those
limits or panicked. The slowest admission-plus-compile interval was
122.3 ms. Six rules exceeded an internal compiler
limit and were rejected before evaluation.

## Resumen en español

Se fijó la release de SigmaHQ por revisión y SHA-256. De 3.302 ficheros,
3.301 pasaron la admisión y 1.022 compilaron contra todas las clases que
seleccionaba su `logsource`. Se aplicaron los mismos límites de IRMind y
se usó un proceso acotado por fichero. Seis reglas superaron un límite
interno del compilador y se rechazaron de forma controlada. La medición se
hizo sin evidencia ni modelo. La tabla agrupa por producto, o por servicio
o categoría cuando falta el producto. Un caso con menos clases aplicables
puede admitir más reglas de una familia concreta.

## Counts by logsource family / Recuentos por familia de logsource

The last six columns are mutually exclusive rejection reasons. One file
can pass admission and still be rejected by the compiler or source table.

Las seis últimas columnas cuentan motivos de rechazo excluyentes. Un
fichero puede pasar la admisión y quedar fuera por el compilador o la tabla.

| Family / Familia | Total | Admitted / Admitidas | Compiled / Compiladas | Logsource | Field / Campo | Modifier / Modificador | Syntax / Sintaxis | Correlation / Correlación | Limits / Límites |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `aws` | 42 | 42 | 25 | 0 | 16 | 1 | 0 | 0 | 0 |
| `azure` | 123 | 123 | 1 | 26 | 89 | 0 | 7 | 0 | 0 |
| `bitbucket` | 12 | 12 | 0 | 12 | 0 | 0 | 0 | 0 | 0 |
| `category/antivirus` | 9 | 9 | 0 | 9 | 0 | 0 | 0 | 0 | 0 |
| `category/database` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `category/dns` | 10 | 10 | 0 | 10 | 0 | 0 | 0 | 0 | 0 |
| `category/firewall` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `category/proxy` | 51 | 51 | 0 | 51 | 0 | 0 | 0 | 0 | 0 |
| `category/webserver` | 83 | 83 | 0 | 0 | 76 | 0 | 7 | 0 | 0 |
| `cisco` | 12 | 12 | 0 | 12 | 0 | 0 | 0 | 0 | 0 |
| `django` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `fortigate` | 7 | 7 | 0 | 7 | 0 | 0 | 0 | 0 | 0 |
| `fortios` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `gcp` | 25 | 25 | 0 | 10 | 14 | 0 | 1 | 0 | 0 |
| `github` | 9 | 9 | 0 | 9 | 0 | 0 | 0 | 0 | 0 |
| `jvm` | 5 | 5 | 0 | 5 | 0 | 0 | 0 | 0 | 0 |
| `kubernetes` | 9 | 9 | 0 | 4 | 5 | 0 | 0 | 0 | 0 |
| `linux` | 183 | 183 | 0 | 26 | 141 | 0 | 16 | 0 | 0 |
| `m365` | 18 | 18 | 2 | 13 | 3 | 0 | 0 | 0 | 0 |
| `macos` | 52 | 52 | 1 | 0 | 51 | 0 | 0 | 0 | 0 |
| `nodejs` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `okta` | 20 | 20 | 12 | 0 | 8 | 0 | 0 | 0 | 0 |
| `opencanary` | 24 | 24 | 0 | 24 | 0 | 0 | 0 | 0 | 0 |
| `paloalto` | 2 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 0 |
| `python` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `rpc_firewall` | 17 | 17 | 0 | 17 | 0 | 0 | 0 | 0 | 0 |
| `ruby_on_rails` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `service/apache` | 2 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 0 |
| `service/nginx` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `spring` | 2 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 0 |
| `sql` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `velocity` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `windows` | 2554 | 2553 | 978 | 454 | 1014 | 70 | 32 | 0 | 6 |
| `zeek` | 21 | 21 | 3 | 14 | 4 | 0 | 0 | 0 | 0 |
| **Total** | 3302 | 3301 | 1022 | 719 | 1421 | 71 | 63 | 0 | 6 |

## Most frequent concrete reasons / Motivos concretos más frecuentes

| Category / Categoría | Reason / Motivo | Rules / Reglas |
| --- | --- | ---: |
| field | `Missing binding OriginalFileName` | 451 |
| field | `Missing binding ParentImage` | 170 |
| field | `Missing binding CommandLine` | 154 |
| logsource | `product=windows/service=*/category=image_load` | 109 |
| modifier | `Compile::UnsupportedModifier` | 71 |
| logsource | `product=windows/service=system/category=*` | 69 |
| field | `Missing binding Description` | 54 |
| logsource | `product=*/service=*/category=proxy` | 51 |
| field | `Missing binding ParentCommandLine` | 50 |
| logsource | `product=windows/service=*/category=registry_event` | 40 |

For rules with several unsupported fields, the table counts the first field
in lexical order. `OriginalFileName` is outside the reviewed bindings.
The large `ParentImage` group primarily covers rules that also select FDR,
whose enrolled process class provides only the parent's base filename. The
`CommandLine` group is mainly broad Linux process rules that also select
auditd, and macOS rules requiring a scalar command line from eslogger. The
reviewed eslogger binding retains the argument list. The broad
`ParentCommandLine` rules also select Windows Security 4688 and FDR, where
the approved exact binding is unavailable. These groups reflect the
reviewed source boundaries. See the [field coverage](../../sigma.md).

Si una regla pide varios campos sin correspondencia, se cuenta el primero
en orden lexicográfico. `OriginalFileName` queda fuera de la tabla revisada.
Los rechazos por `ParentImage` se concentran en reglas que también incluyen
FDR, que en esta clase aporta el nombre base del proceso padre. El grupo
`CommandLine` se concentra en reglas amplias de Linux que incluyen auditd
y en reglas de macOS que esperan una cadena en lugar de la lista de
argumentos de eslogger. Las reglas con `ParentCommandLine` también
seleccionan Security 4688 y FDR, donde ese campo exacto queda fuera de la
cobertura. Consulta la [tabla de campos](../../es/sigma.md).
