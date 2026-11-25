# SigmaHQ admission with expanded v0.7.3 field tables

The Linux release-profile audit uses the
[v0.7.0 audit method](sigmahq-v070-admission.md) and the exact same
SigmaHQ archive. SHA-256
`5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085`.
The audit passes one rule at a time through the current pack admission
and the evaluator V2 compiler. It compiles for every applicable class
in the full reviewed table. Native mapping recipes use deterministic
synthetic versions in this compiler-only test. Each rule has a 512 MiB
address-space limit and two-second CPU and elapsed limits. No evidence,
model or rule scan is involved. Only aggregate results are published.
[SigmaHQ release](https://github.com/SigmaHQ/sigma/releases/tag/r2026-07-01) ·
[Detection Rule License 1.1](https://github.com/SigmaHQ/sigma/blob/552f3fee420ef232a8e5790c4fae591847e32347/LICENSE).

## Cumulative audit / Auditoría acumulada

Every row used the same 3,302 files. Pack admission succeeded for 3,301
files at each step. The columns following `Compiled` are disjoint
rejection categories. No file exceeded the process limits or panicked.
`Max` measures the longest admission and compile call inside its process.

Todas las filas usan los mismos 3.302 ficheros. La admisión del pack
aceptó 3.301 en cada medición. Las columnas posteriores a `Compiled`
son motivos excluyentes. Ningún proceso superó los límites ni tuvo un
pánico. `Max` mide la admisión y compilación más lenta de un fichero.

| Tables / Tablas | Compiled | Change | Logsource | Field | Modifier | Syntax | Limits | Max (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| v0.7.2 baseline / Referencia | 1,022 | — | 719 | 1,421 | 71 | 63 | 6 | 119.3 |
| Sysmon process fields / Campos de proceso | 1,022 | 0 | 719 | 1,421 | 71 | 63 | 6 | 116.9 |
| Sysmon image loads and registry / Carga de imágenes y registro | 1,142 | +120 | 597 | 1,421 | 71 | 64 | 7 | 123.0 |
| CloudTrail leaf fields / Campos escalares | 1,150 | +8 | 597 | 1,413 | 71 | 64 | 7 | 126.6 |
| IIS webserver | 1,150 | 0 | 597 | 1,413 | 71 | 64 | 7 | 116.2 |
| Route 53 and Windows DNS debug | 1,159 | +9 | 587 | 1,414 | 71 | 64 | 7 | 127.3 |

| Family / Familia | Files | v0.7.2 compiled | Expanded tables compiled |
| --- | ---: | ---: | ---: |
| Windows | 2,554 | 978 | 1,098 |
| AWS | 42 | 25 | 33 |
| Category / Categoría `webserver` | 83 | 0 | 0 |
| Category / Categoría `dns` | 10 | 0 | 9 |

## Exact coverage / Cobertura exacta

- Sysmon process-creation original fields help in cases with only the
  applicable Sysmon process class. Broad process rules still fail
  compiler V2 when another provider does not supply the same binding.
  Image load uses ID 7. Registry classes distinguish creation/deletion
  in ID 12 through the original `EventType`, value set in ID 13 and
  rename in ID 14. The broad `registry_event` alias is still unsupported.
  [Sysmon event documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- CloudTrail binds named scalar leaves under `requestParameters` and
  `responseElements`. Whole-object text matching, array traversal and
  unavailable fields are outside this table change. The reviewed event
  action filter keeps its existing scope.
  [CloudTrail event fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html).
- IIS supplies independently retained W3C URI stem and query fields.
  Generic `webserver` rules still span Zeek and Suricata, whose enrolled
  classes lack the same W3C bindings. The combined audit gains zero
  admissions here. The exact bindings can be used for IIS-scoped rules.
- Route 53 Resolver and Windows DNS Debug supply the query and record
  type. One generic DNS rule requires `answer`, which cannot be bound
  with a shared shape for these classes. The table leaves it unsupported.

En un caso limitado a Sysmon se pueden usar los campos nuevos de
proceso. Las reglas genéricas siguen sujetas al requisito de V2 de
compilar en todas las clases. Las clases nuevas de Sysmon distinguen
carga de imágenes, creación, borrado, escritura y renombrado. En
CloudTrail se exponen solo valores escalares concretos y se conserva
el filtro de operaciones existente. IIS aporta los campos W3C donde
se conservan exactamente. Las reglas genéricas de webserver también
alcanzan Zeek y Suricata, donde faltan esas correspondencias. En DNS
sigue fuera el campo `answer`, que carece de un tipo compartido exacto.
