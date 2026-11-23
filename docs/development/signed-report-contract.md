# Signed Markdown and PDF report contract

**Status.** Proposed for v0.7. Implementation requires contract review.

## Report inputs and claims

Replace the current human-readable report preview with a common bounded
report model used by both renderers. Resolve findings from a verified case
checkpoint and include only analyst-confirmed findings at that checkpoint.
Cite the confirmation event and source evidence SHA-256 plus a logical record
index or an authenticated artifact SHA-256. Attach the exact artifact row
locator when a claim is about a row. A dispatcher resolves each reference
against the case ledger and authenticates the referenced object or projection.
An evidence hash alone is insufficient. Report preview names findings omitted
because a citation cannot be resolved. Omission leaves their case status intact.

Claims consist of typed facts, analyst-confirmed conclusions attributed to
the analyst, and explicit supported and refuting references. Populate
descriptive claims from the resolved fields and preserve provenance and
outcome distinctions. A recommendation is expressed as an analyst judgment
linked to the confirmed evidence. Arithmetic, range endpoints and UTC
precision have a deterministic checked representation. For a limited cloud
query or partial detection, attach the signed limitation with its citation
whenever a claim uses that source. A partial capture cannot support a claim
that no other activity occurred.

The optional model proposes an ordered list of confirmed finding IDs and
template IDs with typed slots and citation IDs. IRMind validates each slot
against the cited row or the already confirmed analyst statement. Values
copied directly from model text do not become factual slots. The report
labels accepted model-selected or model-drafted sections as such. Free-form
model prose remains in a separate review draft. An analyst who wants to add a
new claim uses the existing propose-and-confirm flow with exact citations.
This avoids treating citation membership as proof of an arbitrary sentence.
Local report generation works with the model disabled.

## Deterministic rendering

Render the same validated plan into both outputs. Define ordering by existing
stable event keys followed by finding ID, and deduplicate citations by their
canonical key without reordering claims. Use a versioned heading and citation
template, UTF-8 and LF for Markdown, and fixed units, UTC rendering and page
layout for PDF. Inputs include explicit language and renderer versions.
Prevent current clocks, host fonts, path prefixes, randomized PDF
identifiers and unordered collections from affecting output.

Treat all evidence, finding strings and model drafts as untrusted.
Use a shared literal text formatter that makes control and bidi characters
visible and defangs URL schemes, host names in addresses, and email links
in rendered evidence. Markdown escapes all user-supplied syntax and emits
neither HTML nor active links. PDF accepts text operands only and contains no
URI actions, scripts, annotations with actions, attachments or embedded HTML.
Copy source bytes only in the existing evidence export, with their existing
custody and access controls.

## PDF implementation options

| Option | Cost and risk |
| --- | --- |
| Fixed text-only PDF serializer with no new production crate | Recommended first option. A small closed object grammar and fixed metrics make stable bytes feasible. IRMind owns escaping, pagination, offsets and xref correctness, so verify the result with an independent reader. Use Base 14 Courier with a fixed WinAnsi encoding for initial English and Spanish output. Render unsupported code points as reversible visible escapes in PDF and retain exact text in the UTF-8 Markdown. This is a simple PDF, with no PDF/A, custom fonts or shaping claim. |
| Restricted low-level `pdf-writer` | Upstream handles object and string serialization, which reduces manual offset and escape code. An exact release and its dependency closure would need review and reproducibility measurements. The same IRMind text, font and layout restrictions still apply. |
| Higher-level `printpdf` with default features disabled | Offers pagination and font facilities depending on features, with a broader code and dependency surface. A pinned font file and license, fixed shaping inputs, and cross-platform binary and document reproducibility tests would be needed. HTML, image and dynamic font resolution paths offer little value for this report. |

Review expected binary-size and compile-time changes with a dev-only probe
before choosing a production dependency. The proposal recommends starting
with the bounded dependency-free option. [Low-level PDF writer upstream](https://github.com/typst/pdf-writer) ·
[Higher-level PDF tooling and features](https://github.com/fschutt/printpdf/blob/master/Cargo.toml)

## Proposed signing and export

1. `/report` previews the plan and verification status. `/report save md`
   and `/report save pdf` sign a selected rendering while the case is open.
   Require the existing attended analyst signing capability. The model can
   draft within budget and cannot publish or sign. A sealed case can display
   and export previously signed reports.
2. A proposed `ReportPublishedV1` binds the input checkpoint, confirmed
   finding and citation manifest commitment, optional model draft receipt,
   rendering options, renderer version, media type, byte length and output
   SHA-256. Stage the immutable report in a private case directory before the
   ledger commit. Publication and recovery follow the signed inventory,
   with no deletion on an unauthenticated inventory. Keep the 1 MiB cap on
   the record and store the content separately.
3. Propose case marker 6 and export V10 in coordination with the Sigma
   contract. V10 includes an always-present bounded report-object count.
   Each referenced report and citation manifest is covered by the chain and
   export verification. Agree on both section layouts before the first
   release that writes V10. Generate independent canonical records and
   export-header vectors before implementation.
4. `/verify` checks the output digest and length, the chain and author,
   the original checkpoint and confirmation, and the exact row/object
   citations. With the matching renderer it can also reproduce the report
   bytes from the pinned plan. Report verification resolves authenticated
   case evidence even when a claim only cites its immutable row or artifact.
   A missing renderer or original is explicitly reported as a limitation of
   reproduction. A hash mismatch, missing included object or invalid
   citation fails verification. The creating-binary policy covers v0.6
   cases and exports.

## Acceptance

Use only synthetic incidents. Test unconfirmed and uncited claims,
wrong-row and wrong-case pointers, stale or missing checkpoints, incomplete
source results, contradictory model slots, refused signature, partial write,
and malicious Markdown, URLs, PDF syntax and bidi text. Compare exact report
bytes across Linux, macOS and Windows with the same plan, including English
and Spanish fixtures. Validate PDFs with an independent reader and check
that no actions or attachments exist. Verify signed cases and exports,
including mutation and omission of a proof object.
