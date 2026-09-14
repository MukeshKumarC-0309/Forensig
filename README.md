# Forensic-to-Detection Pipeline

Turn a Windows memory image into **detection capability**: extract forensic
indicators, find genuine code injection, and generate a **validated YARA rule**
from the injected region — closing the loop from "found the IOC" to "here is a
rule that detects it."

> **Design is authoritative in [`DESIGN.md`](DESIGN.md).** This README summarizes
> what is built; DESIGN.md (esp. §9.1–§9.11) records how every decision was
> reached and the honest limitations. This is a **v1** with a deliberately
> narrow, honest scope — see *Limitations*.

## What it does

Given one Volatility 3-compatible memory image, the pipeline:

1. **Extract** — processes (`pslist`/`psscan`), network (`netscan`).
2. **Discriminate** (the core engineering) — finds real injection: a userland
   thread starting in a **private, non-file-backed** VAD, kept when the region
   is **RWX** *or* the hosting process is **not** in a benign-runtime allowlist;
   `malfind` is used only to corroborate. This is what separates real injection
   from the flood of benign JIT (Defender, browsers, .NET) that `malfind` alone
   drowns in on modern Windows.
3. **Generate a rule** — from each resident injected region: a **byte/code
   pattern** (disassembled, operand-wildcarded — the primary, required element)
   plus filtered strings as context, emitted as a YARA rule that must **compile**
   (via `yara-x`).
4. **Report** — a JSON document (schema in DESIGN §5), the `.yar` rule file(s),
   and a human-readable Markdown report.

Why byte-patterns and not strings? Real injected code is frequently *stringless*
(shellcode, API-dispatch stubs), while the string-rich regions on a live desktop
are usually *benign* JIT. See DESIGN §9.

## Install

Requires **Python 3.14** and network access on first run (Volatility 3 fetches
Windows symbols).

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt   # volatility3, yara-x, capstone
```

> `yara-python` has no Python 3.14 wheel; this project uses **`yara-x`**
> (VirusTotal's official YARA successor) as the rule compiler.

## Usage

```bash
.venv/Scripts/python.exe -m src.pipeline <memory_image> [out_dir]
```

Produces in `out_dir/` (default `./out_<image>`):

| File | Contents |
|------|----------|
| `report.json` | Full structured document (DESIGN §5 schema) |
| `report.md`   | Human-readable summary |
| `rules/*.yar` | Generated YARA rule per injected region |
| `work/`       | Carved region dumps (evidence) |

**Zero rules is a valid, successful result** — an image with no discriminable
injection (or where the injected pages aren't resident) correctly yields
*indicators, no rules*, not an error.

### Individual stages / validation

```bash
python -m src.discriminate <image> <workdir>              # Stage 1.5 candidates (JSON)
python -m src.rulegen <stage15.json> <out_dir> [--arch x86|x64]   # Stage 2/3
python -m src.validate <rules_dir> <corpus_manifest.json> [out]   # Stage 4
```

The corpus manifest is a JSON list of `{"id","path","label"}` where `label` is
`"malicious"` or `"benign"`; `validate` reports per-rule and overall TP/FP/FN and
lists every false positive.

## Validation status

On the available corpus (3 real injected regions — DumpMe, imagery, BlackEnergy;
19 benign JIT regions): **precision 1.0, 0 false positives**. The detector
caught real injection in DumpMe, imagery (RW), BlackEnergy (RWX) and Reveal's
35-hit false-positive stress case collapsed to **0**. See DESIGN §9.9/§9.11.

**These numbers are limited and honest, not a claim of general accuracy** — see
Limitations.

## Limitations (v1 — read before trusting output)

- **Allowlist is provisional.** The benign-process allowlist was derived from the
  test images; "0 FP" is measured on a small benign set. Malware injecting into
  an allowlisted process evades unless the region is RWX. Needs a broader corpus
  (DESIGN §6) including a modern-Win10 live-injection sample.
- **Capture-timing recall gap.** Injection in **exited / non-resident** processes
  is missed (e.g. Ramnit's dropper had exited). Detection needs the malicious
  thread/region live and paged-in at capture.
- **Cross-sample recall is unmeasured** — no malware family appears in two images
  in the test set.
- **`malfind`-only injections** (no anomalous thread) are not independently
  surfaced (corroboration-only); such a host is caught only if it also has an
  anomalous thread.
- **Volatility 3 / OS support** — modern Windows and many Win7 builds work; some
  XP/2003-era kernels have no symbol table and fail to parse.

## Non-goals (v1)

No Sigma generation, no raw-malware execution/ingestion, no batch processing, no
plugins beyond the fixed set (`pslist`/`psscan`, `netscan`, `malfind`, `threads`,
`vadinfo`). See DESIGN §2/§8.

## Layout

```
src/pipeline.py     CLI orchestrator (image -> report + rules)
src/extract.py      Stage 1 standalone extraction
src/discriminate.py Stage 1.5 injection discrimination
src/rulegen.py      Stage 2/3 rule material + YARA generation
src/validate.py     Stage 4 corpus validation
DESIGN.md           authoritative design + decision log (§9 = findings)
```

## Safety

Handle memory images from real infections as untrusted data. This tool reads
images and emits rules; it never executes sample code. Do not commit real
malicious samples to a public repository (DESIGN §6).
