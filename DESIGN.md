# Forensic-to-Detection Pipeline — DESIGN.md (v1.2)
<!-- v1.1 (2026-09-11): Phase 2 prototype rescope — added Stage 1.5 injection
     discrimination + `threads` plugin (discrimination only), made byte/code
     patterns the primary rule source with strings secondary. See §9. -->
<!-- v1.2 (2026-09-11): deeper prototype (§9.1) showed malfind MISSES the real
     injection while thread-start-in-unbacked-VAD finds it. Pivot: thread-driven
     detection becomes the PRIMARY candidate source (malfind secondary); v1 claim
     narrowed to "flag injection + emit a rule WHEN material is extractable"
     (many images yield indicators but no rule). Still n=1 validated — Stage 2/3
     code remains gated (§7 TBD). See §9.2. -->


## 1. Project goal (one sentence)
Given a Volatility3-compatible memory image, detect code-injection indicators,
generate a validated YARA rule from an injected region WHEN its content is
resident and yields trustworthy material, and produce an analyst-readable
report — closing the loop from investigation to detection where the evidence
allows, and honestly reporting the indicator (with no rule) where it does not.
("Validated" = compiles via yara-python, the Stage 3 gate. Corpus-tested
TP/FP/FN (Stage 4) is a separate, per-run claim and is not implied by the
word "validated." v1.2 narrowed the claim from "always emit a rule" to "emit a
rule when material is extractable" — see §9.1/§9.2 for why: injected regions are
frequently stringless, non-RWX (so malfind misses them), or not resident.)

## 2. Explicit non-goals for v1 (do not build these — defer to v2 discussion)
- No Sigma rule generation. Memory images don't reliably carry the
  log/command-line behavior Sigma needs; a half-supported second rule type
  adds scope without adding a credible output.
- No `dlllist`, no `cmdline` plugin. Extra analysis surface, not needed for
  the core extraction → rule → validation loop.
- No raw malware sample ingestion / execution. v1 input is memory images
  only. No live-sample handling, no sandboxing infrastructure yet.
- No batch processing across many images in v1. One image in, one report +
  one rule set out. Batch mode is a v2 candidate, same as IOC_Enrich deferred
  batch mode to post-v1.

## 3. Fixed plugin set (do not add plugins outside this list without updating this doc)
- `pslist` / `psscan` — process listing + hidden/unlinked process detection
- `malfind` — injected memory region detection (candidate regions for rules)
- `netscan` — network connection extraction (report only, not rule input)
- `threads` — thread start addresses + backing module. PRIMARY candidate source
  as of v1.2: a userland thread starting in a non-file-backed / private VAD is
  the strongest available injection signal. NOT itself rule material — it points
  at the region whose bytes become the rule.
- `vadinfo` — byte-retrieval helper ONLY (v1.2): dumps the full bytes of a
  thread-driven candidate VAD that malfind did not dump. NOT a detection or rule
  source.

Candidate-source order (v1.2, see §9.1/§9.2 for the evidence):
1. PRIMARY — thread-driven: regions hosting a userland thread that starts in an
   unbacked/private VAD (found the real injection in the one malicious sample,
   which malfind missed because the region was RW, not RWX).
2. SECONDARY/corroborating — malfind RWX regions. On modern Windows malfind fires
   mostly on benign JIT (Phase 1: 19/19 benign on a clean image; two further
   images benign-JIT-dominated), so it is no longer trusted as the sole source.
Both feed Stage 1.5, which applies a benign-runtime allowlist to cut the low-
volume false positives thread-driven detection still produces (~1/image, e.g.
CompatTelRunner). Do not add plugins beyond this set.

## 4. Pipeline stages

### Stage 1 — Extraction
Run the fixed plugin set raw (schema §5): pslist/psscan, netscan, malfind,
threads. No filtering or interpretation here — raw structured output only.

Region bytes: Stage 2 needs the FULL bytes of every CANDIDATE region (§1.5),
not malfind's ~64-byte preview. Stage 1 dumps full region bytes + SHA-256:
  - malfind regions via malfind `--dump`;
  - thread-driven candidate VADs (the unbacked/private VAD a suspicious thread
    starts in) via `vadinfo --dump` for that PID/VAD.
`vadinfo` is admitted in v1.2 as a byte-retrieval helper ONLY — not a detection
or rule source. Dumping raw bytes is still extraction, not interpretation.

### Stage 1.5 — Candidate selection & discrimination (v1.2)
Select the regions that proceed to rule generation, and mark those that are
injection INDICATORS but cannot (yet) yield a rule.
Candidate sources (see §3):
  - PRIMARY — a userland thread starting in a non-file-backed / private VAD.
  - SECONDARY — malfind RWX regions.
Filters / context:
  - benign-runtime allowlist (MsMpEng, SearchUI, smartscreen, ngentask,
    chrome/V8, .NET CLR hosts, CompatTelRunner-class telemetry) to drop the
    low-volume benign hits BOTH sources produce (~1/image for threads);
  - corroboration raises confidence (thread-start AND malfind on the same
    region; foreign PE header; unexpected RW→X protection);
  - byte-shape — all-zero / non-resident VADs carry no material.
INDICATOR vs RULE: a candidate may be reported as an injection INDICATOR even
when NO rule is generated (region non-resident, stringless, or no usable byte
pattern — all observed in the prototype, §9.1). Only candidates with extractable,
trustworthy material proceed to Stage 2/3. Allowlist + thresholds resolved in §7.

### Stage 2 — Rule-material extraction (was: string extraction & filtering)
Input: the FULL byte dumps of regions that PASSED Stage 1.5 (not the 64-byte
preview, and not benign-JIT regions).
Primary material = byte/code patterns: hex signatures over the injected code
(e.g. the API-dispatch trampoline stub). Phase 2 prototyping showed real
injected code is often STRINGLESS (§9), so byte patterns — not strings — are
the primary rule source. Guard against over-fitting to one sample by
wildcarding volatile bytes (absolute addresses, immediates).
Secondary material = printable ASCII/UTF-16 strings WHEN a region actually has
trustworthy ones (config / C2 / mutex), filtered by minimum length, a
region-level entropy screen, and an empirical stoplist of common library/
runtime strings.
A region may legitimately yield only a byte pattern, only strings, both, or —
if nothing trustworthy survives — nothing.

Note: this stage was prototyped assisted (not fully by-hand) at the user's
direction; the findings and this rescope are recorded in §9. The original
"stop and rescope if strings aren't trustworthy" gate fired exactly as intended
— strings alone were not trustworthy, hence the byte-pattern-first design.

### Stage 3 — YARA rule generation
Input: the rule material (byte patterns + any trustworthy strings) per region
that passed Stage 1.5.
Output: one YARA rule per passing region, using a fixed template (metadata
block: source image, process, region_id, region SHA-256, timestamp; a
strings/bytes block mixing hex byte-patterns and any trustworthy strings;
condition: N of M matched, threshold resolved in §7). Byte-pattern-only rules
are first-class output, not a fallback.
Quality floor: do NOT emit a rule from fewer than a minimum amount of rule
material — counting byte patterns and strings together (a 1-element rule is
noise; floor resolved in §7). A region with too little trustworthy material
produces no rule.
Validation gate: rule must compile via `yara-python` before being counted
as generated output.
Zero rules is a valid, successful outcome (v1.2 makes this common, not an edge
case): candidates rejected by Stage 1.5 as benign, or that are non-resident /
stringless / without a usable byte-pattern, yield NO rule but are still reported
as injection INDICATORS (§1.5). An image can therefore produce several indicators
and zero rules — that is honest output, not a pipeline failure (drives Stage 5
reporting: indicators and rules are reported separately).

### Stage 4 — Validation against corpus
Run generated rules against a labeled corpus:
- Known-malicious memory images (Win7+ preferred for reliable Volatility3
  support; candidates: public CTF forensics images with documented injection,
  SANS FOR508 samples, Volatility Foundation set)
- Known-benign memory images — INCLUDING images that themselves contain benign
  JIT/RWX regions, since that is the hard false-positive case this pipeline
  must survive, not just quiet images.
Report per rule: true positive / false positive / false negative, same
reporting discipline as IOC_Enrich Phase 4 (hand-traced disagreement cases
documented, not hidden).

### Stage 5 — Reporting, CLI, packaging
Per-image report combining: process anomalies (Stage 1), network indicators
(Stage 1), generated rule(s) (Stage 3), validation result if corpus-tested
(Stage 4). Reconciling pslist vs psscan (surfacing hidden/unlinked processes
from the raw, tagged Stage 1 rows) happens HERE, not in Stage 1.
Output formats: machine-readable JSON plus a human-readable report
(Markdown/HTML). CLI: one image path in, report + generated `.yar` file(s)
out. Also: CLI entry point, `requirements.txt`, portability check, and the
actual `README.md` (written here, not before).

## 5. Output schema (draft — finalize during Phase 1)
```
{
  "schema_version": 1,
  "image": "<filename>",
  "processes": [...pslist/psscan findings, each tagged with source_plugin...],
  "network": [...netscan findings...],
  "injected_regions": [
    {"region_id": "<PID>-<StartVPN>", "PID": n, "Process": "...",
     "Protection": "...", "dump_path": "<file>", "sha256": "<hex>",
     ...remaining malfind fields verbatim...}
  ],
  "generated_rules": [
    {"region_id": "...", "process": "...", "rule_name": "...",
     "elements_used": {"byte_patterns": [...], "strings": [...]},
     "match_threshold": "N of M",
     "yara_text": "...", "compiled": true/false}
  ],
  "validation": {"tested": bool, "tp": n, "fp": n, "fn": n},  // populated in Stage 4
  "meta": {                    // provenance, not analysis
    "extracted_at": "<utc iso8601>",
    "image_path": "<full path>",
    "plugins": [               // one entry per plugin run
      {"plugin": "...", "field": "...", "command": "...",
       "ok": bool, "row_count": n, "error": null}
    ]
  }
}
```
Notes (locked after Stage 1 sign-off / this revision):
- `meta` block: provenance only (which plugin ran, exact command, status, row
  count, timestamp). Records HOW indicators were obtained; no filtering,
  scoring, or flagging — that stays out of Stage 1.
- `processes` holds both pslist and psscan rows in one array; each row tagged
  with `source_plugin`. Rows are NOT merged or deduplicated — reconciling the
  two (surfacing hidden/unlinked processes) is Stage 5 report logic.
- `region_id` (`<PID>-<StartVPN>`) is the stable key linking an injected
  region to the rule generated from it. `generated_rules` cite it plus the
  exact `elements_used` (byte_patterns + strings) and `match_threshold`
  applied, so a rule is auditable from the JSON alone.
- `injected_regions` entries carry `dump_path` + `sha256` for the full region
  bytes (Stage 1 dump; see Stage 1). Stage 2 reads from `dump_path`.
- v1.2: each region also carries `flagged_by` (thread-driven / malfind / both)
  and `indicator_only` (true when it is a reported injection indicator that
  produced no rule — non-resident / stringless / no usable byte pattern). A
  region with `indicator_only=true` has no entry in `generated_rules`.
- `generated_rules` = [] and `validation` = null until their stages populate
  them. An empty `generated_rules` is a VALID result (see Stage 3), not an
  error.
- `schema_version` bumps on any breaking change to this shape.

## 6. Corpus sourcing (resolve before Stage 4, not during)
List specific sample sources and licensing/usage terms here once selected.
Do not proceed to Stage 4 with an unverified or ad-hoc corpus. Guidance:
prefer Windows 7+ images — Volatility3 support for XP/2003-era kernels is
unreliable (confirmed in Phase 1: a Server-2008-labeled sample was an
ntkrpamp XP-era kernel vol3 could not resolve symbols for). For each sample,
record source URL, SHA-256, and license/usage terms. Do not commit real
malicious samples to a public repo — document source/retrieval instead.

Samples gathered so far (Phase 2 prototyping, NOT yet a formalized corpus):
- CyberDefenders labs (zip password `cyberdefenders.org`): NotchItUp(=InCTF2019,
  Win7), Ramnit(Win10), Reveal(Win10), DumpMe(Win7), NintendoHunt(Win10),
  AfricanFalls2(Win10), BlackEnergy(XP, usable), BankingTroubles(XP dud).
- Other: imagery(=Houseplant2020, Win10), WinDump(clean Win10), memdump/Server2008
  (XP dud). Formalize source URLs + SHA-256 + license when the Stage 4 corpus is set.
TRACKED VALIDATION ITEM (fold in mid-project, Stage 1.5/§7 tuning or Stage 4):
our set is thin on ONE hard case — a MODERN Win10 image with LIVE (resident,
non-exited) injection into a randomly-named / non-allowlisted process. It is the
key stress test for the process-reputation discriminator's false-positive
behavior. Until such a sample tests them, §7's FP-discrimination values are
PROVISIONAL. Not blocking; the analysis harness is reusable, add the sample later.

## 7. Decisions — RESOLVED from prototyping, user-signed-off 2026-09-12
Empirical basis: candidate values tested across all 8 vol3-usable images
(§9.1–§9.7). Discrimination scored 4/4 known TPs retained, 0 FP (incl. clean
WinDump and Reveal's 35-hit stress case). PROVISIONAL where noted — the allowlist
was partly derived from these same images and must be re-checked against the
tracked hard-case sample (§6) before it is trusted on unseen systems.

1. DISCRIMINATION (Stage 1.5). A non-file-backed executable thread is treated as
   likely-injection if: protection is RWX (PAGE_EXECUTE_READWRITE) OR the hosting
   process is NOT in the benign-runtime allowlist. Drop base-address 0x0 hits
   (smss/csrss artifacts). malfind RWX regions corroborate but do not gate.
2. BENIGN-RUNTIME ALLOWLIST (PROVISIONAL — overfit-prone, expand with data; note
   vol truncates names to 14 chars): svchost.exe, RuntimeBroker., explorer.exe,
   dllhost.exe, vmtoolsd.exe, SecurityHealth, SkypeApp.exe, smartscreen.ex,
   AppVShNotify.e, MsMpEng.exe, SearchApp.exe, SearchUI.exe, CompatTelRunne,
   thunderbird.ex, msedge.exe, chrome.exe, OneDrive.exe, MemCompression,
   ngentask.exe, WWAHost.exe, NisSrv.exe, vm3dservice.ex.
   KNOWN GAP: allowlisted processes are only caught when RWX (e.g. BlackEnergy→
   svchost). RX/RW injection into an allowlisted process evades — inherent
   fragility, accept for v1, revisit in v2.
3. BYTE-PATTERN (primary rule material): 16–32 bytes of executable-section code;
   wildcard absolute addresses/immediates to avoid single-sample over-fit.
   (24 bytes compiled + matched + stayed specific in the §9.6 test.)
4. STRINGS (secondary): ASCII + UTF-16, minimum length 8; apply stoplist; cap
   8–12 distinctive strings per region.
5. STOPLIST (seed; grow empirically): printable-ASCII-table artifact (the full
   0x20–0x7e run), generic PE strings (DOS-stub message, .text/.rdata/.data/
   .rsrc/.reloc, Rich header), and common benign-JIT/runtime strings.
6. MATCH CONDITION + MIN-MATERIAL FLOOR: a rule fires on (byte-pattern present)
   OR (>= N distinctive strings). Floor to emit a rule at all = 1 strong
   byte-pattern OR >= 3 distinctive strings; below that the region is reported as
   an INDICATOR only (§1.5), no rule.
7. MAX RULES / IMAGE: cap 10 (discrimination yields <=4 candidates/image on the
   set so far; the cap is a safety valve, not expected to bind).

## 8. Deferred to v2 (not designed here, not in scope for this doc)
- Raw malware sample ingestion (isolated VM required, no host network bridging)
- Sigma rule generation
- Batch/multi-image processing
- Additional plugins beyond the §3 set (dlllist, cmdline, registry-adjacent
  artifacts). NOTE: `threads` was admitted in v1.1 for discrimination only.
- Cross-region / cross-rule deduplication and correlation
- Rule tuning driven by Stage 4 false-positive feedback (a tempting loop, but
  out of v1 scope)

## 9. Phase 2 prototype findings (empirical basis for the v1.1 revision)
Assisted prototype (at user's direction) on 3 vol3-usable images: one clean
Win10 (WinDump.mem), one Win7 malicious (InCTF2019 / "NotchItUp" = Challenge.raw),
one Win10 challenge (Houseplant 2020 = imagery.raw). (An XP-era memdump.mem was
unusable — vol3 could not resolve its ntkrpamp symbols, same failure class as §6.)
Findings:
- Real injection caught by malfind (NotchItUp: explorer/chrome/WmiPrvSE) was
  STRINGLESS machine code — API-dispatch trampolines and near-empty RWX VADs;
  0 ASCII/UTF-16 strings at min-length 4 or 6.
- Both Win10 images: malfind output dominated by BENIGN JIT — MsMpEng
  (Defender), SearchUI, smartscreen, ngentask. These are the string-RICH
  regions, i.e. exactly the false-positive material.
- Entropy did not separate the two (malicious 0.01–4.23 overlaps benign 3.9–4.9).
Conclusion: the original premise "mine strings from malfind regions to build the
rule" inverts on real data — signal has no strings, noise has many. The core
problem is not strings-vs-bytes; it is that malfind alone cannot distinguish
real injection from benign JIT. Hence v1.1: add discrimination (Stage 1.5, using
`threads`) and make byte/code patterns the primary rule source, strings
secondary. This is the rescope the Stage 2 "stop if strings aren't trustworthy"
gate was designed to trigger.

### 9.1 CAVEAT — v1.1 discrimination is UNVALIDATED; deeper probe contradicts the malfind-as-source premise (2026-09-11)
Follow-up prototyping on the one real-injection sample (NotchItUp) undercut a
core assumption. Findings:
- The genuine injection is a thread in `sppsvc.exe` starting in a non-file-backed
  VAD at 0xff340000 — flagged by thread analysis, NOT by malfind. malfind never
  flagged that region. malfind's own hits (explorer/chrome/WmiPrvSE) have no
  threads starting in them and are not the malware.
- Therefore the v1.1 Stage 1.5 signals (thread-start-IN-malfind-region, PE
  header) fire on NONE of malfind's regions here — as drafted, discrimination
  would not find this injection.
- The real region's pages were not resident in the capture (dumps as all zeros)
  — no strings AND no bytes extractable from it in this image.
- Thread-driven detection ("userland thread starting in a non-file-backed VAD",
  per vol3's suspicious_threads) is far tighter than malfind but NOT FP-free:
  hits were NotchItUp=1 (real: sppsvc), clean WinDump=1 (CompatTelRunner, benign
  FP), imagery=1 (ruby.exe, ambiguous; region was RW not RWX — why malfind missed
  it). ~1 low-volume, triageable hit per image vs malfind's 4–19.
OPEN ARCHITECTURE QUESTION (do not resolve off n=1): should the candidate-region
source become thread-driven (thread-start-in-unbacked/private VAD), replacing or
augmenting malfind (§3), with malfind demoted? This would be a v1.2 change and
needs more real-injection samples than are currently reachable. Until then, v1.1
Stage 1.5 stands as PROVISIONAL and unvalidated — do not build Stage 2/3 code on
it yet.

### 9.2 DECISION — v1.2 pivot (2026-09-11)
Resolved the §9.1 fork toward the honest, buildable option rather than stalling
for unobtainable samples or over-committing code on n=1:
- Thread-driven detection (thread-start-in-unbacked/private VAD) becomes the
  PRIMARY candidate source; malfind demoted to secondary/corroborating (§3).
  `vadinfo` admitted as a byte-retrieval helper for thread-driven candidates.
- v1's claim narrowed (§1): "detect injection + emit a rule WHEN material is
  extractable," with an explicit INDICATOR-vs-RULE split (§1.5, Stage 3). Many
  images will yield indicators and zero rules — that is honest, expected output.
VALIDATION DEBT (carried, not resolved): this rests on ONE real-injection sample.
Thread-driven detection is ~1 FP/image (benign, triageable) and did catch the
real injection malfind missed, but FP rate, detection recall, and rule-material
availability are all unvalidated at scale. §7 values stay TBD. Stage 1.5 / Stage
2 / Stage 3 CODE REMAINS GATED until (a) more real-injection samples confirm the
FP/recall tradeoff and (b) §7 is filled. v1.2 is a design decision, not a
green-light to code.
Concrete de-risk step when resumable: gather 2–3 more Win7+ real-injection images
(browser/VirusShare/course access — automated acquisition is exhausted), rerun
the thread-driven-vs-malfind comparison, then lock §7 and greenlight Stage 1.5.

### 9.3 REFINEMENT — resolved the ambiguous thread-driven hits (2026-09-12)
Investigated the two hits §9.1 left open, using data already on disk:
- imagery `ruby.exe` (PID 1980) — was labeled "ambiguous"; it is a TRUE POSITIVE.
  Parent is `services.exe` (i.e. ruby running as a Windows service — anomalous),
  and its thread starts in VAD 0x190000, a RESIDENT RW page containing a shellcode
  dispatch stub (`mov r11d,0 / mov rax,0x190000 / mov r10,0x657d7340 / jmp r10`),
  stringless, no PE. malfind did NOT flag it (RW, not RWX).
- WinDump `CompatTelRunner` (PID 3672) — confirmed BENIGN FP. Parent `svchost.exe`
  (MS Compatibility Telemetry); its VAD is a well-formed PE (MZ + .text/.rdata/
  .reloc), i.e. a legit module mapped into private memory.
Revised validation picture: thread-driven detection scored 2 TRUE POSITIVES on
the 2 malicious images (sppsvc, ruby) — both MISSED by malfind — and 1 benign FP
on the clean image (CompatTelRunner). Better than the "~1 FP/image, n=1" framing
in §9.2: effectively n=2 real detections now.
Discrimination signals that separated TP from FP (feed §7, still not locked):
  - process lineage/identity (ruby-as-service = anomalous; svchost→CompatTelRunner
    = expected/allowlistable);
  - region content shape (raw shellcode stub with no PE = suspicious; well-formed
    PE with normal sections = often a legit mapped module);
  - residency (ruby stub was resident → a rule COULD be generated from it, a
    concrete win for the v1.2 byte-pattern-primary design; sppsvc was not resident).
Debt NOT cleared: still only 2 malicious images, both from the same source class
(CTF). FP rate/recall at scale and the allowlist contents remain unvalidated.
Code stays GATED; §7 still TBD. But confidence in the v1.2 pivot is materially up.

### 9.4 EXPANDED VALIDATION — 6 CyberDefenders labs added; earlier optimism tempered (2026-09-12)
Ran thread-driven (suspicious_threads) vs malfind across 5 more vol3-usable Win7/10
images (a 6th, BankingTroubles, and memdump/Server2008 were XP — vol3 duds).
Full results (T = thread-driven hits, M = malfind regions):
| sample        | OS    | T                         | M (mostly benign JIT)        |
| NotchItUp     | Win7  | 1 TP (sppsvc, non-resid)  | 0 real                       |
| imagery       | Win10 | 1 TP (ruby, resident)     | 0 real                       |
| Ramnit        | Win10 | 0 (malware procs EXITED)  | 0 real                       |
| DumpMe        | Win7  | 1 TP (UWkpjFjDzM, RWX)    | caught it, buried in 36      |
| Reveal        | Win10 | 35 — ALMOST ALL BENIGN FP | 12 mixed                     |
| NintendoHunt  | Win10 | 0                         | 2 benign                     |
| AfricanFalls2 | Win10 | 0                         | 17 benign+powershell         |
| clean WinDump | Win10 | 1 benign FP               | 19 benign                    |
KEY CORRECTIONS to §9.2/§9.3 optimism:
- FP rate is NOT ~1/image. On a busy modern Win10 (Reveal: Thunderbird, Skype,
  Edge, RuntimeBroker) thread-driven detection produced 35 hits, nearly all
  BENIGN (modern apps legitimately run threads from non-file-backed exec memory
  — JIT, sandboxes, packed loaders). The earlier 1/image was an artifact of quiet
  images. FP rate is high and system-dependent.
- Recall is inconsistent: caught injection cleanly in NotchItUp, imagery, DumpMe;
  MISSED Ramnit (malicious processes had exited — not resident); NintendoHunt /
  AfricanFalls2 surfaced nothing (may simply lack live injection).
- What separates TP from FP is PROCESS IDENTITY, not the memory signal alone: the
  TPs were anomalous processes (injected sppsvc, ruby-as-service, randomly-named
  UWkpjFjDzM); the FPs were known apps (Thunderbird/Skype/Edge/svchost/RuntimeBroker).
  Protection helps but is not clean (DumpMe TP was RWX; imagery TP was RW).
- DumpMe is the strongest end-to-end case: a randomly-named malware with an RWX
  non-file-backed thread, caught by BOTH detectors, likely resident → the best
  byte-pattern-rule candidate we have (verify residency next).
HONEST CONCLUSION: v1.2's thread-driven pivot is still the best available detector
(beat malfind on every real case), but its usefulness DEPENDS on a load-bearing
process-reputation/allowlist filter that is inherently fragile (malware injecting
into a trusted, allowlisted process would evade it), and recall is capture-
dependent. This reinforces the narrowed v1 claim (§1): detect+indicator, rule only
when extractable; do NOT oversell detection. §7's allowlist/discrimination is the
hard core of the project, not a tuning knob. Code stays GATED; §7 still TBD.

### 9.5 BlackEnergy (XP) — malfind's utility is OS-DEPENDENT (2026-09-12)
Added 99-BlackEnergy (CyberDefenders). It is Windows XP SP3 x86 — but unlike the
earlier XP duds (ntkrpamp/ntkrnlpa ISF missing), vol3 RESOLVED its symbols, so it
ran. Both detectors fired on real injection:
- thread-driven: svchost.exe (PID 880) thread in an RWX non-file-backed VAD
  (0x980000) — clean TP (BlackEnergy → svchost). (smss/csrss base-0x0 RW hits =
  likely artifacts/FP.)
- malfind: 14 regions, 11 in winlogon.exe (+svchost, csrss, msmsgs) — the classic
  BlackEnergy winlogon injection. malfind CAUGHT it here.
INSIGHT: malfind is not worthless — it is worthless ON MODERN WINDOWS specifically.
On XP (no .NET/Defender/UWP JIT) malfind's RWX-private-VAD heuristic cleanly finds
BlackEnergy; on Win10 it drowns in benign JIT (Reveal/imagery/Ramnit). Since v1's
real target is modern Windows, malfind stays demoted (secondary/corroborating) —
but the OS-dependence is worth noting: on legacy targets malfind alone can suffice.
BlackEnergy (winlogon/svchost) + DumpMe (UWkpjFjDzM) are now the two best
rule-generation validation candidates — real malware, both detectors agree,
likely resident. Verify residency + carve content next. Code GATED; §7 TBD.

### 9.6 RULE-GENERATION VALIDATED end-to-end (2026-09-12)
Carved the candidate regions and confirmed the last unproven step works:
- DumpMe UWkpjFjDzM VAD 0x350000: RESIDENT injected PE (397KB, 71% non-zero,
  .text/.rdata/.rsrc, 1622 strings) — byte AND string material.
- BlackEnergy svchost 0x980000: RESIDENT injected PE (36KB); winlogon regions are
  stringless/packed code chunks (byte-pattern-only material). (Several UWkp VADs
  and sppsvc were non-resident — dump-read errors / all-zero — reconfirming the
  residency dependency.)
- Built a YARA rule from the DumpMe PE (24-byte code pattern + strings), compiled
  it, and scanned: MATCHED the malicious region, did NOT match a benign WinDump
  JIT region. Full carve -> rule -> compile -> match -> specificity loop works on
  real malware.
LESSONS (reinforce v1.2):
- The BYTE PATTERN drove the match; naive string auto-selection picked the
  printable-ASCII-table artifact (garbage). Confirms byte-patterns-primary AND
  that the §7 stoplist is load-bearing (must drop artifacts like the ASCII table).
- TOOLING: `yara-python` has NO Python 3.14 wheel and its source build needs a C
  toolchain (fails here). `yara-x` (VirusTotal's official YARA successor) installs
  as an abi3 wheel and works. DECISION FLAGGED: Stage 3's compile gate and §1's
  "validated = compiles via yara-python" should become yara-x (or pin an older
  Python). Resolve when Stage 3 is coded; not rewriting all refs yet.
STATUS: detection (thread-driven primary) AND rule-generation are both now
demonstrated on real malware.

### 9.7 §7 DISCRIMINATION TEST — candidate rule validated across 8 images (2026-09-12)
Tested candidate rule "non-file-backed exec thread flagged if RWX OR process not
in benign-runtime allowlist; drop base-0x0 artifacts" over every susp-threads
result. Per-image (raw hits -> flagged):
  notch 1->1 (sppsvc kept), imagery 1->1 (ruby kept), windump 1->0 (clean, FP
  gone), ramnit 0->0 (exited), dumpme 1->1 (UWkp kept), reveal 35->0 (all benign
  suppressed), nintendo 0->0, africanfalls 0->0, blackenergy 4->1 (svchost RWX
  kept, smss/csrss 0x0 dropped). RESULT: 4/4 known TP retained, 0 FP across all 8.
CAVEAT: allowlist derived from these same images -> "0 FP" is optimistic (overfit);
the RWX-or-non-allowlisted LOGIC generalizes, allowlist CONTENTS need the §6
hard-case sample. This is the empirical basis for §7 (now resolved/signed-off).
GATES NOW: §7 filled + user-signed-off (2026-09-12). Per the stage-gate, Stage 1.5
coding may be greenlit on the user's explicit go. §7 allowlist stays PROVISIONAL
until the §6 hard-case sample tests it. yara-x (not yara-python) is the compiler.

### 9.8 IMPLEMENTATION — Stage 1.5 + Stage 2/3 built and pipeline proven end-to-end (2026-09-12)
Wrote src/discriminate.py (Stage 1.5) and src/rulegen.py (Stage 2+3). The FULL
coded pipeline runs on real malware: DumpMe -> detect UWkpjFjDzM injection ->
carve resident PE -> emit a YARA rule that COMPILES (yara-x) and self-matches.
Verified per-image (Stage 1.5): DumpMe 1 TP (UWkp, thread+malfind), BlackEnergy
1 TP (svchost RWX, thread+malfind). Both real injections caught by the coded rule.

IMPLEMENTATION FINDINGS (bugs fixed + honest gaps — this is a FIRST CUT, not
production-tuned):
- FIXED: "backed" test wrongly used StartPath fallback (always ntdll) -> missed
  all injected threads; now uses Win32StartPath only. FIXED: malfind as an
  independent source flooded (DumpMe: 31 Office/IE JIT FPs) -> now
  CORROBORATION-ONLY (annotates thread-driven regions, adds none). GAP from that:
  a pure malfind-only injection (BlackEnergy winlogon regions) is not surfaced as
  its own candidate (BE still detected via svchost thread).
- OPEN — detection primitive divergence: the from-primitives detector
  (thrdscan x vadinfo) does NOT reproduce the suspicious_threads oracle used in
  §9.7. On clean WinDump it produced 1 FP (ShellExperienceHost, WRITECOPY-exec,
  not in allowlist) that the oracle never surfaced; and requiring EXECUTE
  protection risks missing RW-only TPs (imagery ruby was PAGE_READWRITE). So the
  coded clean-image result is 1 FP, NOT the prototype's 0. Needs a detection-
  primitive alignment pass (thrdscan vs windows.threads live-walk; protection/Tag
  handling: private VadS + RWX/RW vs mapped-image WRITECOPY).
- OPEN — rule quality / §7 tuning: auto string-selection is poor. The DumpMe rule
  picked libjpeg + MSIL/CLR + ASCII-table-repeat strings (generic) and only one
  distinctive string (the malware's own path). The stoplist must grow (libjpeg,
  CLR messages, repeated-ASCII-table) and the CONDITION must make the byte-pattern
  REQUIRED — "$bp or 3 of ($s*)" would false-positive on any libjpeg-bearing file.
- OPEN — arch: rulegen defaults x64; injected code may be 32-bit (UWkp). Detect
  bitness from windows.info (Is64Bit) / per-process WoW64 and pass to capstone.
STATUS: pipeline exists and works mechanically end-to-end; it is a first
implementation, NOT yet accuracy-validated. §7 allowlist + stoplist + condition +
detection-primitive all need one more empirical tuning iteration (plus the §6
hard-case sample) before the pipeline's precision can be trusted. Phases 1.5/2/3
CODED (not signed-off complete — only the user marks completion).

### 9.9 TUNING ITERATION — §9.8 open items resolved + re-validated (2026-09-12)
Addressed every §9.8 open item and re-validated the coded pipeline end-to-end:
DETECTION fixes (src/discriminate.py):
- Replaced the executable-protection gate with a PRIVATE-MEMORY gate
  (PrivateMemory==1). This (a) drops the ShellExperienceHost clean-image FP (a
  WRITECOPY mapped-image section, PrivateMemory=0) and (b) now CATCHES RW private
  injections (imagery ruby, PAGE_READWRITE) that the exec-only gate missed.
RULE-QUALITY fixes (src/rulegen.py):
- Condition now makes the byte-pattern REQUIRED ("$bp"); no "or N strings" branch.
  Strings-only rules (no byte-pattern) require >= floor DISTINCTIVE strings.
- Artifact filter: ordered-ratio heuristic kills ASCII-table/charset runs; a
  boilerplate substring list drops libjpeg/MSIL. Distinctive strings -> metadata.
- Arch auto-detected from the injected PE's Machine field (x86/x64) -> correct
  capstone operand wildcarding.
RE-VALIDATED RESULTS (coded pipeline, from §3 primitives — NOT the suspicious_threads
oracle):
| image        | Stage 1.5 candidates          | rule generated                 |
| DumpMe       | 1 TP UWkp (RWX, thread+malfind)| yes, compiles+self-match (x64) |
| imagery      | 1 TP ruby (RW, thread)         | yes, compiles+self-match (x64) |
| BlackEnergy  | 1 TP svchost (RWX,thread+malf) | yes, compiles+self-match (x86) |
| WinDump clean| 0                             | -                              |
| Reveal (FP-stress) | 0                       | -                              |
=> 3/3 TP each yield a working rule; 0 FP on clean + on the 35-hit FP-stress image.
DumpMe rule specificity: 0 matches across 12 benign regions.
STILL OPEN (honest, not tuning-fixable): Ramnit missed (malicious procs exited —
capture-timing limit); allowlist still PROVISIONAL — "0 FP" is on 2 benign images,
needs the §6 hard-case sample; rule specificity tested only vs region dumps, not a
full benign-binary corpus (Stage 4); malfind-only injections not independently
surfaced. NET: the tuned pipeline is accuracy-validated on the available set with
clean detection + working rules; broader precision still pending Stage 4 + §6.

### 9.10 INTEGRATION — single-command pipeline + report (Stage 5 core) (2026-09-12)
Wrote src/pipeline.py: one CLI run (python -m src.pipeline <image> [out_dir])
orchestrates Stage 1 (pslist/psscan/netscan) + Stage 1.5 (discriminate) +
Stage 2/3 (rulegen), running each plugin once, and emits: report.json (DESIGN §5
schema), rules/<name>.yar, and a human-readable report.md (process/network
summary, possibly-hidden procs, candidates, generated rules, validation status).
Added requirements.txt (volatility3, yara-x, capstone pinned; sample-tooling
optional). Validated on imagery.raw: 138 procs / 87 net / 1 candidate (ruby) ->
1 compiled rule; arch auto-detected (windows.info Is64Bit). "validation": null
(Stage 4 separate); zero-rules is reported as a valid clean result.
REMAINING for v1: README.md (Stage 5); Stage 4 corpus validation (real
precision/recall + §6 hard-case sample); src/extract.py is now partly superseded
by pipeline's inline extraction (keep as the standalone Stage-1 tool or fold in).

### 9.11 STAGE 4 — validation harness built + first run (2026-09-12)
Wrote src/validate.py: compiles the generated .yar rules and scans them over a
labeled corpus manifest (malicious vs benign region dumps), reporting per-rule +
overall TP/FP/FN with every FP listed (disagreements documented, not hidden).
First run — corpus: 3 malicious injected regions (DumpMe UWkp, imagery ruby,
BlackEnergy svchost) + 19 benign WinDump JIT regions; 3 rules:
  TP=3, FP=0, FN=0; precision 1.0, recall 1.0.
HONEST CAVEATS: (1) TP=3 is largely SELF-recall — the rules were built from those
same regions, so matching them is near-tautological; the genuinely meaningful
result is FP=0 across 19 benign regions (SPECIFICITY holds). (2) CROSS-SAMPLE
recall is untested — we have no malware family present in two images, so "does
DumpMe's rule catch the same malware elsewhere?" is unmeasured. (3) Corpus is
small and region-level (not full-image, not a broad benign-binary set). The
harness is real and reusable; trustworthy precision/recall numbers need a larger
labeled corpus (§6) — including the tracked modern-Win10 hard-case sample.

### 9.12 HARDENING — full-image/clean-binary validation + regression test suite (2026-09-12)
Non-data-gated production-confidence work (user go):
- src/validate.py extended: scans files MEMORY-MAPPED (scan_file via mmap), so it
  now handles whole multi-GB memory images and arbitrary clean binaries, not just
  carved region dumps. Added --benign-dir DIR (adds every file as a benign entry)
  = a clean-software false-positive corpus, the real deployed-rule FP surface.
- tests/ regression suite (stdlib unittest — no new dep; run:
  `python -m unittest discover -s tests`): 21 tests, hermetic (synthetic PE/rule
  fixtures, no Volatility, no large files). Covers rulegen (artifact filter, PE
  arch detect, byte-pattern wildcard+compile, build_rule compile/self-match/
  indicator-floor), discriminate (§7 _flag rule + allowlist), validate (TP/FP/FN
  counting, FP listing, mmap scan, benign-dir). All pass.
- Clean-binary FP results: the 3 generated rules vs (a) 17 venv PEs -> 0 FP, then
  (b) a LARGE real set — all of C:\Windows\System32 recursively: 20,734 files
  scanned, 288 skipped (locked/denied), **0 FP**. Strong real-software specificity
  signal: the byte-pattern rules fire on none of 20k+ legit Windows binaries.
  (Also hardened scan_file to skip unreadable/locked/special files instead of
  crashing — surfaced by System32 permission-denied files.)
SCOPE of that result: it validates RULE SPECIFICITY (won't fire on clean Windows)
at real scale. It does NOT address cross-sample RECALL (untested — no family
twice), benign DIVERSITY (one machine's System32), or the Stage-1.5 detection
allowlist. Still the dominant gate: cross-sample recall + a broader/varied benign
fleet + more malicious families + the §6 hard-case sample. Corpus breadth remains
the data problem before a production claim; malware detonation to make images is a
v1 non-goal (user cannot run samples), so the malicious corpus is capped at
pre-made public images.
