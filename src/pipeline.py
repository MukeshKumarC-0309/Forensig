"""
Stage 5 core — pipeline orchestrator + CLI.

One memory image in -> the DESIGN.md §5 JSON document, generated YARA rule
file(s), and a human-readable Markdown report out. Ties together:
  Stage 1   (extract)      : pslist/psscan (processes), netscan (network)
  Stage 1.5 (discriminate) : injection candidates (thread-driven + malfind corrob.)
  Stage 2/3 (rulegen)      : byte-pattern + strings -> compiled YARA rules

Plugins are run once each here and shared, so a single pipeline run does not
re-run malfind/pslist across stages.

Usage: python -m src.pipeline <memory_image> [out_dir]
Exit:  0 ok; 1 bad image path; 2 usage.
Note:  "validation" is null — Stage 4 (corpus validation) is separate. Zero
       generated rules is a VALID result (indicators may still be reported).
"""

from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

from capstone import CS_MODE_32, CS_MODE_64

from . import discriminate as disc
from . import rulegen

SCHEMA_VERSION = 1


def _utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _is64(image: str) -> bool:
    for r in disc._run_json(image, "windows.info"):
        # windows.info renders as key/value rows: [{"Variable":..,"Value":..}]
        if isinstance(r, dict):
            if r.get("Variable") == "Is64Bit":
                return bool(r.get("Value"))
    return True     # default x64


def run(image: str, out_dir: str) -> dict:
    od = Path(out_dir)
    (od / "work").mkdir(parents=True, exist_ok=True)
    rules_dir = od / "rules"

    # Stage 1 — processes (tagged) + network, each plugin once.
    processes, pid2name = [], {}
    for plugin in ("windows.pslist.PsList", "windows.psscan.PsScan"):
        for r in disc._run_json(image, plugin):
            if isinstance(r, dict):
                processes.append({"source_plugin": plugin, **r})
                if r.get("PID") is not None:
                    pid2name.setdefault(r["PID"], r.get("ImageFileName"))
    network = disc._run_json(image, "windows.netscan.NetScan")

    # Stage 1.5 — candidates (reuses pid2name; runs thrdscan/vadinfo/malfind once).
    disc_doc = disc.discriminate(image, str(od / "work"), pid2name=pid2name)
    candidates = disc_doc["candidates"]

    # Stage 2/3 — rules.
    mode = CS_MODE_64 if _is64(image) else CS_MODE_32
    rg = rulegen.generate({"image": Path(image).name, "candidates": candidates},
                          str(rules_dir), mode)

    # mark candidates indicator_only vs rule-backed
    ruled = {r["region_id"] for r in rg["generated_rules"]}
    for c in candidates:
        c["indicator_only"] = c["region_id"] not in ruled

    doc = {
        "schema_version": SCHEMA_VERSION,
        "image": Path(image).name,
        "processes": processes,
        "network": network,
        "injected_regions": candidates,
        "generated_rules": rg["generated_rules"],
        "validation": None,
        "meta": {
            "extracted_at": _utc(),
            "image_path": str(Path(image).resolve()),
            "arch": "x64" if mode == CS_MODE_64 else "x86",
            "counts": {
                "processes": len(processes), "network": len(network),
                "candidates": len(candidates),
                "rules": rg["rule_count"], "indicators": rg["indicator_count"],
            },
        },
    }
    (od / "report.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    (od / "report.md").write_text(_report_md(doc), encoding="utf-8")
    return doc


def _report_md(doc: dict) -> str:
    c = doc["meta"]["counts"]
    ps = [p for p in doc["processes"] if p["source_plugin"].endswith("PsList")]
    pss = [p for p in doc["processes"] if p["source_plugin"].endswith("PsScan")]
    ps_pids = {p.get("PID") for p in ps}
    hidden = sorted({(p.get("PID"), p.get("ImageFileName")) for p in pss
                     if p.get("PID") not in ps_pids})
    est = sum(1 for n in doc["network"] if n.get("State") == "ESTABLISHED")
    lis = sum(1 for n in doc["network"] if n.get("State") == "LISTENING")

    L = [f"# Forensic-to-Detection report — {doc['image']}",
         f"_Generated {doc['meta']['extracted_at']} · arch {doc['meta']['arch']} · schema v{doc['schema_version']}_",
         "",
         "## Summary",
         f"- Processes: {c['processes']} rows (pslist {len(ps_pids)} live; "
         f"{len(hidden)} in psscan only — possibly exited/hidden)",
         f"- Network: {c['network']} endpoints ({est} established, {lis} listening)",
         f"- Injection candidates: {c['candidates']}  →  **rules generated: {c['rules']}**, "
         f"indicators without rule: {c['indicators']}",
         ""]
    if c["candidates"] == 0:
        L += ["_No injection candidates — a clean result (not a failure)._", ""]
    if hidden:
        L += ["## Possibly hidden / exited processes (psscan not in pslist)",
              *[f"- PID {pid} {name}" for pid, name in hidden[:30]], ""]

    L += ["## Injection candidates"]
    if not doc["injected_regions"]:
        L.append("- none")
    for r in doc["injected_regions"]:
        kind = "INDICATOR (no rule)" if r.get("indicator_only") else "RULE"
        L.append(f"- **{r.get('Process')}** `{r['region_id']}` {r.get('Protection')} "
                 f"[{'+'.join(r.get('flagged_by', []))}] → {kind}")
    L.append("")

    L += ["## Generated YARA rules"]
    if not doc["generated_rules"]:
        L.append("- none (no candidate yielded extractable, trustworthy material)")
    for g in doc["generated_rules"]:
        L.append(f"- `{g['rule_name']}` — compiled={g['compiled']}, "
                 f"condition `{g['match_threshold']}` ({g.get('note','')})")
    L += ["", "## Validation", "- not run (Stage 4 / corpus). `validation` is null.",
          ""]
    return "\n".join(L)


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print("usage: python -m src.pipeline <memory_image> [out_dir]", file=sys.stderr)
        return 2
    image = argv[1]
    out_dir = argv[2] if len(argv) == 3 else f"./out_{Path(image).stem}"
    if not Path(image).exists():
        print(f"error: image not found: {image}", file=sys.stderr)
        return 1
    doc = run(image, out_dir)
    c = doc["meta"]["counts"]
    print(f"[+] {doc['image']}: {c['candidates']} candidate(s) -> "
          f"{c['rules']} rule(s), {c['indicators']} indicator(s). "
          f"Report + rules in {out_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
