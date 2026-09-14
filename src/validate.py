"""
Stage 4 — Validation against a labeled corpus (DESIGN.md §4 Stage 4, §5 validation).

Compiles the generated YARA rules and scans them against a labeled corpus of
memory regions (malicious vs benign), reporting per-rule and overall
true-positive / false-positive / false-negative counts. Every FP (a rule
matching a benign region) is listed explicitly so disagreements are documented,
not hidden (same reporting discipline as DESIGN.md §4).

Corpus manifest (JSON): a list of
    {"id": "...", "path": "<file>", "label": "malicious"|"benign", "kind": "..."}
`path` may be a carved region dump, a WHOLE memory image, or an arbitrary clean
binary — files are scanned memory-mapped, so multi-GB images do not blow up RAM.
`kind` is optional/informational ("region"|"image"|"binary"). A `--benign-dir`
adds every file under a directory as a benign entry (a clean-software corpus is
the real false-positive surface for a deployed rule).

Definitions (per corpus entry):
  TP = malicious entry matched by >= 1 rule
  FN = malicious entry matched by 0 rules
  FP = benign entry matched by >= 1 rule

Usage: python -m src.validate <rules_dir> [corpus_manifest.json] [--benign-dir DIR] [--out FILE]
"""

from __future__ import annotations

import contextlib
import json
import mmap
import sys
from pathlib import Path

import yara_x


def _compile_rules(rules_dir: Path):
    srcs, names = [], []
    for f in sorted(rules_dir.glob("*.yar")):
        srcs.append(f.read_text(encoding="utf-8"))
        names.append(f.stem)
    if not srcs:
        raise SystemExit(f"no .yar rules in {rules_dir}")
    return yara_x.compile("\n\n".join(srcs)), names


def scan_file(rules, path: Path):
    """Scan a file (region dump, full image, or binary) memory-mapped so a
    multi-GB image is not read into RAM. Returns a list of matching rule
    identifiers, or None if the file is unreadable/unmappable (locked, denied,
    special) so the caller can skip it rather than abort the whole run."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0:
        return []
    try:
        with open(path, "rb") as f:
            with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as mm:
                try:
                    res = rules.scan(memoryview(mm))
                except TypeError:           # older binding wants bytes
                    res = rules.scan(bytes(mm))
                return [m.identifier for m in res.matching_rules]
    except (OSError, ValueError):           # permission denied / locked / special file
        return None


def _load_corpus(manifest_path: str | None, benign_dir: str | None) -> list[dict]:
    corpus: list[dict] = []
    if manifest_path:
        with open(manifest_path, encoding="utf-8") as f:
            corpus.extend(json.load(f))
    if benign_dir:
        for p in sorted(Path(benign_dir).rglob("*")):
            if p.is_file():
                corpus.append({"id": f"benign_{p.name}", "path": str(p),
                               "label": "benign", "kind": "binary"})
    return corpus


def validate(rules_dir: str, manifest_path: str | None = None,
             benign_dir: str | None = None) -> dict:
    rules, rule_names = _compile_rules(Path(rules_dir))
    corpus = _load_corpus(manifest_path, benign_dir)

    tp = fn = fp = 0
    skipped = 0
    per_rule: dict[str, dict] = {n: {"tp": 0, "fp": 0} for n in rule_names}
    fp_details, fn_details = [], []

    for item in corpus:
        p = Path(item["path"])
        label = item["label"]
        if not p.exists():
            skipped += 1
            continue
        matched = scan_file(rules, p)
        if matched is None:                 # unreadable/locked/special — skip
            skipped += 1
            continue
        if label == "malicious":
            if matched:
                tp += 1
                for m in matched:
                    per_rule.setdefault(m, {"tp": 0, "fp": 0})["tp"] += 1
            else:
                fn += 1
                fn_details.append(item["id"])
        else:  # benign
            if matched:
                fp += 1
                for m in matched:
                    per_rule.setdefault(m, {"tp": 0, "fp": 0})["fp"] += 1
                fp_details.append({"region": item["id"], "matched_rules": matched})

    n_mal = sum(1 for i in corpus if i["label"] == "malicious")
    n_ben = sum(1 for i in corpus if i["label"] == "benign")
    return {
        "tested": True, "tp": tp, "fp": fp, "fn": fn,
        "corpus": {"malicious": n_mal, "benign": n_ben, "rules": len(rule_names),
                   "skipped_unreadable": skipped, "scanned": len(corpus) - skipped},
        "recall": round(tp / (tp + fn), 3) if (tp + fn) else None,     # over scanned malicious
        "precision": round(tp / (tp + fp), 3) if (tp + fp) else None,
        "per_rule": per_rule,
        "false_positives": fp_details,     # documented, not hidden
        "false_negatives": fn_details,
    }


def main(argv: list[str]) -> int:
    args = argv[1:]
    if not args:
        print("usage: python -m src.validate <rules_dir> [corpus_manifest.json] "
              "[--benign-dir DIR] [--out FILE]", file=sys.stderr)
        return 2
    rules_dir = args[0]
    manifest = benign_dir = out = None
    i = 1
    while i < len(args):
        a = args[i]
        if a == "--benign-dir":
            benign_dir = args[i + 1]; i += 2
        elif a == "--out":
            out = args[i + 1]; i += 2
        elif not a.startswith("--") and manifest is None:
            manifest = a; i += 1
        else:
            print(f"unknown arg: {a}", file=sys.stderr); return 2
    if manifest is None and benign_dir is None:
        print("provide a manifest and/or --benign-dir", file=sys.stderr)
        return 2
    result = validate(rules_dir, manifest, benign_dir)
    text = json.dumps(result, indent=2)
    if out:
        Path(out).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
