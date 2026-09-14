"""
Stage 1 — Extraction layer.

Runs the fixed Volatility3 plugin set (DESIGN.md section 3) against a single
memory image and emits structured JSON per the schema (DESIGN.md section 5).

Scope discipline (per the project stage-gate rule):
- This module does RAW extraction only. No filtering, scoring, dedup,
  interpretation, or anomaly-flagging happens here — that logic belongs to
  later stages. Plugin rows are passed through verbatim.
- Only these plugins run: windows.pslist, windows.psscan, windows.netscan,
  windows.malfind. Nothing else.
- "generated_rules" and "validation" do not exist until later phases, so they
  are emitted as [] and null respectively.

malfind region bytes (DESIGN.md section 4, Stage 1):
- malfind's JSON only previews ~64 bytes of each flagged region, which is not
  enough for Stage 2 string mining. So malfind is run with --dump to write the
  FULL bytes of each region to a per-region file, and each injected_regions
  entry records dump_path + a SHA-256 of that file. Dumping raw bytes is still
  extraction, not interpretation.

The __main__ block here is a minimal internal test harness so the extraction
can be run on a test image. It is NOT the Stage 5 CLI — that is written later.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# Bump on any breaking change to the emitted schema shape (DESIGN.md section 5).
SCHEMA_VERSION = 1

# The fixed plugin set. Each entry: (plugin, schema field the rows land in,
# dump?) where dump=True runs the plugin with --dump into the region dump dir.
# Order is stable so output is deterministic.
PLUGINS = [
    ("windows.pslist.PsList", "processes", False),
    ("windows.psscan.PsScan", "processes", False),
    ("windows.netscan.NetScan", "network", False),
    ("windows.malfind.Malfind", "injected_regions", True),
]

# Path to the vol executable inside the project venv. Resolved relative to
# this file so it works regardless of the caller's working directory.
_VENV_VOL = Path(__file__).resolve().parent.parent / ".venv" / "Scripts" / "vol.exe"


def _vol_command() -> list[str]:
    """Return the base vol invocation, preferring the project venv."""
    if _VENV_VOL.exists():
        return [str(_VENV_VOL)]
    # Fall back to a vol on PATH.
    return ["vol"]


def run_plugin(image_path: str, plugin: str, dump_dir: str | None = None) -> dict:
    """
    Run one Volatility3 plugin against the image with the JSON renderer.

    If dump_dir is given, the plugin runs with --dump and -o dump_dir so it
    writes artifact files (used for malfind's full region bytes).

    Returns a dict describing the invocation and its result. On success,
    "rows" holds the raw parsed JSON array from Volatility3 (verbatim, no
    interpretation). On failure, "rows" is [] and "error" carries the reason
    so a single bad plugin does not abort the whole extraction.
    """
    cmd = _vol_command() + ["-q", "-r", "json"]
    if dump_dir is not None:
        # -o is a global option (before the plugin name); --dump is a plugin
        # option (after it).
        cmd += ["-o", dump_dir]
    cmd += ["-f", image_path, plugin]
    if dump_dir is not None:
        cmd += ["--dump"]

    result = {
        "plugin": plugin,
        "command": " ".join(cmd),
        "ok": False,
        "rows": [],
        "error": None,
    }
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        result["error"] = f"failed to launch vol: {exc}"
        return result

    if proc.returncode != 0:
        # Surface Volatility's own stderr, trimmed, for diagnosis.
        stderr_tail = "\n".join(proc.stderr.strip().splitlines()[-8:])
        result["error"] = f"vol exited {proc.returncode}: {stderr_tail}"
        return result

    stdout = proc.stdout.strip()
    if not stdout:
        # Plugin ran but produced no rows (valid — e.g. no injected regions).
        result["ok"] = True
        return result

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        result["error"] = f"could not parse vol json output: {exc}"
        return result

    result["ok"] = True
    result["rows"] = parsed
    return result


def _sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file, read in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _enrich_region(row: dict, dump_dir: Path) -> dict:
    """
    Add addressing + region-byte provenance to one malfind row (no analysis):
    - region_id: stable "<PID>-<StartVPN hex>" key linking a region to the
      rule later generated from it (DESIGN.md section 5).
    - dump_path / sha256: the full region bytes malfind wrote via --dump.

    malfind reports the written filename in the "File output" field; when a
    region could not be dumped that field holds a status string instead, so we
    only attach a path when a real file is present.
    """
    pid = row.get("PID")
    start = row.get("Start VPN")
    if isinstance(start, int):
        region_id = f"{pid}-{start:#x}"
    else:
        region_id = f"{pid}-{start}"

    dump_path = None
    sha256 = None
    file_out = row.get("File output")
    if isinstance(file_out, str) and file_out not in ("", "Disabled"):
        candidate = dump_dir / file_out
        if not candidate.exists():
            candidate = Path(file_out)  # in case vol reported an absolute path
        if candidate.exists() and candidate.is_file():
            dump_path = str(candidate)
            sha256 = _sha256_file(candidate)

    # region_id / dump_path / sha256 first so they read as the row's identity.
    return {"region_id": region_id, "dump_path": dump_path, "sha256": sha256, **row}


def extract(image_path: str, dump_dir: str | None = None) -> dict:
    """
    Run the full fixed plugin set against one image and assemble the Stage 1
    JSON document per DESIGN.md section 5.

    dump_dir receives malfind's full-region byte dumps; if None, a temp dir is
    created and its path recorded under meta. processes rows are tagged with
    their source_plugin (pslist vs psscan) so provenance is preserved without
    deduping or flagging — raw passthrough.
    """
    if dump_dir is None:
        dump_dir = tempfile.mkdtemp(prefix="forensig_regions_")
    dump_path_dir = Path(dump_dir)
    dump_path_dir.mkdir(parents=True, exist_ok=True)

    image = Path(image_path)
    doc: dict = {
        "schema_version": SCHEMA_VERSION,
        "image": image.name,
        "processes": [],
        "network": [],
        "injected_regions": [],
        "generated_rules": [],   # populated in Stage 3, empty here
        "validation": None,      # populated in Stage 4, null here
        "meta": {
            "extracted_at": datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="seconds"),
            "image_path": str(image),
            "region_dump_dir": str(dump_path_dir),
            "plugins": [],       # per-plugin command + status, for provenance
        },
    }

    for plugin, field, dump in PLUGINS:
        run = run_plugin(image_path, plugin, dump_dir=dump_dir if dump else None)
        doc["meta"]["plugins"].append(
            {
                "plugin": plugin,
                "field": field,
                "command": run["command"],
                "ok": run["ok"],
                "row_count": len(run["rows"]),
                "error": run["error"],
            }
        )
        rows = run["rows"]
        if field == "processes":
            # Tag provenance; do not merge/dedup across pslist and psscan.
            for row in rows:
                if isinstance(row, dict):
                    row = {"source_plugin": plugin, **row}
                doc["processes"].append(row)
        elif field == "injected_regions":
            for row in rows:
                if isinstance(row, dict):
                    row = _enrich_region(row, dump_path_dir)
                doc["injected_regions"].append(row)
        else:
            doc[field].extend(rows)

    return doc


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(
            "usage: python -m src.extract <memory_image_path> [region_dump_dir]",
            file=sys.stderr,
        )
        return 2
    image_path = argv[1]
    dump_dir = argv[2] if len(argv) == 3 else None
    if not Path(image_path).exists():
        print(f"error: image not found: {image_path}", file=sys.stderr)
        return 1
    doc = extract(image_path, dump_dir=dump_dir)
    json.dump(doc, sys.stdout, indent=2)
    sys.stdout.write("\n")
    # Non-zero exit if any plugin failed, so failures are visible to the caller.
    any_failed = any(not p["ok"] for p in doc["meta"]["plugins"])
    return 3 if any_failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
