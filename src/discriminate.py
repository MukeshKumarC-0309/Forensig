"""
Stage 1.5 — Injection discrimination & candidate selection (DESIGN.md v1.2 §1.5, §7).

Selects the memory regions that proceed to rule generation, separating real
injection from benign JIT using the §7-locked rule:

  A non-file-backed EXECUTABLE thread-start region is a candidate if
    protection is RWX (PAGE_EXECUTE_READWRITE)  OR  the hosting process is
    NOT in the benign-runtime allowlist. Base-address 0x0 hits are dropped.

Primary source  : thread-driven — a userland thread whose start address lands in
                  a non-file-backed executable VAD (threads x vadinfo).
Secondary source: malfind RWX regions, kept only when the process is NOT
                  allowlisted (corroborating; malfind alone drowns in benign JIT
                  on modern Windows — see §9.4).

Provenance/scope discipline: this stage INTERPRETS (that is its job,
per DESIGN.md §1.5) but generates no rule material — that is Stage 2. Every
candidate records why it was flagged. Values come from §7, not guessed here.

Plugins used (all within the DESIGN.md §3 fixed set): windows.thrdscan (threads
source — windows.threads.Threads was unreliable under --pid here), windows.vadinfo
(protection + file-backing, and byte dump for thread-driven candidates),
windows.pslist/psscan (PID -> name), windows.malfind (secondary + --dump).
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

# §7 benign-runtime allowlist (PROVISIONAL — overfit-prone, pending §6 hard-case
# sample). vol truncates ImageFileName to 14 chars; entries match that form.
ALLOWLIST = {
    "svchost.exe", "RuntimeBroker.", "explorer.exe", "dllhost.exe", "vmtoolsd.exe",
    "SecurityHealth", "SkypeApp.exe", "smartscreen.ex", "AppVShNotify.e",
    "MsMpEng.exe", "SearchApp.exe", "SearchUI.exe", "CompatTelRunne",
    "thunderbird.ex", "msedge.exe", "chrome.exe", "OneDrive.exe",
    "MemCompression", "ngentask.exe", "WWAHost.exe", "NisSrv.exe", "vm3dservice.ex",
}

RWX = "PAGE_EXECUTE_READWRITE"
_EXEC_PROT = ("PAGE_EXECUTE",)  # any protection containing EXECUTE is executable

_VENV_VOL = Path(__file__).resolve().parent.parent / ".venv" / "Scripts" / "vol.exe"


def _vol() -> list[str]:
    return [str(_VENV_VOL)] if _VENV_VOL.exists() else ["vol"]


def _run_json(image: str, plugin: str, *extra: str, out: str | None = None) -> list[dict]:
    """Run a vol plugin with the JSON renderer; return parsed rows ([] on error)."""
    cmd = _vol() + ["-q", "-r", "json"]
    if out is not None:
        cmd += ["-o", out]
    cmd += ["-f", image, plugin, *extra]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return []
    s = proc.stdout.strip()
    if not s:
        return []
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return []


def _is_exec(prot: str | None) -> bool:
    return bool(prot) and "EXECUTE" in prot


def _sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _flag(process: str | None, protection: str | None) -> bool:
    """The §7 discrimination rule."""
    if protection == RWX:
        return True
    return process not in ALLOWLIST


def discriminate(image: str, workdir: str, pid2name: dict[int, str] | None = None) -> dict:
    wd = Path(workdir)
    (wd / "regions").mkdir(parents=True, exist_ok=True)

    # PID -> process name (pslist + psscan; psscan also catches exited procs).
    # The orchestrator (src.pipeline) may pass this in to avoid re-running the
    # process plugins; otherwise compute it here for standalone use.
    if pid2name is None:
        pid2name = {}
        for plugin in ("windows.pslist.PsList", "windows.psscan.PsScan"):
            for r in _run_json(image, plugin):
                if isinstance(r, dict) and r.get("PID") is not None:
                    pid2name.setdefault(r["PID"], r.get("ImageFileName"))

    # Thread-driven: threads whose Win32 start is NOT backed by a module.
    threads = _run_json(image, "windows.thrdscan.ThrdScan")
    unbacked = []
    for t in threads:
        if not isinstance(t, dict):
            continue
        # Use the Win32 start (the real thread entry) ONLY. Do NOT fall back to
        # StartAddress/StartPath: those are the generic ntdll bootstrap
        # (RtlUserThreadStart), which is always module-backed and would mask the
        # injected entry.
        addr = t.get("Win32StartAddress")
        backed = t.get("Win32StartPath")
        if isinstance(addr, int) and addr != 0 and not backed:
            unbacked.append((t.get("PID"), addr, t.get("TID")))

    # For each PID with an unbacked-start thread, pull its VADs once and locate
    # the containing VAD to read protection + confirm it is non-file-backed.
    candidates: dict[str, dict] = {}   # region_id -> record
    vad_cache: dict[int, list[dict]] = {}
    for pid, addr, tid in unbacked:
        if pid not in vad_cache:
            vad_cache[pid] = _run_json(image, "windows.vadinfo.VadInfo", "--pid", str(pid))
        vad = next(
            (v for v in vad_cache[pid]
             if isinstance(v, dict)
             and isinstance(v.get("Start VPN"), int)
             and v["Start VPN"] <= addr <= v.get("End VPN", -1)),
            None,
        )
        if vad is None:
            continue
        start = vad["Start VPN"]
        if start == 0:                      # smss/csrss base-0x0 artifact
            continue
        if vad.get("File"):                 # backed by a file -> not injection
            continue
        # Require PRIVATE committed memory. Injected code lives in private VADs
        # (VadS); mapped image sections (even non-file-backed SEC_IMAGE, e.g.
        # ShellExperienceHost's WRITECOPY-exec region) are PrivateMemory=0 and are
        # a benign FP source. Gating on private (not on executable protection)
        # also KEEPS RW private injections whose thread executes from data memory
        # (e.g. imagery ruby, PAGE_READWRITE) — which an EXECUTE-only gate missed.
        if not vad.get("PrivateMemory"):
            continue
        name = pid2name.get(pid)
        if not _flag(name, vad.get("Protection")):
            continue
        rid = f"{pid}-{start:#x}"
        candidates.setdefault(rid, {
            "region_id": rid, "PID": pid, "Process": name,
            "Protection": vad.get("Protection"), "Start VPN": start,
            "End VPN": vad.get("End VPN"), "flagged_by": [], "reason": [],
            "dump_path": None, "sha256": None,
        })
        rec = candidates[rid]
        if "thread" not in rec["flagged_by"]:
            rec["flagged_by"].append("thread")
        reason = ("RWX thread-start" if vad.get("Protection") == RWX
                  else "thread-start in non-allowlisted process")
        if reason not in rec["reason"]:
            rec["reason"].append(reason)

    # Dump the thread-driven candidate VADs (vadinfo --dump) and hash them.
    if candidates:
        dumpdir = wd / "regions"
        for pid in {c["PID"] for c in candidates.values()}:
            _run_json(image, "windows.vadinfo.VadInfo", "--pid", str(pid), "--dump",
                      out=str(dumpdir))
        for rec in candidates.values():
            hexstart = f"{rec['Start VPN']:x}"
            hit = next((f for f in glob.glob(str(dumpdir / f"pid.{rec['PID']}.vad.0x{hexstart}-*"))), None)
            if hit:
                rec["dump_path"] = hit
                rec["sha256"] = _sha256(Path(hit))

    # Secondary source = malfind, used as CORROBORATION ONLY. malfind flags all
    # RWX private VADs, which on real desktops includes huge amounts of benign
    # Office/browser/JIT RWX (DumpMe: 31 such FPs). §9.7 only validated the §7
    # rule on thread-driven hits, not on malfind, so malfind is NOT an independent
    # candidate source here: it only raises confidence on a region a thread
    # already flagged (same region_id). KNOWN GAP (flagged to user, DESIGN §9.8):
    # a pure malfind-only injection with no anomalous thread (e.g. BlackEnergy's
    # winlogon regions) is therefore NOT surfaced as its own candidate — such a
    # host is still detected if it ALSO has an anomalous thread (BlackEnergy via
    # svchost). Making malfind a clean independent source needs its own
    # discriminator (PE-header / shellcode vs Office-macro JIT) — deferred.
    malfind_dir = wd / "malfind"
    malfind_dir.mkdir(exist_ok=True)
    for r in _run_json(image, "windows.malfind.Malfind", "--dump", out=str(malfind_dir)):
        if not isinstance(r, dict):
            continue
        start = r.get("Start VPN")
        if not isinstance(start, int):
            continue
        rid = f"{r.get('PID')}-{start:#x}"
        rec = candidates.get(rid)
        if rec is None:
            continue                          # corroboration only — no new regions
        if "malfind" not in rec["flagged_by"]:
            rec["flagged_by"].append("malfind")
            rec["reason"].append("malfind RWX (corroborates thread-driven)")
        fout = r.get("File output")
        if rec["dump_path"] is None and isinstance(fout, str) and fout not in ("", "Disabled"):
            p = malfind_dir / fout
            if p.exists():
                rec["dump_path"] = str(p)
                rec["sha256"] = _sha256(p)

    out_list = sorted(candidates.values(), key=lambda c: (c["PID"], c["Start VPN"]))
    return {
        "image": Path(image).name,
        "stage": "1.5-discrimination",
        "allowlist_provisional": True,
        "candidate_count": len(out_list),
        "candidates": out_list,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: python -m src.discriminate <image> <workdir>", file=sys.stderr)
        return 2
    image, workdir = argv[1], argv[2]
    if not Path(image).exists():
        print(f"error: image not found: {image}", file=sys.stderr)
        return 1
    doc = discriminate(image, workdir)
    json.dump(doc, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
