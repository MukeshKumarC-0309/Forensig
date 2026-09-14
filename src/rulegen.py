"""
Stage 2 + Stage 3 — Rule-material extraction and YARA rule generation
(DESIGN.md v1.2 §4 Stage 2/3, parameters from §7).

Input : the Stage 1.5 candidate document (src.discriminate), whose candidates
        carry dump_path (full region bytes) + sha256.
Output: for each candidate whose region is resident and yields enough material,
        a YARA rule that COMPILES (yara-x) and matches the region; candidates
        below the min-material floor are reported as indicator-only (no rule).

§7 parameters applied here:
- byte-pattern primary: 16-32 bytes of executable-section code, operand bytes
  (displacements/immediates) wildcarded via capstone to avoid single-sample
  over-fit.
- strings secondary: ASCII + UTF-16, min length 8, stoplist applied, cap 8-12.
- min-material floor: 1 byte-pattern OR >= 3 distinctive strings, else indicator.
- compile gate: rule must compile via yara-x (yara-python has no py3.14 wheel).
"""

from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path

import struct

import yara_x
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

MIN_STR_LEN = 8
STR_CAP = 12
MIN_STRINGS_FLOOR = 3
BP_TARGET_BYTES = 24            # aim for ~24 bytes of wildcarded code

# §7 stoplist seed (grow empirically). Generic PE / benign-runtime strings and
# the printable-ASCII-table artifact are dropped before ranking.
STOPLIST = {
    "!This program cannot be run in DOS mode.", ".text", ".rdata", ".data",
    ".rsrc", ".reloc", "`.rdata", "@.data", "@.rsrc", "@.reloc", "RichG", "Rich",
}
_ASCII_TABLE = bytes(range(0x20, 0x7f))     # the full printable run (an artifact)


def _ascii_strings(b: bytes, n: int) -> list[str]:
    return [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{%d,}" % n, b)]


def _wide_strings(b: bytes, n: int) -> list[str]:
    out = []
    for m in re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % n, b):
        try:
            out.append(m.decode("utf-16-le"))
        except UnicodeDecodeError:
            pass
    return out


# Substrings that mark generic statically-linked-library / runtime boilerplate
# (drop for rule specificity; observed in the DumpMe carve: libjpeg + MSIL/CLR).
_DROP_SUBSTR = (
    "JPEG", "JFIF", "Thomas G. Lane", "Start Of Frame", "Huffman",
    "MSIL", "native constructor", "DllMain", "/clr", "CorExitProcess",
)


def _ordered_ratio(s: str) -> float:
    """Fraction of adjacent char pairs that are consecutive (c, c+1). ASCII-table
    / charset artifacts score very high; normal text scores low."""
    if len(s) < 2:
        return 0.0
    consec = sum(1 for i in range(1, len(s)) if ord(s[i]) == ord(s[i - 1]) + 1)
    return consec / (len(s) - 1)


def _is_artifact(s: str) -> bool:
    if s in STOPLIST:
        return True
    if s[:1] in ".@`":
        return True
    if _ordered_ratio(s) >= 0.5:            # ASCII-table / charset run artifact
        return True
    if any(sub in s for sub in _DROP_SUBSTR):
        return True
    return False


def pe_arch(b: bytes) -> int | None:
    """Return capstone mode from an injected PE's Machine field, or None."""
    if b[:2] != b"MZ" or len(b) < 0x40:
        return None
    try:
        e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
        if b[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        machine = struct.unpack_from("<H", b, e_lfanew + 4)[0]
    except struct.error:
        return None
    return {0x14C: CS_MODE_32, 0x8664: CS_MODE_64}.get(machine)


def extract_strings(b: bytes) -> list[str]:
    """Stage 2 strings: filtered, de-duped, ranked by specificity, capped."""
    raw = _ascii_strings(b, MIN_STR_LEN) + _wide_strings(b, MIN_STR_LEN)
    seen, keep = set(), []
    for s in raw:
        if s in seen or _is_artifact(s):
            continue
        # require some alphabetic content (drops pure punctuation/opcode runs)
        if sum(c.isalpha() for c in s) < 4:
            continue
        seen.add(s)
        keep.append(s)
    # rank: longer + more unique-char strings first
    keep.sort(key=lambda s: (-len(set(s)), -len(s)))
    return keep[:STR_CAP]


def byte_pattern(b: bytes, mode: int) -> str | None:
    """Stage 2 byte pattern: disassemble a code run, wildcard operand bytes,
    return a YARA hex string (or None if too little code)."""
    # choose a code offset: past the PE header if this is a mapped image
    start = 0x1000 if b[:2] == b"MZ" else next((i for i, x in enumerate(b) if x), 0)
    code = b[start:start + 512]
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    toks: list[str] = []
    nbytes = 0
    for insn in md.disasm(code, 0):
        raw = bytearray(insn.bytes)
        enc = insn.encoding
        mask = [False] * len(raw)
        for off, size in ((enc.disp_offset, enc.disp_size), (enc.imm_offset, enc.imm_size)):
            for i in range(off, min(off + size, len(raw))):
                if i > 0:                    # keep at least the opcode byte
                    mask[i] = True
        for i, byte in enumerate(raw):
            toks.append("??" if mask[i] else f"{byte:02x}")
        nbytes += len(raw)
        if nbytes >= BP_TARGET_BYTES:
            break
    if nbytes < 8 or all(t == "??" for t in toks):
        return None
    # trim trailing wildcards (a pattern shouldn't end in ??)
    while toks and toks[-1] == "??":
        toks.pop()
    return " ".join(toks)


def _rule_name(process: str | None, region_id: str) -> str:
    base = re.sub(r"[^A-Za-z0-9]", "_", (process or "proc")) + "_" + region_id.replace("-", "_").replace("0x", "")
    return "injected_" + re.sub(r"_+", "_", base)


def build_rule(cand: dict, mode: int) -> dict:
    """Stage 3: assemble + compile a rule for one candidate. Returns a
    generated_rules record (or an indicator-only marker)."""
    out = {
        "region_id": cand["region_id"], "process": cand.get("Process"),
        "rule_name": None,
        "elements_used": {"byte_patterns": [], "strings": []},
        "match_threshold": None, "yara_text": None, "compiled": False,
        "indicator_only": True, "note": None,
    }
    dp = cand.get("dump_path")
    if not dp or not Path(dp).exists():
        out["note"] = "no resident dump — indicator only"
        return out
    b = Path(dp).read_bytes()
    if sum(1 for x in b if x) == 0:
        out["note"] = "region all-zero / non-resident — indicator only"
        return out

    # Arch: prefer the injected PE's Machine field; fall back to the CLI default.
    region_mode = pe_arch(b) or mode
    bp = byte_pattern(b, region_mode)
    strings = extract_strings(b)          # already stoplist-filtered + ranked

    # §7 min-material floor
    if bp is None and len(strings) < MIN_STRINGS_FLOOR:
        out["note"] = f"below floor (byte_pattern=False, distinct_strings={len(strings)}) — indicator only"
        return out

    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    def meta_val(s: str) -> str:
        # metadata strings can't span the escaping rules of pattern strings safely;
        # keep them short + escaped.
        return esc(s[:120])

    name = _rule_name(cand.get("Process"), cand["region_id"])
    meta = ["  meta:",
            f'    image = "{esc(cand.get("_image",""))}"',
            f'    process = "{esc(str(cand.get("Process")))}"',
            f'    region_id = "{cand["region_id"]}"',
            f'    sha256 = "{cand.get("sha256")}"',
            f'    generated = "{datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}"']

    # §7 condition policy: the byte-pattern is the REQUIRED anchor when present
    # (a code signature is specific; an "OR N generic strings" branch would
    # false-positive on any binary sharing a library). Distinctive strings go in
    # metadata as analyst context, NOT into the condition. Only when there is NO
    # byte-pattern do we fall back to a strings-only rule (>= floor distinctive).
    strings_block, condition = [], None
    if bp:
        strings_block = [f"    $bp = {{ {bp} }}"]
        condition = "$bp"
        out["elements_used"]["byte_patterns"].append(bp)
        for i, s in enumerate(strings[:3]):          # notable strings -> meta
            meta.append(f'    notable_string_{i} = "{meta_val(s)}"')
    else:
        used = strings[:STR_CAP]
        strings_block = [f'    $s{i} = "{esc(s)}"' for i, s in enumerate(used)]
        condition = f"{MIN_STRINGS_FLOOR} of ($s*)"
        out["elements_used"]["strings"] = used

    lines = [f"rule {name} {{", *meta, "  strings:", *strings_block,
             "  condition:", f"    {condition}", "}"]
    rule_text = "\n".join(lines)

    out["rule_name"] = name
    out["match_threshold"] = condition
    out["yara_text"] = rule_text
    try:
        rules = yara_x.compile(rule_text)
        out["compiled"] = True
        # self-match sanity
        matched = [m.identifier for m in rules.scan(b).matching_rules]
        out["indicator_only"] = False
        out["note"] = f"compiled; self-match={name in matched}"
    except Exception as exc:            # noqa: BLE001 - record any compile failure
        out["compiled"] = False
        out["note"] = f"compile failed: {exc}"
    return out


def generate(stage15_doc: dict, out_dir: str, mode: int) -> dict:
    od = Path(out_dir)
    od.mkdir(parents=True, exist_ok=True)
    image = stage15_doc.get("image", "")
    rules, indicators = [], []
    for cand in stage15_doc.get("candidates", []):
        cand = {**cand, "_image": image}
        rec = build_rule(cand, mode)
        if rec["compiled"]:
            (od / f"{rec['rule_name']}.yar").write_text(rec["yara_text"], encoding="utf-8")
            rules.append(rec)
        else:
            indicators.append({"region_id": rec["region_id"], "process": rec["process"],
                               "note": rec["note"]})
    return {
        "image": image, "stage": "2-3-rulegen",
        "generated_rules": rules,
        "indicators_without_rule": indicators,
        "rule_count": len(rules), "indicator_count": len(indicators),
    }


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: python -m src.rulegen <stage15_json> <out_dir> [--arch x86|x64]",
              file=sys.stderr)
        return 2
    stage15_json, out_dir = argv[1], argv[2]
    mode = CS_MODE_32 if (len(argv) > 3 and argv[3] == "--arch" and argv[4] == "x86") else CS_MODE_64
    with open(stage15_json, encoding="utf-8") as f:
        doc = json.load(f)
    result = generate(doc, out_dir, mode)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
