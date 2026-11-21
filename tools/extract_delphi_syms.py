#!/usr/bin/env python3
"""
Recover Delphi class and method names from a PE file -- without Ghidra.

This is the standalone companion to DelphiReSym.py: it walks the same metadata
(VMT -> MDT -> MethodEntry) straight out of the file, so you can triage a sample
in a second before deciding whether to load it into Ghidra.

Supported layouts:

  * Delphi 2 .. 7     76 byte VMT header, variable length MDT entries
                      (Word size; Pointer address; ShortString name) -- full recovery
  * Delphi 2009+      88 byte VMT header, fixed size method entry references --
                      class names only (run DelphiReSym.py in Ghidra for the rest)

Usage:
    python extract_delphi_syms.py sample.exe
    python extract_delphi_syms.py sample.exe --json > syms.json
    python extract_delphi_syms.py sample.exe --header 76      # force the layout

The header size is auto-detected by counting dword slots whose value is
(own address + header size) and whose vmtClassName field points at a printable
Pascal string: on a Delphi 7 binary that scores ~200 for 76 and 0 for 88.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys

VMT_HEADER_SIZES = (76, 88)


class PE:
    """Minimal PE reader: sections plus VA <-> file offset translation."""

    def __init__(self, path: str):
        self.data = open(path, "rb").read()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe:pe + 4] != b"PE\0\0":
            raise SystemExit("not a PE file")
        n_sections = struct.unpack_from("<H", self.data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", self.data, pe + 20)[0]
        opt = pe + 24
        self.image_base = struct.unpack_from("<I", self.data, opt + 28)[0]
        self.sections = []
        off = opt + opt_size
        for _ in range(n_sections):
            name = self.data[off:off + 8].rstrip(b"\0").decode("latin-1")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", self.data, off + 8)
            self.sections.append({
                "name": name, "va": self.image_base + va,
                "vsize": vsize, "rsize": rsize, "rptr": rptr,
            })
            off += 40

    def section(self, *names: str) -> dict | None:
        for wanted in names:
            for sec in self.sections:
                if sec["name"] == wanted:
                    return sec
        return None

    def offset(self, va: int) -> int | None:
        for sec in self.sections:
            if sec["va"] <= va < sec["va"] + sec["rsize"]:
                return sec["rptr"] + (va - sec["va"])
        return None

    def dword(self, va: int) -> int | None:
        off = self.offset(va)
        return None if off is None else struct.unpack_from("<I", self.data, off)[0]

    def word(self, va: int) -> int | None:
        off = self.offset(va)
        return None if off is None else struct.unpack_from("<H", self.data, off)[0]

    def short_string(self, va: int | None, max_len: int = 60) -> str | None:
        """Delphi ShortString: length byte followed by ASCII."""
        if not va:
            return None
        off = self.offset(va)
        if off is None:
            return None
        length = self.data[off]
        if not 1 <= length <= max_len:
            return None
        raw = self.data[off + 1:off + 1 + length]
        if len(raw) != length or any(c < 0x20 or c > 0x7E for c in raw):
            return None
        return raw.decode("latin-1")


def detect_header(pe: PE, code: dict) -> int:
    """Score 76 vs 88 and return the winner (88 when neither scores)."""
    base = code["va"]
    raw = pe.data[code["rptr"]:code["rptr"] + code["rsize"]]
    limit = (len(raw) - 0x24) // 4 * 4
    scores = {size: 0 for size in VMT_HEADER_SIZES}
    for i, (value,) in enumerate(struct.iter_unpack("<I", raw[:limit])):
        offset = i * 4
        delta = (value - (base + offset)) & 0xFFFFFFFF
        if delta not in scores:
            continue
        if pe.short_string(pe.dword(base + offset + 0x20)):
            scores[delta] += 1
    best = max(scores, key=lambda size: scores[size])
    return best if scores[best] else 88


def walk_legacy_mdt(pe: PE, mdt: int, code_lo: int, code_hi: int) -> list[tuple[str, int]]:
    """Delphi 2..7: Word count; {Word size; Pointer address; ShortString name}[]"""
    count = pe.word(mdt) or 0
    methods: list[tuple[str, int]] = []
    cursor = mdt + 2
    for _ in range(count):
        size = pe.word(cursor)
        if not size or size < 7:
            break
        entry = pe.dword(cursor + 2)
        name = pe.short_string(cursor + 6)
        if not entry or not name or not code_lo <= entry < code_hi:
            break
        methods.append((name, entry))
        cursor += size
    return methods


def collect(pe: PE, header: int) -> list[dict]:
    code = pe.section("CODE", ".text")
    if code is None:
        raise SystemExit("no code section ('CODE' / '.text') found")
    lo, hi = code["va"], code["va"] + code["rsize"]
    raw = pe.data[code["rptr"]:code["rptr"] + code["rsize"]]

    classes: list[dict] = []
    limit = (len(raw) - 0x24) // 4 * 4
    for i, (value,) in enumerate(struct.iter_unpack("<I", raw[:limit])):
        offset = i * 4
        va = lo + offset
        if (value - va) & 0xFFFFFFFF != header:
            continue
        name = pe.short_string(pe.dword(va + 0x20))
        if not name:
            continue
        mdt = pe.dword(va + 0x18) or 0
        methods = []
        if header == 76 and lo <= mdt < hi and mdt > va:
            methods = walk_legacy_mdt(pe, mdt, lo, hi)
        classes.append({
            "vmt": va, "mdt": mdt, "name": name,
            "methods": [{"name": n, "entry": a} for n, a in methods],
        })
    classes.sort(key=lambda c: c["vmt"])
    return classes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("path", help="PE file (unpacked Delphi executable)")
    ap.add_argument("--header", type=int, choices=VMT_HEADER_SIZES,
                    help="force the VMT header size instead of auto-detecting")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("--quiet", action="store_true", help="skip classes without methods")
    args = ap.parse_args()

    pe = PE(args.path)
    header = args.header or detect_header(pe, pe.section("CODE", ".text"))
    classes = collect(pe, header)

    if args.json:
        json.dump({"header": header, "classes": classes}, sys.stdout,
                  indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0

    with_methods = [c for c in classes if c["methods"]]
    total = sum(len(c["methods"]) for c in classes)
    print(f"VMT header: {header} bytes"
          f"   classes: {len(classes)}"
          f"   with published methods: {len(with_methods)}"
          f"   methods: {total}")
    if header == 88:
        print("note: Delphi 2009+ method entry references are not parsed here; "
              "run DelphiReSym.py in Ghidra for names and signatures.")
    print()

    for cls in classes:
        if args.quiet and not cls["methods"]:
            continue
        print(f"class {cls['name']}  VMT={cls['vmt']:08X} MDT={cls['mdt']:08X}"
              f"  ({len(cls['methods'])} published)")
        for method in cls["methods"]:
            print(f"    {method['entry']:08X}  {cls['name']}.{method['name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
