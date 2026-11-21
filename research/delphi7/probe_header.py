#!/usr/bin/env python3
"""
Print the VMT self-pointer score for every plausible header size.

A real VMT has, at VMT+0, a dword equal to (VMT + header size) -- the self pointer to the
class reference -- and its vmtClassName field points at a printable Pascal string. Counting
both conditions across the code section separates real VMTs from the "address + constant"
coincidences scattered through x86 code.

    python probe_header.py /path/to/delphi7.exe

On a Delphi 7 binary the 76 score dominates by two orders of magnitude and 88 scores zero;
on Delphi 2009+ it is the other way round.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
from extract_delphi_syms import PE, VMT_HEADER_SIZES  # noqa: E402

import struct  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip())
        return 2
    pe = PE(sys.argv[1])
    code = pe.section("CODE", ".text")
    if code is None:
        print("no code section ('CODE' / '.text') found")
        return 1
    base = code["va"]
    raw = pe.data[code["rptr"]:code["rptr"] + code["rsize"]]
    limit = (len(raw) - 0x24) // 4 * 4
    scores = {size: 0 for size in VMT_HEADER_SIZES}
    for i, (value,) in enumerate(struct.iter_unpack("<I", raw[:limit])):
        offset = i * 4
        delta = (value - (base + offset)) & 0xFFFFFFFF
        if delta in scores and pe.short_string(pe.dword(base + offset + 0x20)):
            scores[delta] += 1
    print(f"section {code['name']}  size {code['rsize']} bytes")
    for size, score in sorted(scores.items()):
        print(f"  header {size:3d}: {score:6d} candidate(s)")
    best = max(scores, key=lambda size: scores[size])
    print(f"-> header size {best if scores[best] else 88} (default when nothing scores)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
