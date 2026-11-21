#!/usr/bin/env python3
"""
Dump a Delphi 2..7 method table (MDT), raw and parsed.

This is the tool that showed the legacy layout:
    Word count; {Word size; Pointer address; ShortString name}[]

    python dump_mdt.py /path/to/delphi7.exe --class TFrm_Main
    python dump_mdt.py /path/to/delphi7.exe --vmt 0x00401234 --hex
    python dump_mdt.py /path/to/delphi7.exe --all

--all replays the walk over every class and prints the recovered methods, which is the
same set the Ghidra script should produce.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
from extract_delphi_syms import PE, collect, detect_header  # noqa: E402


def hexdump(pe: PE, va: int, length: int) -> None:
    off = pe.offset(va)
    if off is None:
        print(f"  {va:08X} is not mapped")
        return
    for row in range(0, length, 16):
        chunk = pe.data[off + row:off + row + 16]
        if not chunk:
            break
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        text = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        print(f"  {va + row:08X}  {hexpart:<47}  {text}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Dump a Delphi 2..7 method table.")
    ap.add_argument("path")
    ap.add_argument("--class", dest="cls", help="class name, e.g. TFrm_Main")
    ap.add_argument("--vmt", help="VMT address in hex, e.g. 0x473D28")
    ap.add_argument("--all", action="store_true", help="walk every class")
    ap.add_argument("--hex", action="store_true", help="also hexdump the raw MDT")
    args = ap.parse_args()

    pe = PE(args.path)
    classes = collect(pe, detect_header(pe, pe.section("CODE", ".text")))
    if args.all:
        for cls in classes:
            if not cls["methods"]:
                continue
            print(f"class {cls['name']}  VMT={cls['vmt']:08X} MDT={cls['mdt']:08X}"
                  f"  ({len(cls['methods'])})")
            for method in cls["methods"]:
                print(f"    {method['entry']:08X}  {method['name']}")
        return 0

    target = None
    if args.vmt:
        wanted = int(args.vmt, 16)
        target = next((c for c in classes if c["vmt"] == wanted), None)
    elif args.cls:
        target = next((c for c in classes if c["name"] == args.cls), None)
    else:
        print("give --class, --vmt or --all")
        return 2
    if target is None:
        print("not found")
        return 1

    print(f"class {target['name']}  VMT={target['vmt']:08X} MDT={target['mdt']:08X}")
    if args.hex:
        hexdump(pe, target["mdt"], 0x60)
    for method in target["methods"]:
        print(f"    {method['entry']:08X}  {method['name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
