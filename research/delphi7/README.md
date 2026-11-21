# Delphi 2 – 7 support: how the format was derived

These notes and the harness in this folder are what the Delphi 2..7 support in
`src/ghidra_scripts/DelphiReSym.py` was built from. They are kept because the layout
differences are easy to get wrong in the same way twice.

Test binary: a Delphi 7 application (Borland compiler, 32-bit, unpacked).
All numbers below come from that one sample — treat them as "what to expect", not as
constants.

## What differs from Delphi 2009+

| | Delphi 2 .. 7 | Delphi 2009+ |
|---|---|---|
| Code section name | `CODE` | `.text` |
| VMT header size | **76** bytes | 88 bytes |
| Method table (MDT) count field | at `MDT + 0` | at `MDT + 2` |
| MDT entries | variable length: `Word size; Pointer address; ShortString name` | fixed size references to MethodEntry structs |
| Method entry | name + entry point only | name, entry point, return type RTTI, parameter entries |

Delphi 2009 added `vmtEquals` / `vmtGetHashCode` / `vmtToString` to `TObject`, which is
where the 12 extra header bytes come from. The self pointer at `VMT + 0` therefore points
at `VMT + 76` on old binaries and `VMT + 88` on new ones — that is what the probe scores.

## The three bugs this fixed

1. **`find_vmts` looked only for a section named `.text`.** Delphi 2..7 call it `CODE`, so
   the scan never even started.
2. **`jump_dist` was hardcoded to 88**, so every candidate was rejected and the tool
   printed `Number of VMTs found: 0`.
3. **The MDT was parsed as fixed size entries with the count at `+2`**, which on a legacy
   MDT reads garbage: the "count" is the low word of the first entry's size.

## Evidence produced by the probes

With the section name fixed and every plausible header size tried, the self-pointer score
is unambiguous — the old header size wins by two orders of magnitude and the new one scores
exactly zero:

```
header 76: ~200 candidates      header 88: 0 candidates
```

That candidate count is also the number of class references the walk then recovers, which
is the cross-check that matters: if the header size is wrong the count collapses to zero,
and if the MDT stride is wrong the class count still matches but the method count does not.

Walking the legacy MDT by adding each entry's own size word terminates cleanly on every
class; the entry sizes observed are `7 + name length` rounded up to a dword boundary.
A handful of classes publish methods, and those names come back identical to the ones the
Ghidra script produces.

## Files

| file | what it does |
|---|---|
| `run_offline.py` | Runs the real `DelphiReSym.py` against a PE file with a stubbed Ghidra API (steps 1–6) and prints the recovered symbols. Regression harness, no Ghidra process needed. |
| `probe_header.py` | Prints the self-pointer score for every plausible header size. |
| `dump_mdt.py` | Hexdumps and parses one class's MDT (`--class`, `--vmt`, or `--all`). This is what showed the variable length layout. |

The remaining one-off scripts used during the investigation (`scan_vmt.py`,
`scan_vmt2.py`, `diag_vmt.py`, `dump_vmt.py`, `sim_check.py`) were folded into the three
above or into the script itself; they are not shipped.

## Reproducing

```bash
# what the patched script recovers, without Ghidra
python run_offline.py /path/to/delphi7.exe

# same thing without any Ghidra stub, straight from the PE
python ../../tools/extract_delphi_syms.py /path/to/delphi7.exe
```

Both should report 76 bytes, the same class count and the same method names.
