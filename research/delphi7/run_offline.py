"""
Run DelphiReSym.py's VMT/MDT pipeline offline, without a Ghidra process.

Stubs just enough of the Ghidra API (Memory / Address / Program / TaskMonitor) to execute
steps 1-6 of the script against a real PE file and print what it recovers. Useful as a
regression harness: edit the script, re-run this, compare the recovered symbol count.

    python run_offline.py path/to/sample.exe [--script path/to/DelphiReSym.py]

The default --script is this repo's src/ghidra_scripts/DelphiReSym.py. The stub covers
only the subset of the Ghidra API the script touches; anything outside it raises, which is
intended -- a silent no-op would make the harness lie.
"""
import argparse
import os
import struct
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))

_ap = argparse.ArgumentParser(description="Run DelphiReSym's pipeline offline.")
_ap.add_argument("path", help="PE file (unpacked Delphi binary)")
_ap.add_argument("--script", default=os.path.join(HERE, "..", "..", "src",
                                                  "ghidra_scripts", "DelphiReSym.py"),
                 help="DelphiReSym.py to execute")
_args = _ap.parse_args()

PATH = _args.path

SCRIPT = _args.script

data = open(PATH, "rb").read()
pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
optsz = struct.unpack_from("<H", data, pe + 20)[0]
opt = pe + 24
image_base = struct.unpack_from("<I", data, opt + 28)[0]
SECS = []
off = opt + optsz
for _ in range(nsec):
    name = data[off:off + 8].rstrip(b"\0").decode("latin-1")
    vsz, va, rsz, rptr = struct.unpack_from("<IIII", data, off + 8)
    SECS.append({"name": name, "va": image_base + va, "vsz": vsz,
                 "rsz": rsz, "rptr": rptr})
    off += 40


class MemoryAccessException(Exception):
    pass


class AddressOutOfBoundsException(Exception):
    pass


class Address:
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = int(v) & 0xFFFFFFFF

    def add(self, n):
        return Address(self.v + int(n))

    def subtract(self, n):
        if isinstance(n, Address):
            return self.v - n.v
        return Address(self.v - int(n))

    def getOffset(self):
        return self.v

    def __eq__(self, o):
        return isinstance(o, Address) and o.v == self.v

    def __lt__(self, o):
        return self.v < o.v

    def __le__(self, o):
        return self.v <= o.v

    def __gt__(self, o):
        return self.v > o.v

    def __ge__(self, o):
        return self.v >= o.v

    def __hash__(self):
        return hash(self.v)

    def __int__(self):
        return self.v

    def __repr__(self):
        return f"{self.v:08X}"


def toAddr(x):
    return x if isinstance(x, Address) else Address(int(x, 0) if isinstance(x, str) else x)


def _sec_of(va):
    for s in SECS:
        if s["va"] <= va < s["va"] + s["rsz"]:
            return s
    return None


class Memory:
    def _read(self, va, n):
        s = _sec_of(va)
        if s is None or va + n > s["va"] + s["rsz"]:
            raise MemoryAccessException(f"{va:08X}+{n}")
        o = s["rptr"] + (va - s["va"])
        return data[o:o + n]

    def getByte(self, addr):
        b = self._read(int(addr), 1)[0]
        return b - 256 if b > 127 else b

    def getShort(self, addr):
        v = struct.unpack("<H", self._read(int(addr), 2))[0]
        return v - 65536 if v > 32767 else v

    def getInt(self, addr):
        return struct.unpack("<i", self._read(int(addr), 4))[0]

    def getLong(self, addr):
        return struct.unpack("<q", self._read(int(addr), 8))[0]

    def getBytes(self, addr, buf):
        b = self._read(int(addr), len(buf))
        buf[:] = b
        return len(b)

    def getBlocks(self):
        return [MemoryBlock(s) for s in SECS]


class MemoryBlock:
    def __init__(self, s):
        self.s = s

    def getName(self):
        return self.s["name"]

    def getStart(self):
        return Address(self.s["va"])

    def getEnd(self):
        return Address(self.s["va"] + self.s["rsz"] - 1)

    def getSize(self):
        return self.s["rsz"]


class Dummy:
    def __init__(self, *a, **k):
        pass


class _Mod(types.ModuleType):
    def __getattr__(self, name):
        if name == "MemoryAccessException":
            return MemoryAccessException
        if name == "AddressOutOfBoundsException":
            return AddressOutOfBoundsException
        if name == "Address":
            return Address
        if name == "Memory":
            return Memory
        if name == "MemoryBlock":
            return MemoryBlock
        cls = type(name, (Dummy,), {})
        setattr(self, name, cls)
        return cls


for mod in ("ghidra", "ghidra.program", "ghidra.program.model", "ghidra.program.model.symbol",
            "ghidra.program.model.listing", "ghidra.program.model.mem",
            "ghidra.program.model.address", "ghidra.program.model.data",
            "ghidra.util", "ghidra.util.task", "ghidra.util.exception",
            "ghidra.ghidra_builtins", "pyghidra"):
    sys.modules[mod] = _Mod(mod)
sys.modules["pyghidra"].started = lambda: False

# minimal jpype stand-in: JArray(JByte)(n) -> a bytearray that getBytes() can fill
_jpype = _Mod("jpype")


class _JByte:
    pass


_jpype.JByte = _JByte
_jpype.JArray = lambda typ: (lambda n: bytearray(n))
sys.modules["jpype"] = _jpype

memory = Memory()


class Program:
    def getMemory(self):
        return memory

    def getDefaultPointerSize(self):
        return 4


class Monitor:
    def isCancelled(self):
        return False

    def setMessage(self, *_a):
        pass


g = {
    "__name__": "drs_d7",
    "currentProgram": Program(),
    "monitor": Monitor(),
    "toAddr": toAddr,
}
src = open(SCRIPT, encoding="utf-8").read()
_mod = types.ModuleType("drs_d7")
_mod.__dict__.update(g)
sys.modules["drs_d7"] = _mod
g = _mod.__dict__
exec(compile(src, SCRIPT, "exec"), g)

print("=== steps 1-6 ===")
text_section = g["get_text_section"](memory)
settings = g["get_architecture_settings"](text_section)
print(f"jump_dist={settings.jump_dist}  legacy_mdt={settings.legacy_mdt}")

vmts = g["find_vmts"](settings)
print(f"find_vmts -> {len(vmts)} VMT(s): {[str(v) for v in vmts]}")

mdt_rel = g["get_vmt_field_addresses"](vmts, settings, settings.mdt_offset)
rtti_rel = g["get_vmt_field_addresses"](vmts, settings, settings.rtti_offset)
top = g["traverse_mdt_top_level"](mdt_rel, settings)
sym = g["traverse_method_entries"](top, settings)
all_sym = g["add_namespace_information"](rtti_rel, sym, settings)

print(f"\nfinal VMTs with symbols: {len(all_sym.entries)}")
total = 0
for vmt, info in all_sym.entries.items():
    print(f"\nVMT {vmt}  ns={info.namespace!r}  methods={len(info.method_entries)}")
    for me, mi in info.method_entries.items():
        total += 1
        print(f"   {mi.function_entry_point}  {mi.function_name}")
print(f"\ntotal method names recovered: {total}")
