import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).parents[1] / 'src/ghidra_scripts/DelphiReSym.py'

class Address(int):
    def add(self, amount):
        return Address(self + amount)

class Memory:
    def __init__(self, data):
        self.data = data
    def getMemory(self):
        return self
    def getByte(self, address):
        return self.data[address]

class StringTests(unittest.TestCase):
    def load(self, data):
        tree = ast.parse(SOURCE.read_text())
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {'read_pascal_str', 'pascal_str_size', 'iter_vmt_self_references'}]
        namespace = {'struct': __import__('struct'), 'Address': Address, 'currentProgram': Memory(data)}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(SOURCE), 'exec'), namespace)
        return namespace
    def test_utf8_and_encoded_cursor(self):
        raw = 'Méthode'.encode('utf-8')
        ns = self.load(bytes([len(raw)]) + raw + b'\x04Next')
        self.assertEqual(ns['read_pascal_str'](Address(0)), 'Méthode')
        following = ns['pascal_str_size'](Address(0))
        self.assertEqual(ns['read_pascal_str'](Address(following)), 'Next')
    def test_record_bound(self):
        ns = self.load(b'\x05abcdef')
        with self.assertRaises(ValueError):
            ns['read_pascal_str'](Address(0), Address(4))
    def test_scanner_matches_bytewise_oracle(self):
        import random
        rng = random.Random(31)
        for width in (4, 8):
            base = 0x40fff0 if width == 4 else 0x14000fff0
            data = bytearray(rng.randbytes(140000))
            for off in (0, 17, 65520, 65536, len(data) - width):
                data[off:off + width] = (base + off + 88).to_bytes(width, 'little')
            ns = self.load(b'')
            actual = list(ns['iter_vmt_self_references'](bytes(data), base, width, 88, 0, len(data)))
            expected = [off for off in range(len(data) - width + 1) if int.from_bytes(data[off:off+width], 'little') == base + off + 88]
            self.assertEqual(actual, expected)
    def test_windows_ansi(self):
        ns = self.load(b'\x03M\xe9t')
        self.assertEqual(ns['read_pascal_str'](Address(0)), 'Mét')
    def test_truncated_name_is_not_silently_accepted(self):
        ns = self.load(b'\x05ab')
        with self.assertRaises(IndexError):
            ns['read_pascal_str'](Address(0))


class ApplicationTests(unittest.TestCase):
    def test_missing_signature_is_not_applied_as_void_or_no_parameters(self):
        from types import SimpleNamespace
        tree = ast.parse(SOURCE.read_text())
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'apply_symbols']
        calls = []
        ns = {'VmtMdtMapping': object, 'ArchitectureSpecificSettings': object,
              'debug': lambda *args: None, 'check_cancel': lambda: None,
              'prepare_data_type': lambda *args: SimpleNamespace(namespace='Unit.T'),
              'apply_function_names': lambda *args: 1,
              'apply_namespaces': lambda *args: 1,
              'apply_return_types': lambda entry, typ: calls.append(('return', typ)) or 0,
              'apply_parameter_tuples': lambda *args: calls.append(('params', args[1])) or 1}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(SOURCE), 'exec'), ns)
        method = SimpleNamespace(function_name='Method', function_entry_point=1,
                                 return_type_str=None, parameter_entries={}, parameters_valid=False)
        mapping = SimpleNamespace(entries={1: SimpleNamespace(namespace='Unit.T', method_entries={2: method})})
        result = ns['apply_symbols'](mapping, object())
        self.assertEqual(calls, [('return', None)])
        self.assertEqual(result['parameter_set'], 0)
        method.parameters_valid = True
        calls.clear()
        result = ns['apply_symbols'](mapping, object())
        self.assertEqual(result['parameter_set'], 1)
        self.assertIn(('params', {}), calls)
        method.function_name = None
        calls.clear()
        result = ns['apply_symbols'](mapping, object())
        self.assertEqual(result['function'], 0)
        self.assertEqual(calls, [])

if __name__ == '__main__':
    unittest.main()
