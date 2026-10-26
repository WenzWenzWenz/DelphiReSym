"""Analyze a real Delphi PE and verify two Ghidra metadata application passes."""
import argparse
import hashlib
import json
import sys
import types
from pathlib import Path
from tempfile import TemporaryDirectory


def snapshot(program):
    return {
        str(function.getEntryPoint()): {
            'name': str(function.getName(True)),
            'signature': str(function.getSignature()),
            'parameters': int(function.getParameterCount()),
        }
        for function in program.getFunctionManager().getFunctions(True)
    }


def check_tobject(program):
    functions = {str(f.getName(True)): f for f in program.getFunctionManager().getFunctions(True)}
    for method in ('Create', 'Free'):
        function = functions['System::TObject::' + method]
        assert function.getParameterCount() == 1
        parameter = function.getParameter(0)
        assert str(parameter.getName()) == 'Self'
        assert parameter.getDataType().getLength() == program.getDefaultPointerSize()
        assert 'TObject' in str(parameter.getDataType().getName())


def check_vtables(program):
    count = 0
    for datatype in program.getDataTypeManager().getAllDataTypes():
        if datatype.getName().startswith('VT_') and hasattr(datatype, 'getDefinedComponents'):
            for component in datatype.getDefinedComponents():
                assert component.getLength() == program.getDefaultPointerSize()
                assert component.getDataType().getLength() == program.getDefaultPointerSize()
                count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--ghidra', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--legacy', action='store_true')
    parser.add_argument('--minimum-labels', type=int, default=1)
    parser.add_argument('--disable-analyzer', action='append', default=[])
    parser.add_argument('--required-entry', action='append', default=[])
    args = parser.parse_args()

    import pyghidra
    pyghidra.start(install_dir=args.ghidra)
    from pyghidra.core import _setup_project, _analyze_program
    from pyghidra.api import transaction
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Program
    from ghidra.util.task import TaskMonitor

    source = Path(__file__).parents[1] / 'src/ghidra_scripts/DelphiReSym.py'
    with TemporaryDirectory() as location:
        project, program = _setup_project(args.binary, project_location=location)
        flat = FlatProgramAPI(program)
        if args.disable_analyzer:
            manager = AutoAnalysisManager.getAnalysisManager(program)
            manager.registerOptions()
            options = program.getOptions(Program.ANALYSIS_PROPERTIES)
            with transaction(program, 'Configure recorded analyzer overrides'):
                for analyzer in args.disable_analyzer:
                    assert options.contains(analyzer), analyzer
                    options.setBoolean(analyzer, False)
            manager.initializeOptions()
        _analyze_program(flat, program)
        print('Ghidra auto-analysis complete', flush=True)
        module = types.ModuleType('delphi_application_test')
        sys.modules[module.__name__] = module
        module.__dict__.update(
            currentProgram=program, monitor=TaskMonitor.DUMMY, toAddr=flat.toAddr,
            createFunction=flat.createFunction, createClass=flat.createClass,
            getFunctionAt=flat.getFunctionAt, disassemble=flat.disassemble,
        )
        source_text = source.read_text()
        source_sha256 = hashlib.sha256(source_text.encode()).hexdigest()
        exec(compile(source_text.rsplit('if pyghidra.started():', 1)[0], str(source), 'exec'), module.__dict__)
        module.VERBOSE_INFO = False
        assert module.prepare_data_type('UInt64').data_type.getLength() == 8
        original_apply = module.apply_symbols
        expected_names = {}

        def checked_apply(metadata, settings):
            expected_names.clear()
            for cls in metadata.entries.values():
                if cls.namespace:
                    for method in cls.method_entries.values():
                        if method.function_name:
                            expected_names[str(method.function_entry_point)] = method.function_name
            return original_apply(metadata, settings)

        module.apply_symbols = checked_apply
        original = snapshot(program)
        passes = []
        for iteration in range(2):
            print(f'Applying Delphi metadata, pass {iteration + 1}', flush=True)
            with transaction(program, 'Delphi recovery verification'):
                module.main()
            passes.append(snapshot(program))
        vt_components = check_vtables(program)
        if args.legacy:
            assert not expected_names, 'Legacy fixture unexpectedly supplied extended methods'
            assert passes[-1] == original, 'Unsupported metadata altered existing functions'
        else:
            check_tobject(program)
            assert vt_components > 0
            assert len(expected_names) >= args.minimum_labels
            assert original.keys() <= passes[-1].keys()
            for address in args.required_entry:
                assert address in expected_names, f"Missing required metadata entry: {address}"
            for address, name in expected_names.items():
                target = flat.toAddr(address)
                assert address in passes[-1], (
                    f'Missing recovered function: {address}; '
                    f'containing function={program.getFunctionManager().getFunctionContaining(target)}; '
                    f'code unit={program.getListing().getCodeUnitContaining(target)}'
                )
                assert passes[-1][address]['name'].endswith('::' + name), address
        result = {
            'binary': args.binary.name,
            'source_sha256': source_sha256,
            'disabled_analyzers': args.disable_analyzer,
            'legacy': args.legacy,
            'recovered_method_targets': len(expected_names),
            'verified_vt_components': vt_components,
            'first_functions': len(passes[0]),
            'second_functions': len(passes[1]),
            'changed_second_pass': sum(passes[0].get(k) != v for k, v in passes[1].items()),
            'functions': passes[1],
        }
        args.output.write_text(json.dumps(result, indent=2) + '\n')
        print({k: v for k, v in result.items() if k != 'functions'}, flush=True)


if __name__ == '__main__':
    main()
