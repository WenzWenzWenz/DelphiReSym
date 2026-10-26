# Recovery regression checks

These tests are added by the metadata-recovery patch; upstream main did not have a test suite.
Run the six Python regression cases without Ghidra:

```sh
python -m unittest discover -s tests -v
```

For full application, install PyGhidra, select a supported JDK, and run against a local Delphi PE with recoverable TObject metadata:

```sh
python tests/ghidra_application.py sample.exe --ghidra /path/to/ghidra_12.2_PUBLIC --output application.json
```

This imports and analyzes the PE in Ghidra, applies DelphiReSym twice inside database transactions,
and records resulting function names, namespaces, signatures and parameter counts. It also checks the
UInt64 width, defined VT pointer components and TObject.Create/Free Self parameters. It does not
execute the input PE. Inspect `changed_second_pass` to identify differences between applications;
a successful run alone does not establish semantic correctness for every recovered type.

The application assertions exercise selected known signatures and layout widths. They do not
provide source-level ground truth for every recovered method, ABI, runtime string layout or
compiler version. The runner retains the source hash in its output so results can be tied to
the exact script tested.

## GitHub Actions

Every pull request and push to `main` or a `fix/` branch runs the Python regressions
and seven real-binary jobs. The public corpus is pinned by archive and PE SHA-256
in `.github/ci/corpus.json`:

| Binary | Check |
| --- | --- |
| UPSPowerMTR (Delphi 7) | `CODE` discovery; unsupported extended metadata must not alter functions |
| Inno Setup 5.6.1 (Delphi 2009) | Small `CODE` stub; no false recovery |
| Inno Setup 6.2.2 (Rio), x86 | Named recovery and signature application |
| Inno Setup 7.1.0 (Athens), x86 and x64 | Named recovery, signatures and VT widths |
| HeidiSQL 12.10, x86 and x64 | Larger VCL metadata and generic names |

Each job analyzes its PE in Ghidra and applies recovery twice. Modern fixtures
must meet a recorded minimum number of distinct method targets; every extracted
named target must exist as a named Ghidra function. The test also checks known
`TObject` signatures, `UInt64`, and defined VT component widths. Legacy fixtures
must leave the original function records unchanged. Second-pass differences are
recorded because the tool currently recommends running twice.

Ghidra 12.2 and the downloaded binaries are verified before use. Python dependencies
are installed offline from wheels inside that verified Ghidra archive. The user-supplied
private binary is not downloaded or redistributed by CI. HeidiSQL x64 disables only
`Create Address Tables`, which exhausted a 6 GB heap in the audit; the result records
that override. Other jobs use default analysis.

The workflow uses GitHub-hosted runners, read-only repository permission, SHA-pinned
official actions, no persisted checkout credentials, no secrets and no shared caches.
It uses `pull_request`, never `pull_request_target`. Fork workflows may require a
maintainer's approval in GitHub before their first run. Diagnostics contain JSON and
logs, not executables, and expire after seven days. Dependabot checks action pins weekly.

Ghidra upgrades require updating the release URL and digest together and rerunning the
real corpus. These fixtures cover the listed behaviors; they do not establish complete
source-level accuracy for every Delphi compiler or ABI.
