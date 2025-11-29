# DelphiReSym – A Delphi Symbol Name Recovery Tool for Reverse Engineers

_DelphiReSym_ is a reverse engineering utility that reconstructs **fully qualified Delphi symbol names** from after-compilation metadata embedded in Delphi executables. This includes function names, return types, parameter types, and parameter names. The tool also automatically creates VT structures into Ghidra's Data Type Manager, which get filled with recovered inherited functions and virtual functions for any recovered virtual method table.

_DelphiReSym_ is designed for use with **Ghidra** (via `pyghidra`) and aims to ease the reverse engineering process of Delphi malware and legacy applications by restoring as much human-readable semantic context from metadata as possible.

<img width="1263" height="603" alt="DelphiReSym_before_after" src="https://github.com/user-attachments/assets/5c972cd5-0aa0-49ea-bdbc-57c942100b5a" />


## 🛠️ How to run

1. **Start Ghidra with `pyghidra`**:
   Run Ghidra using the pyghidra-specific launcher from $GHIDRA_HOME:

   * On Windows:
     `.\support\pyghidraRun.bat`
   * On Linux/macOS:
     `./support/pyghidraRun`

2. **Import the binary you want to analyse and open it in Ghidra's CodeBrowser** (🐉 button).

3. **(Optional)**: Let Ghidra complete its **Auto Analysis**.
   The tool has been tested post-analysis without issues. Executing it pre-auto-analysis though has a negative effect on the accuracy of statistics which _DelphiReSym_ prints upon successful execution (but not on the reversing logic).

4. **Load the script**:

   * Download the script from this repo's [releases](https://github.com/WenzWenzWenz/DelphiReSym/releases) *(or the main branch, but that one might not be stable)*.
   * Go to **Window > Script Manager** (green play button).
   * Click the **"Manage Script Directories"** button (the button which looks like an itemize symbol).
   * Add the folder containing the downloaded `DelphiReSym.py` via the green plus icon.
   * Close the bundle manager.

5. **Run the tool (twice)**:

   * Locate the script "DelphiReSym.py" in the Script Manager list (bundled in the "Delphi" directory).
   * Click it, then press the **green play button** ("Run Script").
   * If the imported binary is supported, a progress bar and status messages will appear in the Ghidra console.
   * _**⚠️ FOR NOW, RUN THE TOOL TWICE IN A ROW TO GET BEST RESULTS ⚠️**_


## 💻 Requirements

* [Ghidra](https://github.com/NationalSecurityAgency/ghidra) (version **11.3 or newer**, for bundled `pyghidra` support)
* A working **Python 3 interpreter**
* [`pyghidra`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_11.3_build/Ghidra/Configurations/Public_Release/src/global/docs/WhatsNew.md#pyghidra) must be properly configured and used to run the script



## ✅ Supported Delphi versions

_DelphiReSym_ supports the following Delphi versions, which share compatible metadata formats:

* Delphi 2009 *(not sure if this version is supported -> couldn't be tested due to lack of 2009 binaries)*
* Delphi 2010
* Delphi XE
* Delphi XE2
* Delphi XE3
* Delphi XE4
* Delphi XE5
* Delphi XE6
* Delphi XE7
* Delphi XE8
* Delphi 10 Seattle
* Delphi 10.1 Berlin
* Delphi 10.2 Tokyo
* Delphi 10.3 Rio
* Delphi 10.4 Sydney
* Delphi 11 Alexandria
* Delphi 12 Athens

Versions beyond Delphi 12 **may** work, **provided** they retain the same compiler metadata format.

> With Delphi 13 Florence released, I aim to dig into its file format soon.



## 🧪 How to find out if my Delphi executable version is supported?

You can try using the [DIE (Detect It Easy)](https://github.com/horsicq/Detect-It-Easy) tool to get a rough guess of the Delphi version. However, the most reliable approach is to **simply run the tool** – if the version is unsupported, it will fail immediately, before any changes are made to your Ghidra project.



## ⚙️ Why is my Delphi version not supported?

Certain Delphi versions use **incompatible metadata formats**, which are not yet supported by this tool.
The visual timeline illustrates the assumed format divergences, under the assumption that Delphi 2009 is not supported. Sections marked **red** and **yellow** in that timeline are unsupported and might have a more fine-grained format change history.
![alt text](https://github.com/WenzWenzWenz/ghidra_scripts/blob/main/timeline.png) "Figure 1.: Overview of the various changes in Delphi's file format aligned to its historical timeline.")

For an in-depth explanation of Delphi's executable format evolution, refer to my [academic work](https://github.com/WenzWenzWenz/DelphiReSym/blob/main/Academic_work_v2.pdf).



## 📈 Evaluation

On real-world Delphi malware samples (of supported versions), the tool achieved the following recovery rates:

* **Function names & return types**:
  Between **31.56%** and **54.23%** successfully reconstructed.

* **Parameter sets** (complete lists of `(name, type)` tuples for each function):
  Between **27.31%** and **47.80%** reconstructed.
  *Note*: The actual accuracy for total parameter **tuples** is higher, since each function may have multiple parameters.



## ⚠️ Limitations, warnings & known bugs:
* The tool only works on **unpacked** Delphi binaries. Packed binaries will most likely not contain accessible metadata. Use a service like [UnpacMe by OALabs](https://www.unpac.me/) if needed.
* The tool makes use of Ghidra-API's replacement conflict handler. This means that if a user has created data types etc. before the tool's execution, those with conflicting names may be forcefully overwritten! 
* If you encounter problems when displaying template names, refer to [this issue](https://github.com/WenzWenzWenz/DelphiReSym/issues/2): Ghidra's decompilation and disassembly views only display template names of up to 10 characters by default. However, changing it within the settings solves the problem.



## 📝 Roadmap

- [ ] Increase coverage of Delphi versions:
   - [ ] Finish format analysis. Initial format analysis for Delphi versions *Delphi 2* through *Delphi 2006* has been conducted (hopefully works for *Delphi 2007* as well).
   - [ ] Evaluate practical efficacy for old samples of Malware families.
- [ ] Analyse the file format of new Delphi version 13.
- [ ] Integrate logging functionality for errors and make error handling prettier. Maybe auto detect Delphi versions.
- [ ] Use Ghidra's Function ID feature -> create Ghidra signatures (e.g. for omni-present 64bit Delphi functions)
- [ ] Integrate Ghidra [headless mode](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md)
- [ ] QoL feature: If the tool detects code that Ghidra has not yet detected as such, envoke disassembler ourselves.
- [X] Implement recursive descent parser for Delphi templates
- [X] New feature: replace typecasts with actual RTTI datatype structures (credit goes to [@huettenhain](https://github.com/huettenhain)!)



## 📌 Disclaimer

This is a research tool and work in progress. While it can significantly assist reverse engineering tasks, it may yield yet unknown errors. Contributions and feedback are welcome!
