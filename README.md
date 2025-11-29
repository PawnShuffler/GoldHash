# GoldHash

GoldHash is a Windows file integrity baseline and comparison tool built in PowerShell. It allows you to generate cryptographic hashes for files in a directory, create a baseline, and later compare your current files against that baseline to detect modifications, missing files, or unknown files.

GoldHash supports multiple output formats (JSON, CSV, HTML) and provides a clean, color-coded HTML report for easy analysis.

## Usecase

A SOC team suspects that a machine has been infected with malware. They are unsure which files have been modified and whether a threat actor has established a backdoor by altering system files. A SOC analyst can use GoldHash to compare the current file integrity against a baseline, preferably generated from a well-maintained company "golden image" of the Windows endpoint. This allows the team to quickly identify modified, missing, or unknown files, and take appropriate remediation steps.
GoldHash can be used as a lightweight method to detect unexpected file modifications, which can indicate malicious activity on endpoints before or during the attack.

## Features

- **Baseline Mode** - Compute and save SHA256 hashes for all files in a directory.
- **Compare Mode** - Compare current files against a baseline to detect:
  - `CORRECT` - file unchanged
  - `SUSPICIOUS` - file modified
  - `MISSING` - file missing
  - `UNKNOWN` - new/untracked file
- **Multiple Output Formats** - JSON, CSV, HTML
- **HTML Reports** - Color-coded status, sortable columns, user-friendly
- **Metadata Block** - Stores machine, username, OS, scan path, hash algorithm, and timestamp
- **Verbose Mode** - Optional detailed console output

## Installation

1. Clone this repository:

```powershell
git clone https://github.com/PawnShuffler/GoldHash.git
```
2. Open PowerShell.
3. Navigate to the folder containing ```GoldHash.ps1.```

## Usage
GoldHash supports two modes: **Baseline** and **Compare**.

### Baseline mode
Generates a baseline hash file for a target directory.
```powershell
.\GoldHash.ps1 -Mode Baseline -Path "C:\TargetFolder" -OutputType json -VerboseMode
```
- **Options:**
  - `-Mode Baseline` - runs in baseline mode
  - `-Path` - target folder to scan
  - `-OutputType` - optional, default json (```json```, ```csv```, ```html```)
  - `-Output` - optional path to save the file. If omitted, creates a timestamped file in script folder
  - `-VerboseMode` - optional, prints detailed info in console

 ### Compare mode
Compares files on the machine against an existing baseline.
```powershell
.\GoldHash.ps1 -Mode Compare -Path "C:\TargetFolder" -BaselineFile "C:\baseline.json" -OutputType html
```
- **Options:**
  - `-Mode Compare` - runs in compare mode
  - `-Path` - target folder to scan
  - `-BaselineFile` - path to the previously generated baseline file
  - `-OutputType` - optional, default json (```json```, ```csv```, ```html```)
  - `-Output` - optional path to save the file. If omitted, creates a timestamped file in script folder
  - `-VerboseMode` - optional, prints detailed info in console
 
 - HTML reports include
   - Sortable columns -> click to sort
   - Color-coded status

## Example
Generate a baseline of System32 in JSON format on your golden image of Windows endpoint
```powershell
.\GoldHash.ps1 -Mode Baseline -Path "C:\Windows\System32"
```
Compare files on a potentially infected machine
```powershell
.\GoldHash.ps1 -Mode Compare -Path "C:\Windows\System32" -BaselineFile ".\baseline.json" -OutputType html -Output "D:\SOC\compare_report.html"
```

---

### Notes, Limitations and Disclaimers
 - GoldHash uses SHA256 for hashing.
 - The HTML report is fully sortable by clicking column headers.
 - GoldHash does not prevent file changes; it is purely a reporting tool.
 - Accuracy depends on the correctness of the baseline. If the baseline itself is compromised, the results may be misleading.
 - Tested on typical Windows environments, but unforeseen permission issues or extremely large directories may affect performance, multithreading is To-Do.
 - Use with caution in sensitive or production environments; always verify critical files separately.
 - Not designed to replace enterprise-grade endpoint integrity or monitoring solutions.

### Contributing
Contributions, improvements, and bug reports are welcome. 
The creator will maintain this project on a best-effort basis.
