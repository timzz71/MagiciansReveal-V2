# 🧙‍♂️ MagiciansReveal V2

### 🕵️ Minecraft Forensic Scanner

MagiciansReveal V2 is a local PowerShell forensic scanner for investigating Minecraft installations, Java processes, launcher data, logs, JAR files, DNS cache, registry traces, and other related artifacts.

> ⚠️ This tool provides forensic indicators. It cannot guarantee recovery of evidence that has been securely deleted, overwritten, encrypted, or removed from memory.

---

## 🚀 Quick Start

### 🌐 Run directly from GitHub

Open **PowerShell as Administrator** and run:

```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/timzz71/MagiciansReveal-V2/main/MagiciansRevealV2.ps1')"
```

Only run remote scripts from a repository you trust. Review the source before using it in a production or moderation environment.

### 💻 Run a local copy

```powershell
powershell -ExecutionPolicy Bypass -File ".\MagiciansRevealV2.ps1"
```

For the strongest results, start PowerShell as **Administrator** before launching the scanner.

---

## 📋 Menu Options

### `1` — Scan Minecraft Directory

Scans the selected `mods` directory and analyzes JAR filenames and contents for configured signatures, suspicious strings, and obfuscation indicators.

### `2` — Scan Full System

Checks:

- 🧩 Java and Javaw process metadata
- 🎮 Active Minecraft process detection
- 📁 Minecraft and launcher directories
- 📝 Logs, crash reports, JSON, XML, TXT, and configuration files
- 📦 Recent JAR files
- 🌐 DNS cache entries
- 🗃️ Registry traces
- 🕒 Prefetch and event-log health
- 🧹 Recent residual artifacts and suspicious filenames

The scan also records relevant paths and timestamps in the findings list.

### `3` — Export Report

Exports findings as:

- `MagiciansRevealV2_report_YYYYMMDD_HHMMSS.json`
- `MagiciansRevealV2_report_YYYYMMDD_HHMMSS.txt`

Reports are written to the current PowerShell directory.

### `4` — View Current Findings

Displays all findings collected during the current session.

### `5` — Clear All Findings

Clears findings from the current session only.

### `6` — Exit

Closes the scanner.

---

## 🎨 Finding Levels

🔴 **Detection** — A configured signature or strong forensic indicator was found.

🟡 **Warning** — A suspicious or incomplete indicator was found and requires review.

⚪ **Info** — Context such as process metadata or scan status.

Always review the evidence path and surrounding context before making a final decision. Generic strings can occur in legitimate tools or documentation.

---

## 🔐 Administrator Permissions

Administrator access is recommended because Windows may restrict access to:

- Other users’ processes
- Security and event logs
- Prefetch data
- Protected registry locations
- Launcher and temporary directories

If the scanner is not elevated, it displays a warning and continues with best-effort checks.

---

## ⚡ Recommended Workflow

1. Start the scanner before investigating the Minecraft session.
2. Run **Scan Minecraft Directory** with the correct `mods` path.
3. Run **Scan Full System** while Minecraft is open when possible.
4. Review findings and evidence paths.
5. Export JSON and TXT reports.
6. Preserve the reports and relevant files for review.

For historical investigations, preserve the machine state quickly. Self-destruct routines may remove files, overwrite memory, or clear traces before a later scan begins.

---

## 🛠️ Troubleshooting

### The remote command runs an old version

Confirm that the repository’s `MagiciansRevealV2.ps1` file has been committed and pushed. The remote command always downloads the current file from GitHub.

### Minecraft is not detected

Start Minecraft first, then run option `2`. The scanner looks for Java processes with Minecraft, Fabric, Forge, Quilt, LWJGL, launcher, or game-directory indicators.

### A directory is skipped

Run PowerShell as Administrator and verify that the path still exists. Some temporary files disappear while the scan is running.

### A finding is a false positive

Treat generic module names as indicators, not proof. Check the complete file path, timestamp, JAR contents, process command line, and other correlated findings.

---

## 🛡️ Privacy and Safety

- Analysis is performed locally by the PowerShell script.
- The scanner does not modify Minecraft files or process memory.
- Remote execution downloads and executes the script supplied by the GitHub URL.
- Use a pinned commit or a reviewed local copy for high-trust environments.
- Obtain appropriate authorization before scanning another person’s computer.

---

## 📄 License and Use

Use this tool only for authorized moderation, incident response, forensic analysis, or testing. Detection results should be reviewed by a qualified administrator before disciplinary action.

