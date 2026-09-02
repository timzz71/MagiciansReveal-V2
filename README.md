# 🧙‍♂️ Magicians Reveal V2.0

### 🕵️ Professional Minecraft Cheat Forensic Scanner

Magicians Reveal scans Minecraft mods, JAR contents, JVM injection indicators, obfuscation signals, residual artifacts, and USN Journal entries.

> ⚠️ Results are forensic indicators, not automatic proof. Deleted or overwritten evidence may no longer be recoverable.

## 🚀 Run from GitHub

Open **PowerShell as Administrator** and run:

```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/timzz71/MagiciansReveal-V2/main/MagiciansRevealV2.ps1')"
```

Review the remote script before executing it. The command downloads the current version published at that URL.

## 💻 Run locally

```powershell
powershell -ExecutionPolicy Bypass -File ".\MagiciansRevealV2.ps1"
```

Administrator privileges are recommended for residual and USN Journal access.

## 📋 Menu

### `1` — Scan Mods Folder 🧩

Scans the selected folder, or `%APPDATA%\.minecraft\mods`, for known patterns and strings, suspicious class names, fullwidth obfuscation, injection indicators, nested JARs, and obfuscation signals. JAR SHA-1 hashes are checked against Modrinth; verified files are excluded from threat findings.

### `2` — Scan JVM Injection ⚙️

Inspects active `java.exe` and `javaw.exe` command lines for `-javaagent:`, `-Xbootclasspath`, JDWP, and native `-agentpath:` injection. Known legitimate agents are excluded.

### `3` — Scan Residual Artifacts 🧹

Checks recent files in `%TEMP%`, `%LOCALAPPDATA%\Temp`, `%WINDIR%\Prefetch`, Minecraft logs/crash reports, and crash dumps. It checks suspicious filenames, text contents, recent JAR traces, and the C: drive USN Journal for suspicious deleted or renamed JAR names.

### `4` — Full Scan 🔍

Runs the mods, JVM injection, and residual artifact scans in sequence.

### `5` — Export Report 📄

Creates `MagiciansReveal_YYYYMMDD_HHMMSS.json` and `.txt` files in the current directory.

### `6` — View Findings 👁️

Displays the current session’s findings.

### `7` — Clear Findings 🗑️

Clears the in-memory findings list.

### `8` — Exit 🚪

Closes the scanner.

## 🎨 Severity Levels

🔴 **CRITICAL** — Multiple strong indicators or strings combined with injection evidence.

🟣 **HIGH** — JVM injection, suspicious residual content, or strong obfuscation evidence.

🟡 **MEDIUM** — Suspicious mod, filename, pattern, or artifact requiring review.

🟠 **LOW** — Lower-confidence contextual indicator.

## 🛠️ Requirements

- Windows PowerShell
- Minecraft data available on the machine
- Administrator privileges recommended
- Internet access for Modrinth hash verification
- C: drive USN Journal enabled for USN results

Analysis is local except for the optional Modrinth SHA-1 lookup performed by the script.

## ✅ Recommended Workflow

1. Start PowerShell as Administrator.
2. Run option `1` against the actual profile’s `mods` folder.
3. Run option `2` while Java/Minecraft is active.
4. Run option `3` for residual and self-destruct traces.
5. Use option `4` for the complete sequence.
6. Export reports with option `5`.

## ⚠️ Limitations

This V2.0 script does not read arbitrary Java process RAM. It cannot guarantee recovery if files, memory strings, or filesystem records have been erased or overwritten. USN Journal retention varies by system. Generic strings may also occur in legitimate software, so review paths, timestamps, and correlated evidence before taking action.

## 🔐 Authorized Use

Use Magicians Reveal only on systems and Minecraft installations you own or are authorized to investigate. Preserve exported reports and avoid modifying suspicious files before collection.

