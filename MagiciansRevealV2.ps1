<#
.SYNOPSIS
    MagiciansReveal v2.0 – Professional Minecraft Cheat Forensic Scanner
.DESCRIPTION
    Detects injectable clients, self-destructing cheats, residual artifacts,
    JVM injection and live process memory signatures (Meow-style detection).
.AUTHOR
    Tim Cheese
.VERSION
    4.0.0
#>

#region Init
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$script:Findings = @()
$script:ScanStart = Get-Date

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkYellow
    Write-Host "  ║                                                                          ║" -ForegroundColor DarkYellow
    Write-Host "  ║                      M A G I C I A N S   R E V E A L                     ║" -ForegroundColor Yellow
    Write-Host "  ║                                                                          ║" -ForegroundColor DarkYellow
    Write-Host "  ║              Professional Cheat Forensic Scanner  •  V2.0                ║" -ForegroundColor White
    Write-Host "  ║                                                                          ║" -ForegroundColor DarkYellow
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkYellow
    Write-Host ""
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "   $Title" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

function Add-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Details
    )
    $script:Findings += [PSCustomObject]@{
        Severity = $Severity
        Category = $Category
        Title    = $Title
        Details  = $Details
        Time     = Get-Date -Format "HH:mm:ss"
    }
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Magenta" }
        "MEDIUM"   { "Yellow" }
        "LOW"      { "DarkYellow" }
        default    { "Gray" }
    }
    Write-Host "  [$Severity] " -ForegroundColor $color -NoNewline
    Write-Host $Title -ForegroundColor White
    if ($Details) {
        Write-Host "           $Details" -ForegroundColor DarkGray
    }
    Write-Host ""
}
#endregion

#region Signatures
$cheatStrings = @(
    # High value client identifiers
    "VapeClient","VapeLite","vape.gg","MeteorClient","meteorclient","meteordevelopment",
    "LiquidBounce","liquidbounce","WurstClient","SigmaClient","Novoware","GameSense",
    "OsirisClient","CosmosClient","SorusClient","AzuraClient","DoomsdayClient",
    "ArgonClient","KryptonClient","PrestigeClient","198Macros","DeltaClient",
    "ElysianClient","OnyxClient","LuminaClient","RavenB","UZIClient","SkidBounce",
    "FutureClient","RusherHack","Aristois","Pandaware","Astolfo","IntentClient",
    "Novoclient","Hellion","VirginClient","XenonClient","GypsyClient","Dqrkis",
    "WalksyOptimizer","LWFH Crystal","catlean","AsteriaClient",

    # Combat / Crystal / Totem
    "AutoCrystal","AutoHitCrystal","CrystalAura","AimAssist","TriggerBot","SilentAim",
    "KillAura","AutoTotem","HoverTotem","InventoryTotem","AutoPot","ShieldBreaker",
    "ShieldDisabler","AutoAnchor","DoubleAnchor","SafeAnchor","AirAnchor","MaceSwap",
    "StunSlam","AutoDoubleHand","FakeLag","PingSpoof","WTap","FakePunch",

    # Self-destruct / evasion
    "SelfDestruct","selfdestruct","self destruct","HideClient","StringCleaner",
    "AntiSS","USN Journal Cleaner","Delete USN Journal","Replace Mod",

    # Generic high-signal
    "jnativehook","imgui.binding","LicenseCheckMixin","phantom-refmap.json",
    "client-refmap.json","cheat-refmap.json","org.chainlibs.module"
)

$cheatDomains = @(
    "vape.gg","vapeclient.com","meteorclient.com","liquidbounce.net","wurstclient.net",
    "sigmaclient.com","novoware.cc","gamesense.pw","osirisclient.com","prestigeclient.vip",
    "dqrkis.xyz","orchard.gg","intent.store","rise.today","riseclient.com"
)

$patternRegex = [regex]::new( ($cheatStrings | ForEach-Object { [regex]::Escape($_) }) -join "|", "IgnoreCase, Compiled")
#endregion

#region Win32 Memory API
$memCode = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

public class MemScanner {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    const int PROCESS_VM_READ = 0x0010;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_GUARD = 0x100;
    const uint PAGE_NOACCESS = 0x01;

    public static List<string> ScanProcess(int pid, string[] signatures) {
        var results = new List<string>();
        IntPtr hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return results;

        try {
            IntPtr address = IntPtr.Zero;
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            uint mbiSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

            while (VirtualQueryEx(hProcess, address, out mbi, mbiSize) != 0) {
                long regionSize = mbi.RegionSize.ToInt64();
                // Skip non-committed, guarded, noaccess, or huge regions
                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect & PAGE_GUARD) == 0 &&
                    (mbi.Protect & PAGE_NOACCESS) == 0 &&
                    regionSize > 0 && regionSize < 80 * 1024 * 1024) {

                    try {
                        byte[] buffer = new byte[regionSize];
                        int bytesRead;
                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, buffer.Length, out bytesRead) && bytesRead > 0) {
                            string text = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                            foreach (string sig in signatures) {
                                if (text.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0) {
                                    if (!results.Contains(sig)) results.Add(sig);
                                }
                            }
                        }
                    } catch {}
                }

                long next = mbi.BaseAddress.ToInt64() + regionSize;
                if (next <= 0) break;
                address = new IntPtr(next);
            }
        } finally {
            CloseHandle(hProcess);
        }
        return results;
    }
}
"@

try {
    Add-Type -TypeDefinition $memCode -Language CSharp -ErrorAction Stop
    $script:MemoryScannerAvailable = $true
} catch {
    $script:MemoryScannerAvailable = $false
}
#endregion

#region Scans
function Scan-Memory {
    Write-Section "LIVE MEMORY SCAN (Self-Destruct Detection)"

    if (-not $script:MemoryScannerAvailable) {
        Write-Host "  [!] Memory scanner failed to load. Run as Administrator." -ForegroundColor Red
        return
    }

    $procs = Get-Process -Name java,javaw -ErrorAction SilentlyContinue
    if (-not $procs) {
        Write-Host "  ✔  No Java processes found." -ForegroundColor Green
        return
    }

    $totalFound = 0
    foreach ($p in $procs) {
        Write-Host "  Scanning PID $($p.Id) ($($p.ProcessName)) ..." -ForegroundColor DarkGray
        try {
            $hits = [MemScanner]::ScanProcess($p.Id, $cheatStrings)
            if ($hits.Count -gt 0) {
                $totalFound++
                $sev = if ($hits.Count -ge 4) { "CRITICAL" } else { "HIGH" }
                Add-Finding -Severity $sev -Category "Memory" -Title "PID $($p.Id) — $($p.ProcessName)" `
                    -Details ("Detected: " + ($hits -join ", "))
            }
        } catch {
            Write-Host "    Could not read memory of PID $($p.Id)" -ForegroundColor DarkGray
        }
    }

    if ($totalFound -eq 0) {
        Write-Host "  ✔  No cheat signatures found in process memory." -ForegroundColor Green
    } else {
        Write-Host "  ⚠  $totalFound process(es) contained cheat signatures in memory." -ForegroundColor Red
    }
}

function Scan-DNS {
    Write-Section "DNS CACHE SCAN"

    try {
        $dns = ipconfig /displaydns 2>$null | Out-String
        $found = 0
        foreach ($domain in $cheatDomains) {
            if ($dns -match [regex]::Escape($domain)) {
                Add-Finding -Severity "HIGH" -Category "DNS" -Title $domain -Details "Cheat-related domain found in DNS cache"
                $found++
            }
        }
        if ($found -eq 0) {
            Write-Host "  ✔  No known cheat domains in DNS cache." -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Could not read DNS cache." -ForegroundColor Yellow
    }
}

function Scan-JVM {
    Write-Section "JVM COMMAND-LINE SCAN"

    $procs = Get-Process -Name java,javaw -ErrorAction SilentlyContinue
    if (-not $procs) {
        Write-Host "  ✔  No Java processes." -ForegroundColor Green
        return
    }

    $found = 0
    foreach ($p in $procs) {
        try {
            $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -EA SilentlyContinue).CommandLine
            if (-not $cmd) { continue }

            $hits = @()
            if ($cmd -match '-javaagent:') {
                $agents = [regex]::Matches($cmd, '-javaagent:(?:"([^"]+)"|(\S+))')
                foreach ($a in $agents) {
                    $name = [IO.Path]::GetFileName(($a.Groups[1].Value + $a.Groups[2].Value).Trim())
                    if ($name -notmatch 'jmxremote|yjp|jrebel|newrelic|jacoco|theseus') {
                        $hits += "Agent: $name"
                    }
                }
            }
            if ($cmd -match '-Xbootclasspath') { $hits += "Xbootclasspath" }
            if ($cmd -match '-agentlib:jdwp')  { $hits += "JDWP" }
            if ($cmd -match '-agentpath:')     { $hits += "agentpath" }

            if ($hits.Count -gt 0) {
                $found++
                Add-Finding -Severity "HIGH" -Category "JVM" -Title "PID $($p.Id)" -Details ($hits -join " | ")
            }
        } catch {}
    }
    if ($found -eq 0) {
        Write-Host "  ✔  No suspicious JVM flags." -ForegroundColor Green
    }
}

function Scan-Residual {
    Write-Section "RESIDUAL + USN JOURNAL SCAN"

    $paths = @(
        $env:TEMP,
        "$env:LOCALAPPDATA\Temp",
        "$env:WINDIR\Prefetch",
        "$env:APPDATA\.minecraft\logs",
        "$env:APPDATA\.minecraft\crash-reports",
        "$env:LOCALAPPDATA\CrashDumps"
    ) | Where-Object { Test-Path $_ }

    $found = 0
    $files = Get-ChildItem $paths -Recurse -Force -EA SilentlyContinue |
             Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -gt (Get-Date).AddDays(-14) -and $_.Length -lt 20MB }

    foreach ($f in $files) {
        foreach ($sig in $cheatStrings) {
            if ($f.Name -match [regex]::Escape($sig)) {
                Add-Finding -Severity "MEDIUM" -Category "Residual" -Title $f.Name -Details "Suspicious filename"
                $found++
                break
            }
        }
        if ($f.Length -lt 3MB -and $f.Extension -match '\.(log|txt|json|cfg|properties)$') {
            try {
                $content = Get-Content $f.FullName -Raw -EA SilentlyContinue
                if ($content) {
                    foreach ($s in $cheatStrings) {
                        if ($content -match [regex]::Escape($s)) {
                            Add-Finding -Severity "HIGH" -Category "Residual" -Title $f.Name -Details "Contains: $s"
                            $found++
                            break
                        }
                    }
                }
            } catch {}
        }
    }

    # Basic USN check
    try {
        $usn = fsutil usn readjournal C: 2>$null | Select-String "\.jar"
        foreach ($line in $usn) {
            if ($line -match 'File Name\s+:\s+(.+\.jar)') {
                $jn = $Matches[1].Trim()
                foreach ($sig in $cheatStrings) {
                    if ($jn -match [regex]::Escape($sig)) {
                        Add-Finding -Severity "HIGH" -Category "USN" -Title $jn -Details "Deleted/renamed JAR (possible self-destruct)"
                        $found++
                        break
                    }
                }
            }
        }
    } catch {}

    if ($found -eq 0) {
        Write-Host "  ✔  No residual / self-destruct traces found." -ForegroundColor Green
    } else {
        Write-Host "  ⚠  $found residual finding(s)." -ForegroundColor Red
    }
}

function Scan-Mods {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        Write-Host "  [!] Path not found." -ForegroundColor Red
        return
    }
    $jars = Get-ChildItem $Path -Filter *.jar -EA SilentlyContinue
    if ($jars.Count -eq 0) {
        Write-Host "  [!] No JARs found." -ForegroundColor Yellow
        return
    }

    Write-Section "MOD FOLDER SCAN — $($jars.Count) files"

    $flagged = 0
    $i = 0
    foreach ($jar in $jars) {
        $i++
        Write-Progress -Activity "Scanning mods" -Status $jar.Name -PercentComplete (($i / $jars.Count)*100)

        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -EA SilentlyContinue
            $zip = [IO.Compression.ZipFile]::OpenRead($jar.FullName)
            $hits = [System.Collections.Generic.HashSet[string]]::new()

            foreach ($e in $zip.Entries) {
                if ($e.FullName -match '\.(class|json)$' -or $e.FullName -match 'MANIFEST') {
                    try {
                        $ms = New-Object IO.MemoryStream
                        $e.Open().CopyTo($ms)
                        $bytes = $ms.ToArray()
                        $ms.Dispose()
                        $text = [Text.Encoding]::ASCII.GetString($bytes)
                        foreach ($s in $cheatStrings) {
                            if ($text.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                [void]$hits.Add($s)
                            }
                        }
                    } catch {}
                }
            }
            $zip.Dispose()

            if ($hits.Count -gt 0) {
                $flagged++
                $sev = if ($hits.Count -ge 4) { "CRITICAL" } else { "HIGH" }
                Add-Finding -Severity $sev -Category "Mod" -Title $jar.Name -Details ("Detected: " + ($hits -join ", "))
            }
        } catch {}
    }
    Write-Progress -Activity "Scanning mods" -Completed

    if ($flagged -eq 0) {
        Write-Host "  ✔  No threats found in mods folder." -ForegroundColor Green
    } else {
        Write-Host "  ⚠  $flagged suspicious mod(s) found." -ForegroundColor Red
    }
}
#endregion

#region Menu
function Show-Menu {
    Write-Host ""
    Write-Host "  1.  Scan Mods Folder" -ForegroundColor Green
    Write-Host "  2.  Scan Live Memory          (self-destruct detection)" -ForegroundColor Red
    Write-Host "  3.  Scan DNS Cache" -ForegroundColor Yellow
    Write-Host "  4.  Scan JVM Flags" -ForegroundColor Cyan
    Write-Host "  5.  Scan Residual + USN" -ForegroundColor DarkYellow
    Write-Host "  6.  Full Investigation" -ForegroundColor Magenta
    Write-Host "  7.  Export Report" -ForegroundColor White
    Write-Host "  8.  View Findings" -ForegroundColor Gray
    Write-Host "  9.  Exit" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Banner

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "  [!]  WARNING: Not running as Administrator." -ForegroundColor Red
    Write-Host "       Memory scanning and USN journal will be limited or fail." -ForegroundColor Red
    Write-Host ""
}

do {
    Show-Menu
    $c = Read-Host "  Choice"

    switch ($c) {
        "1" {
            Write-Banner
            $p = Read-Host "  Mods folder path (Enter = default)"
            if ([string]::IsNullOrWhiteSpace($p)) { $p = "$env:APPDATA\.minecraft\mods" }
            Scan-Mods $p
            Read-Host "`n  Press Enter"
            Write-Banner
        }
        "2" {
            Write-Banner
            Scan-Memory
            Read-Host "`n  Press Enter"
            Write-Banner
        }
        "3" {
            Write-Banner
            Scan-DNS
            Read-Host "`n  Press Enter"
            Write-Banner
        }
        "4" {
            Write-Banner
            Scan-JVM
            Read-Host "`n  Press Enter"
            Write-Banner
        }
        "5" {
            Write-Banner
            Scan-Residual
            Read-Host "`n  Press Enter"
            Write-Banner
        }
        "6" {
            Write-Banner
            $p = Read-Host "  Mods folder path (Enter = default)"
            if ([string]::IsNullOrWhiteSpace($p)) { $p = "$env:APPDATA\.minecraft\mods" }
            Scan-Mods $p
            Scan-Memory
            Scan-DNS
            Scan-JVM
            Scan-Residual
            Write-Host ""
            Write-Host "  ════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "  FULL INVESTIGATION COMPLETE" -ForegroundColor White
            Write-Host "  ════════════════════════════════════════════════" -ForegroundColor Red
            Read-Host "`n  Press Enter"
            Write-Banner
        }
        "7" {
            if ($script:Findings.Count -eq 0) {
                Write-Host "  No findings to export." -ForegroundColor Yellow
            } else {
                $name = "MagiciansReveal_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                $script:Findings | ConvertTo-Json -Depth 5 | Out-File "$name.json" -Encoding utf8
                $txt = "Magicians Reveal V2.0 Report`n" + ("="*55) + "`n`n"
                foreach ($f in $script:Findings) {
                    $txt += "[$($f.Severity)] $($f.Title)`n  $($f.Details)`n`n"
                }
                $txt | Out-File "$name.txt" -Encoding utf8
                Write-Host "  Saved: $name.json + $name.txt" -ForegroundColor Green
            }
            Read-Host "`n  Press Enter"
            Write-Banner
        }
        "8" {
            Write-Banner
            if ($script:Findings.Count -eq 0) {
                Write-Host "  No findings." -ForegroundColor Yellow
            } else {
                Write-Section "FINDINGS ($($script:Findings.Count))"
                foreach ($f in $script:Findings) {
                    $col = switch ($f.Severity) {
                        "CRITICAL" { "Red" }
                        "HIGH"     { "Magenta" }
                        "MEDIUM"   { "Yellow" }
                        default    { "DarkYellow" }
                    }
                    Write-Host "  [$($f.Severity)] " -ForegroundColor $col -NoNewline
                    Write-Host $f.Title -ForegroundColor White
                    Write-Host "           $($f.Details)" -ForegroundColor DarkGray
                    Write-Host ""
                }
            }
            Read-Host "  Press Enter"
            Write-Banner
        }
        "9" {
            Write-Host "`n  Exiting...`n" -ForegroundColor DarkGray
            exit
        }
        default {
            Write-Host "  Invalid choice." -ForegroundColor Red
            Start-Sleep -Milliseconds 500
            Write-Banner
        }
    }
} while ($true)
#endregion
