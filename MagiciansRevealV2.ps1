<#
.SYNOPSIS
    MagiciansReveal v5.0 – Professional Minecraft Cheat Forensic Scanner
.DESCRIPTION
    Stable high-signal detection of cheats, residual artifacts, self-destruct traces,
    DNS activity, JVM injection and suspicious mods.
.AUTHOR
    Tim Cheese
.VERSION
    5.0.0
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
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkYellow
    Write-Host "  ║                                                                      ║" -ForegroundColor DarkYellow
    Write-Host "  ║                   M A G I C I A N S   R E V E A L                    ║" -ForegroundColor Yellow
    Write-Host "  ║                                                                      ║" -ForegroundColor DarkYellow
    Write-Host "  ║                Professional Cheat Forensic Scanner                   ║" -ForegroundColor White
    Write-Host "  ║                              v5.0                                    ║" -ForegroundColor DarkGray
    Write-Host "  ║                                                                      ║" -ForegroundColor DarkYellow
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkYellow
    Write-Host ""
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "  ────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "   $Text" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

function Add-Finding {
    param(
        [ValidateSet("CRITICAL","HIGH","MEDIUM","LOW")]
        [string]$Severity,
        [string]$Title,
        [string]$Details = ""
    )

    $script:Findings += [PSCustomObject]@{
        Severity = $Severity
        Title    = $Title
        Details  = $Details
        Time     = Get-Date -Format "HH:mm:ss"
    }

    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Magenta" }
        "MEDIUM"   { "Yellow" }
        "LOW"      { "DarkYellow" }
    }

    Write-Host "  [$Severity] " -ForegroundColor $color -NoNewline
    Write-Host $Title -ForegroundColor White
    if ($Details) {
        Write-Host "           → $Details" -ForegroundColor DarkGray
    }
    Write-Host ""
}
#endregion

#region Signatures
$HighValueStrings = @(
    # Clients
    "VapeClient","VapeLite","vape.gg","MeteorClient","meteorclient","meteordevelopment",
    "LiquidBounce","WurstClient","SigmaClient","Novoware","GameSense","OsirisClient",
    "CosmosClient","AzuraClient","DoomsdayClient","ArgonClient","KryptonClient",
    "PrestigeClient","FutureClient","RusherHack","Aristois","Pandaware","Astolfo",
    "IntentClient","Novoclient","Hellion","VirginClient","XenonClient","GypsyClient",
    "Dqrkis","WalksyOptimizer","LWFH Crystal","catlean","AsteriaClient","198Macros",

    # Combat / Crystal / Totem
    "AutoCrystal","AutoHitCrystal","CrystalAura","AimAssist","TriggerBot","SilentAim",
    "KillAura","AutoTotem","HoverTotem","InventoryTotem","AutoPot","ShieldBreaker",
    "ShieldDisabler","AutoAnchor","DoubleAnchor","SafeAnchor","AirAnchor","MaceSwap",
    "StunSlam","AutoDoubleHand","FakeLag","PingSpoof","WTap","FakePunch",

    # Self-destruct / evasion
    "SelfDestruct","selfdestruct","self destruct","HideClient","StringCleaner",
    "AntiSS","USN Journal Cleaner","Delete USN Journal","Replace Mod",

    # Technical
    "jnativehook","imgui.binding","LicenseCheckMixin","phantom-refmap.json",
    "client-refmap.json","cheat-refmap.json","org.chainlibs.module"
)

$CheatDomains = @(
    "vape.gg","vapeclient.com","meteorclient.com","liquidbounce.net","wurstclient.net",
    "sigmaclient.com","novoware.cc","gamesense.pw","osirisclient.com","prestigeclient.vip",
    "dqrkis.xyz","orchard.gg","intent.store","rise.today","riseclient.com"
)
#endregion

#region Core Functions
function Scan-Mods {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Host "  [!] Path not found: $Path" -ForegroundColor Red
        return
    }

    $jars = @(Get-ChildItem -Path $Path -Filter "*.jar" -ErrorAction SilentlyContinue)
    if ($jars.Count -eq 0) {
        Write-Host "  [!] No JAR files found." -ForegroundColor Yellow
        return
    }

    Write-Section "MOD SCAN — $($jars.Count) files (threats only)"

    $flagged = 0
    $i = 0

    foreach ($jar in $jars) {
        $i++
        Write-Progress -Activity "Scanning mods" -Status $jar.Name -PercentComplete (($i / $jars.Count) * 100)

        $hits = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            $zip = [System.IO.Compression.ZipFile]::OpenRead($jar.FullName)

            foreach ($entry in $zip.Entries) {
                if ($entry.FullName -match '\.(class|json)$' -or $entry.FullName -match 'MANIFEST\.MF') {
                    try {
                        $stream = $entry.Open()
                        $ms = New-Object System.IO.MemoryStream
                        $stream.CopyTo($ms)
                        $stream.Close()
                        $bytes = $ms.ToArray()
                        $ms.Dispose()

                        $text = [System.Text.Encoding]::ASCII.GetString($bytes)

                        foreach ($s in $HighValueStrings) {
                            if ($text.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                [void]$hits.Add($s)
                            }
                        }
                    } catch {}
                }
            }
            $zip.Dispose()
        } catch {}

        if ($hits.Count -gt 0) {
            $flagged++
            $sev = if ($hits.Count -ge 4) { "CRITICAL" } elseif ($hits.Count -ge 2) { "HIGH" } else { "MEDIUM" }
            Add-Finding -Severity $sev -Title $jar.Name -Details ($hits -join ", ")
        }
    }

    Write-Progress -Activity "Scanning mods" -Completed

    Write-Host ""
    if ($flagged -eq 0) {
        Write-Host "  ✔  No threats found in mods folder." -ForegroundColor Green
    } else {
        Write-Host "  ⚠  $flagged suspicious mod(s) detected." -ForegroundColor Red
    }
}

function Scan-JVM {
    Write-Section "JVM INJECTION SCAN"

    $procs = Get-Process -Name "java","javaw" -ErrorAction SilentlyContinue
    if (-not $procs) {
        Write-Host "  ✔  No Java processes running." -ForegroundColor Green
        return
    }

    $found = 0
    foreach ($p in $procs) {
        try {
            $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue).CommandLine
            if (-not $cmd) { continue }

            $hits = @()

            if ($cmd -match '-javaagent:') {
                $matches = [regex]::Matches($cmd, '-javaagent:(?:"([^"]+)"|(\S+))')
                foreach ($m in $matches) {
                    $agentPath = ($m.Groups[1].Value + $m.Groups[2].Value).Trim()
                    $agentName = [System.IO.Path]::GetFileName($agentPath)
                    if ($agentName -notmatch 'jmxremote|yjp|jrebel|newrelic|jacoco|theseus') {
                        $hits += "Agent: $agentName"
                    }
                }
            }
            if ($cmd -match '-Xbootclasspath') { $hits += "Xbootclasspath" }
            if ($cmd -match '-agentlib:jdwp')  { $hits += "JDWP Debug" }
            if ($cmd -match '-agentpath:')     { $hits += "Native agentpath" }

            if ($hits.Count -gt 0) {
                $found++
                Add-Finding -Severity "HIGH" -Title "PID $($p.Id) ($($p.ProcessName))" -Details ($hits -join " | ")
            }
        } catch {}
    }

    if ($found -eq 0) {
        Write-Host "  ✔  No suspicious JVM flags detected." -ForegroundColor Green
    }
}

function Scan-DNS {
    Write-Section "DNS CACHE SCAN"

    try {
        $dnsOutput = ipconfig /displaydns 2>$null | Out-String
        $found = 0

        foreach ($domain in $CheatDomains) {
            if ($dnsOutput -match [regex]::Escape($domain)) {
                Add-Finding -Severity "HIGH" -Title $domain -Details "Cheat-related domain found in DNS cache"
                $found++
            }
        }

        if ($found -eq 0) {
            Write-Host "  ✔  No known cheat domains found in DNS cache." -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Failed to read DNS cache." -ForegroundColor Yellow
    }
}

function Scan-Residual {
    Write-Section "RESIDUAL + SELF-DESTRUCT SCAN"

    $searchPaths = @(
        $env:TEMP,
        "$env:LOCALAPPDATA\Temp",
        "$env:WINDIR\Prefetch",
        "$env:APPDATA\.minecraft\logs",
        "$env:APPDATA\.minecraft\crash-reports",
        "$env:LOCALAPPDATA\CrashDumps",
        "$env:APPDATA\.minecraft"
    ) | Where-Object { Test-Path $_ }

    $found = 0
    $cutoff = (Get-Date).AddDays(-14)

    $files = Get-ChildItem -Path $searchPaths -Recurse -Force -ErrorAction SilentlyContinue |
             Where-Object {
                 -not $_.PSIsContainer -and
                 $_.LastWriteTime -gt $cutoff -and
                 $_.Length -lt 25MB
             }

    foreach ($file in $files) {
        # Filename check
        foreach ($sig in $HighValueStrings) {
            if ($file.Name -match [regex]::Escape($sig)) {
                Add-Finding -Severity "MEDIUM" -Title $file.Name -Details "Suspicious residual filename"
                $found++
                break
            }
        }

        # Content check (text files only)
        if ($file.Length -lt 4MB -and $file.Extension -match '\.(log|txt|json|cfg|properties|xml|yml)$') {
            try {
                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    foreach ($sig in $HighValueStrings) {
                        if ($content -match [regex]::Escape($sig)) {
                            Add-Finding -Severity "HIGH" -Title $file.Name -Details "Contains signature: $sig"
                            $found++
                            break
                        }
                    }
                }
            } catch {}
        }
    }

    # Prefetch special check
    $prefetch = Get-ChildItem "$env:WINDIR\Prefetch" -ErrorAction SilentlyContinue
    if ($prefetch -and $prefetch.Count -lt 8) {
        Add-Finding -Severity "MEDIUM" -Title "Prefetch Anomaly" -Details "Very low prefetch count ($($prefetch.Count)) — possible cleaning"
        $found++
    }

    # Basic USN Journal
    try {
        $usnLines = fsutil usn readjournal C: 2>$null | Select-String -Pattern "\.jar"
        foreach ($line in $usnLines) {
            if ($line -match 'File Name\s+:\s+(.+\.jar)') {
                $jarName = $Matches[1].Trim()
                foreach ($sig in $HighValueStrings) {
                    if ($jarName -match [regex]::Escape($sig)) {
                        Add-Finding -Severity "HIGH" -Title $jarName -Details "USN Journal — deleted/renamed JAR (possible self-destruct)"
                        $found++
                        break
                    }
                }
            }
        }
    } catch {}

    if ($found -eq 0) {
        Write-Host "  ✔  No residual or self-destruct traces found." -ForegroundColor Green
    } else {
        Write-Host "  ⚠  $found residual finding(s) detected." -ForegroundColor Red
    }
}
#endregion

#region Menu
function Show-Menu {
    Write-Host ""
    Write-Host "  1.  Scan Mods Folder" -ForegroundColor Green
    Write-Host "  2.  Scan JVM Injection" -ForegroundColor Yellow
    Write-Host "  3.  Scan DNS Cache" -ForegroundColor Cyan
    Write-Host "  4.  Scan Residual + Self-Destruct" -ForegroundColor DarkYellow
    Write-Host "  5.  Full Investigation" -ForegroundColor Magenta
    Write-Host "  6.  Export Report" -ForegroundColor White
    Write-Host "  7.  View Findings" -ForegroundColor Gray
    Write-Host "  8.  Clear Findings" -ForegroundColor DarkGray
    Write-Host "  9.  Exit" -ForegroundColor DarkRed
    Write-Host ""
}

# Start
Write-Banner

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "  [!]  Not running as Administrator — residual & USN scan will be limited." -ForegroundColor Red
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "  Enter choice"

    switch ($choice) {
        "1" {
            Write-Banner
            $path = Read-Host "  Mods folder path (press Enter for default)"
            if ([string]::IsNullOrWhiteSpace($path)) {
                $path = "$env:APPDATA\.minecraft\mods"
            }
            Scan-Mods -Path $path
            Read-Host "`n  Press Enter to continue"
            Write-Banner
        }
        "2" {
            Write-Banner
            Scan-JVM
            Read-Host "`n  Press Enter to continue"
            Write-Banner
        }
        "3" {
            Write-Banner
            Scan-DNS
            Read-Host "`n  Press Enter to continue"
            Write-Banner
        }
        "4" {
            Write-Banner
            Scan-Residual
            Read-Host "`n  Press Enter to continue"
            Write-Banner
        }
        "5" {
            Write-Banner
            $path = Read-Host "  Mods folder path (press Enter for default)"
            if ([string]::IsNullOrWhiteSpace($path)) {
                $path = "$env:APPDATA\.minecraft\mods"
            }
            Scan-Mods -Path $path
            Scan-JVM
            Scan-DNS
            Scan-Residual
            Write-Host ""
            Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "  FULL INVESTIGATION COMPLETE" -ForegroundColor White
            Write-Host "  ══════════════════════════════════════════════════" -ForegroundColor Red
            Read-Host "`n  Press Enter to continue"
            Write-Banner
        }
        "6" {
            if ($script:Findings.Count -eq 0) {
                Write-Host "  No findings to export." -ForegroundColor Yellow
            } else {
                $base = "MagiciansReveal_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                $script:Findings | ConvertTo-Json -Depth 5 | Out-File "$base.json" -Encoding utf8

                $txt = "Magicians Reveal v5.0 Report`n" + ("=" * 50) + "`n`n"
                foreach ($f in $script:Findings) {
                    $txt += "[$($f.Severity)] $($f.Title)`n  $($f.Details)`n`n"
                }
                $txt | Out-File "$base.txt" -Encoding utf8

                Write-Host "  ✔  Saved: $base.json + $base.txt" -ForegroundColor Green
            }
            Read-Host "`n  Press Enter to continue"
            Write-Banner
        }
        "7" {
            Write-Banner
            if ($script:Findings.Count -eq 0) {
                Write-Host "  No findings." -ForegroundColor Yellow
            } else {
                Write-Section "CURRENT FINDINGS ($($script:Findings.Count))"
                foreach ($f in $script:Findings) {
                    $col = switch ($f.Severity) {
                        "CRITICAL" { "Red" }
                        "HIGH"     { "Magenta" }
                        "MEDIUM"   { "Yellow" }
                        default    { "DarkYellow" }
                    }
                    Write-Host "  [$($f.Severity)] " -ForegroundColor $col -NoNewline
                    Write-Host $f.Title -ForegroundColor White
                    if ($f.Details) {
                        Write-Host "           → $($f.Details)" -ForegroundColor DarkGray
                    }
                    Write-Host ""
                }
            }
            Read-Host "  Press Enter to continue"
            Write-Banner
        }
        "8" {
            $script:Findings = @()
            Write-Host "  ✔  Findings cleared." -ForegroundColor Green
            Start-Sleep -Milliseconds 700
            Write-Banner
        }
        "9" {
            Write-Host ""
            Write-Host "  Exiting Magicians Reveal..." -ForegroundColor DarkGray
            Write-Host ""
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
