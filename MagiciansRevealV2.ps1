<#
.SYNOPSIS
    MagiciansReveal v3.0 – Professional Minecraft Cheat Forensic Scanner
.DESCRIPTION
    High-precision detection of injectable clients, self-destructing cheats,
    obfuscated mods, residual artifacts and JVM injection.
.AUTHOR
    Tim Cheese
.VERSION
    3.0.0
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
    Write-Host "  ║                     Professional Cheat Forensic Scanner                  ║" -ForegroundColor White
    Write-Host "  ║                                    v2.0                                  ║" -ForegroundColor DarkGray
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
        [string]$Severity,   # CRITICAL / HIGH / MEDIUM / LOW
        [string]$Category,
        [string]$Title,
        [string]$Details
    )

    $script:Findings += [PSCustomObject]@{
        Severity  = $Severity
        Category  = $Category
        Title     = $Title
        Details   = $Details
        Time      = Get-Date -Format "HH:mm:ss"
    }

    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Magenta" }
        "MEDIUM"   { "Yellow" }
        "LOW"      { "DarkYellow" }
        default    { "Gray" }
    }

    Write-Host "  [$Severity] " -ForegroundColor $color -NoNewline
    Write-Host "$Title" -ForegroundColor White
    if ($Details) {
        Write-Host "           $Details" -ForegroundColor DarkGray
    }
    Write-Host ""
}
#endregion

#region Signatures
$cheatPatterns = @(
    "AimAssist","AutoCrystal","AutoHitCrystal","CrystalAura","TriggerBot","SilentAim",
    "Criticals","ReachHack","ShieldBreaker","ShieldDisabler","AxeSpam","KillAura",
    "BowAimbot","AutoCrit","AutoAnchor","DoubleAnchor","SafeAnchor","AirAnchor",
    "AutoBed","BedAura","NoBounce","LWFH Crystal","WalksyCrystalOptimizerMod",
    "AutoTotem","HoverTotem","InventoryTotem","LegitTotem","AutoPot","AutoArmor",
    "AutoDoubleHand","PopSwitch","MaceSwap","StunSlam","FlyHack","SpeedHack","BHop",
    "AntiFall","NoKnockback","AntiKB","StepHack","WaterWalk","NoSlow","JumpReset",
    "SprintReset","NoJumpDelay","ElytraSpeed","FakeLag","PingSpoof","FakeInv","WTap",
    "FakeNick","PackSpoof","Antiknockback","AutoGap","AutoPearl","AutoTPA",
    "BlockESP","PlayerESP","XRayHack","Tracers","Freecam","FakeItem","NewChunks",
    "FastPlace","ChestSteal","AutoClicker","AutoEat","AutoMine","AutoFirework",
    "ElytraSwap","FastXP","AutoBridge","AutoBreach","GrimBypass","VulcanBypass",
    "MatrixBypass","AACBypass","VerusDisabler","WatchdogBypass","PacketMine","PacketFly",
    "SessionStealer","TokenLogger","TokenGrabber","KeyLogger","RemoteAccess",
    "ReverseShell","Backdoor","Asteria","Prestige","Xenon","Argon","Hellion","Virgin",
    "Donut","VapeClient","MeteorClient","LiquidBounce","RusherHack","FutureClient",
    "Aristois","Pandaware","AstolfoClient","Novoclient","IntentClient",
    "org.chainlibs.module.impl.modules","LicenseCheckMixin",
    "ClientPlayerInteractionManagerAccessor","phantom-refmap.json",
    "client-refmap.json","cheat-refmap.json","jnativehook","imgui.binding"
)

$cheatStrings = @(
    "AutoCrystal","autocrystal","auto crystal","cw crystal","AutoHitCrystal",
    "AutoAnchor","autoanchor","auto anchor","DoubleAnchor","SafeAnchor","AirAnchor",
    "anchorMacro","AutoTotem","autototem","auto totem","InventoryTotem","HoverTotem",
    "hover totem","legittotem","AutoPot","autopot","auto pot","AutoArmor","autoarmor",
    "auto armor","AutoPotRefill","ShieldDisabler","ShieldBreaker",
    "Breaking shield with axe...","AutoDoubleHand","autodoublehand",
    "auto double hand","AutoClicker","AutoMace","MaceSwap","SpearSwap","StunSlam",
    "Donut","JumpReset","axespam","axe spam","AimAssist","aimassist","aim assist",
    "triggerbot","trigger bot","SilentRotations","FakeInv","FakeLag","pingspoof",
    "ping spoof","fakePunch","Fake Punch","mace_swap","quick_strike","macro_198",
    "stun_slam","safe_anchor","double_anchor","auto_pot_refill","walksy_optimizer",
    "key_pearl","aim_assist","auto_neth_pot","auto_dtap","trigger_bot","auto_web",
    "webmacro","web macro","AntiWeb","AutoWeb","lvstrng","dqrkis","selfdestruct",
    "self destruct","WalksyCrystalOptimizerMod","WalksyOptimizer","WalskyOptimizer",
    "autoCrystalPlaceClock","AutoFirework","ElytraSwap","FastXP","FastExp",
    "NoJumpDelay","PackSpoof","Antiknockback","catlean","AuthBypass",
    "obfuscatedAuth","LicenseCheckMixin","BaseFinder","invsee","ItemExploit",
    "FreezePlayer","LWFH Crystal","KeyPearl","LootYeeter","FastPlace","AutoBreach",
    "setBlockBreakingCooldown","getBlockBreakingCooldown","blockBreakingCooldown",
    "onBlockBreaking","setItemUseCooldown","invokeDoAttack","invokeDoItemUse",
    "invokeOnMouseButton","onPushOutOfBlocks","onIsGlowing",
    "Automatically switches to sword when hitting with totem","arrayOfString",
    "POT_CHEATS","Dqrkis Client","Entity.isGlowing","Activate Key","Click Simulation",
    "On RMB","No Count Glitch","No Bounce","NoBounce","Place Delay","Break Delay",
    "Fast Mode","Place Chance","Break Chance","Stop On Kill","Damage Tick","damagetick",
    "Anti Weakness","Particle Chance","Trigger Key","Switch Delay","Totem Slot",
    "Silent Rotations","Smooth Rotations","Rotation Speed","Use Easing","Easing Strength",
    "While Use","Stop on Kill","Glowstone Delay","Glowstone Chance","Explode Delay",
    "Explode Chance","Explode Slot","Only Charge","Anchor Macro","Reach Distance",
    "Min Height","Min Fall Speed","Attack Delay","Breach Delay","Require Elytra",
    "Auto Switch Back","Check Line of Sight","Only When Falling","Require Crit",
    "Show Status Display","Stop On Crystal","Check Shield","On Pop","Predict Damage",
    "On Ground","Check Players","Predict Crystals","Check Aim","Check Items",
    "Activates Above","Blatant","Force Totem","Stay Open For","Auto Inventory Totem",
    "Only On Pop","Vertical Speed","Hover Totem","Swap Speed","Strict One-Tick",
    "Mace Priority","Min Totems","Min Pearls","Totem First","Drop Interval",
    "Random Pattern","Loot Yeeter","Horizontal Aim Speed","Vertical Aim Speed",
    "Include Head","Web Delay","Holding Web","Not When Affects Player","Hit Delay",
    "Require Hold Axe","Fake Punch","placeInterval","breakInterval","stopOnKill",
    "activateOnRightClick","holdCrystal","KillAura","ClickAura","MultiAura",
    "ForceField","LegitAura","AimBot","AutoAim","SilentAim","AimLock","HeadSnap",
    "CrystalAura","AnchorAura","AnchorFill","AnchorPlace","BedAura","AutoBed",
    "BedBomb","BedPlace","BowAimbot","BowSpam","AutoBow","AutoCrit","CritBypass",
    "AlwaysCrit","CriticalHit","ReachHack","ExtendReach","LongReach","HitboxExpand",
    "AntiKB","NoKnockback","GrimVelocity","GrimDisabler","VelocitySpoof","KBReduce",
    "OffhandTotem","TotemSwitch","AutoWeapon","AutoSword","AutoCity","Burrow",
    "SelfTrap","HoleFiller","AntiSurround","AntiBurrow","WTap","TargetStrafe",
    "AutoGap","AutoPearl","FlyHack","CreativeFlight","BoatFly","PacketFly","AirJump",
    "SpeedHack","BHop","BunnyHop","AntiFall","NoFallDamage","SafeFall","StepHack",
    "FastClimb","AutoStep","HighStep","WaterWalk","LiquidWalk","LavaWalk","NoSlow",
    "NoSlowdown","NoWeb","NoSoulSand","WallHack","ElytraSpeed","InstantElytra",
    "ScaffoldWalk","FastBridge","BuildHelper","AutoBridge","Nuker","NukerLegit",
    "InstantBreak","GhostHand","NoSwing","PlaceAssist","AirPlace","AutoPlace",
    "InstantPlace","PlayerESP","MobESP","ItemESP","StorageESP","ChestESP","Tracers",
    "NameTagsHack","XRayHack","OreFinder","CaveFinder","OreESP","NewChunks",
    "ChunkBorders","TunnelFinder","TargetHUD","ReachDisplay","DoubleClicker",
    "JitterClick","ButterflyClick","CPSBoost","ChestStealer","InvManager",
    "InvMovebypass","AutoSprint","AntiAFK","AutoRespawn","PopSwitch","FakeLatency",
    "FakePing","SpoofRotation","PositionSpoof","GameSpeed","SpeedTimer","GrimBypass",
    "VulcanBypass","MatrixBypass","AACBypass","VerusDisabler","IntaveBypass",
    "WatchdogBypass","PacketMine","PacketWalk","PacketSneak","PacketCancel",
    "PacketDupe","PacketSpam","SelfDestruct","HideClient","SessionStealer",
    "TokenLogger","TokenGrabber","DiscordToken","RemoteAccess","ReverseShell",
    "C2Server","Backdoor","KeyLogger","StashFinder","TrailFinder","imgui.binding",
    "JNativeHook","GlobalScreen","NativeKeyListener","client-refmap.json",
    "cheat-refmap.json","meteordevelopment","cc/novoline","com/alan/clients",
    "club/maxstats","wtf/moonlight","me/zeroeightsix/kami","net/ccbluex",
    "today/opai","net/minecraft/injection","org/chainlibs/module/impl/modules",
    "xyz/greaj","com/cheatbreaker","com/moonsworth","doomsdayclient",
    "DoomsdayClient","doomsday.jar","novaclient","api.novaclient.lol",
    "WalksyOptimizer","LWFH Crystal","vape.gg","vapeclient","VapeClient","VapeLite",
    "intent.store","IntentClient","rise.today","riseclient.com","meteor-client",
    "meteorclient","meteordevelopment.meteorclient","liquidbounce","fdp-client",
    "novoware","novoclient","aristois","impactclient","azura","pandaware","skilled",
    "moonClient","astolfo","futureClient","konas","rusherhack","inertia","exhibition",
    "dev.krypton","dev/krypton","skid.krypton","skid/krypton","VirginClient",
    "virgin client","catlean","CatleanClient","catlean client","ArgonClient",
    "argon client","Asteria","AsteriaClient","asteria client","Prestige",
    "PrestigeClient","prestige client","prestigeclient.vip","gypsy","GypsyClient",
    "gypsy client","Xenon","XenonClient","xenon client","GrimClient","grim client",
    "phantom-refmap.json","dqrkis.xyz","Dqrkis Client"
)

$patternRegex = [regex]::new(
    '(?<![A-Za-z])(' + ($cheatPatterns -join '|') + ')(?![A-Za-z])',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$fullwidthRegex = [regex]::new(
    "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{3,}",
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$obfuscators = @("Skidfuscator","Paramorphism","Radon","Caesium","Bozar","Branchlock","Binscure","Qprotect","Zelix","Stringer","JNIC","Scuti","Smoke")

# Only real injection indicators
$injectionIndicators = @(
    "-javaagent:",
    "-Xbootclasspath",
    "-agentlib:jdwp",
    "-agentpath:",
    "runtime.exec",
    "ProcessBuilder"
)
#endregion

#region Core
function Get-SHA1 {
    param([string]$Path)
    try {
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $fs = [System.IO.File]::OpenRead($Path)
        $hash = $sha1.ComputeHash($fs)
        $fs.Close()
        return ([BitConverter]::ToString($hash) -replace '-','')
    } catch { return $null }
}

function Test-Modrinth {
    param([string]$Hash)
    try {
        $r = Invoke-RestMethod "https://api.modrinth.com/v2/version_file/$Hash" -TimeoutSec 4 -ErrorAction Stop
        if ($r.project_id) { return $true }
    } catch {}
    return $false
}

function Analyze-JAR {
    param([string]$Path)

    $hash = Get-SHA1 $Path
    $isVerified = $false
    if ($hash) { $isVerified = Test-Modrinth $hash }

    $foundPatterns  = [System.Collections.Generic.HashSet[string]]::new()
    $foundStrings   = [System.Collections.Generic.HashSet[string]]::new()
    $foundFullwidth = [System.Collections.Generic.HashSet[string]]::new()
    $injectionHits  = @()
    $obfScore       = 0
    $classCount     = 0
    $badNames       = 0

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        foreach ($e in $zip.Entries) {
            $name = $e.FullName

            # Pattern match on filename
            foreach ($m in $patternRegex.Matches($name)) {
                [void]$foundPatterns.Add($m.Value)
            }

            # Class name analysis
            if ($name -match '\.class$') {
                $classCount++
                $base = [IO.Path]::GetFileNameWithoutExtension($name)
                if ($base -match '^[a-z]$' -or $base -match '^[0-9]+$' -or $base -match '[^\x00-\x7F]' -or $base -match '^[O0Il1_]{2,}$') {
                    $badNames++
                }
            }

            # Content scan
            if ($name -match '\.(class|json)$' -or $name -match 'MANIFEST\.MF') {
                try {
                    $stream = $e.Open()
                    $ms = New-Object IO.MemoryStream
                    $stream.CopyTo($ms)
                    $stream.Close()
                    $bytes = $ms.ToArray()
                    $ms.Dispose()

                    $text = [Text.Encoding]::UTF8.GetString($bytes)
                    $ascii = [Text.Encoding]::ASCII.GetString($bytes)

                    foreach ($m in $patternRegex.Matches($ascii)) { [void]$foundPatterns.Add($m.Value) }
                    foreach ($s in $cheatStrings) {
                        if ($ascii.Contains($s) -or $text.Contains($s)) { [void]$foundStrings.Add($s) }
                    }
                    foreach ($m in $fullwidthRegex.Matches($text)) { [void]$foundFullwidth.Add($m.Value) }

                    foreach ($ind in $injectionIndicators) {
                        if ($ascii -match [regex]::Escape($ind) -or $text -match [regex]::Escape($ind)) {
                            $injectionHits += $ind
                        }
                    }
                } catch {}
            }

            if ($name -match '\.jar$' -and $name -notmatch 'META-INF') {
                $injectionHits += "Nested JAR"
            }
        }
        $zip.Dispose()
    } catch { return $null }

    if ($classCount -gt 20 -and ($badNames / $classCount) -gt 0.35) {
        $obfScore = 6
    }
    foreach ($o in $obfuscators) {
        if ($name -match $o) { $obfScore += 5 }
    }

    return @{
        Verified     = $isVerified
        Patterns     = $foundPatterns
        Strings      = $foundStrings
        Fullwidth    = $foundFullwidth
        Injection    = $injectionHits
        Obfuscation  = $obfScore
    }
}
#endregion

#region Scans
function Scan-Mods {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Host "  [!] Path not found." -ForegroundColor Red
        return
    }

    $jars = Get-ChildItem $Path -Filter *.jar -ErrorAction SilentlyContinue
    if ($jars.Count -eq 0) {
        Write-Host "  [!] No JAR files found." -ForegroundColor Yellow
        return
    }

    Write-Section "MOD SCAN — $($jars.Count) files (only showing threats)"

    $flagged = 0
    $i = 0

    foreach ($jar in $jars) {
        $i++
        Write-Progress -Activity "Analyzing" -Status $jar.Name -PercentComplete (($i / $jars.Count) * 100)

        $r = Analyze-JAR $jar.FullName
        if (-not $r) { continue }
        if ($r.Verified) { continue }

        $hasThreat = $false
        $details = @()

        if ($r.Strings.Count -gt 0) {
            $details += "Strings: $($r.Strings -join ', ')"
            $hasThreat = $true
        }
        if ($r.Patterns.Count -gt 0) {
            $details += "Patterns: $($r.Patterns -join ', ')"
            $hasThreat = $true
        }
        if ($r.Fullwidth.Count -gt 0) {
            $details += "Fullwidth: $($r.Fullwidth -join ', ')"
            $hasThreat = $true
        }
        if ($r.Injection.Count -gt 0) {
            $details += "Injection: $($r.Injection -join ', ')"
            $hasThreat = $true
        }
        if ($r.Obfuscation -ge 5) {
            $details += "Obfuscation Score: $($r.Obfuscation)"
            $hasThreat = $true
        }

        if ($hasThreat) {
            $flagged++
            $sev = "MEDIUM"
            if ($r.Injection.Count -gt 0 -or $r.Obfuscation -ge 6) { $sev = "HIGH" }
            if ($r.Strings.Count -gt 3 -or ($r.Strings.Count -gt 0 -and $r.Injection.Count -gt 0)) { $sev = "CRITICAL" }

            Add-Finding -Severity $sev -Category "Mod" -Title $jar.Name -Details ($details -join "  |  ")
        }
    }

    Write-Progress -Activity "Analyzing" -Completed

    Write-Host ""
    if ($flagged -eq 0) {
        Write-Host "  ✔  No threats found in $i mods." -ForegroundColor Green
    } else {
        Write-Host "  ⚠  $flagged threat(s) found out of $i mods." -ForegroundColor Red
    }
}

function Scan-JVM {
    Write-Section "JVM INJECTION SCAN"

    $procs = Get-Process -Name java,javaw -ErrorAction SilentlyContinue
    if (-not $procs) {
        Write-Host "  ✔  No Java processes running." -ForegroundColor Green
        return
    }

    $found = 0
    foreach ($p in $procs) {
        try {
            $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction SilentlyContinue).CommandLine
            if (-not $cmd) { continue }

            $hits = @()
            if ($cmd -match '-javaagent:') {
                $agents = [regex]::Matches($cmd, '-javaagent:(?:"([^"]+)"|(\S+))')
                foreach ($a in $agents) {
                    $agentName = [IO.Path]::GetFileName( ($a.Groups[1].Value + $a.Groups[2].Value).Trim() )
                    if ($agentName -notmatch 'jmxremote|yjp|jrebel|newrelic|jacoco|theseus') {
                        $hits += "Agent → $agentName"
                    }
                }
            }
            if ($cmd -match '-Xbootclasspath') { $hits += "Xbootclasspath" }
            if ($cmd -match '-agentlib:jdwp')  { $hits += "JDWP" }
            if ($cmd -match '-agentpath:')     { $hits += "Native agentpath" }

            if ($hits.Count -gt 0) {
                $found++
                Add-Finding -Severity "HIGH" -Category "JVM" -Title "PID $($p.Id)" -Details ($hits -join "  |  ")
            }
        } catch {}
    }

    if ($found -eq 0) {
        Write-Host "  ✔  No JVM injection detected." -ForegroundColor Green
    }
}

function Scan-Residual {
    Write-Section "RESIDUAL + SELF-DESTRUCT SCAN"

    $paths = @(
        $env:TEMP,
        "$env:LOCALAPPDATA\Temp",
        "$env:WINDIR\Prefetch",
        "$env:APPDATA\.minecraft\logs",
        "$env:APPDATA\.minecraft\crash-reports",
        "$env:LOCALAPPDATA\CrashDumps"
    ) | Where-Object { Test-Path $_ }

    $found = 0
    $files = Get-ChildItem $paths -Recurse -Force -ErrorAction SilentlyContinue |
             Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -gt (Get-Date).AddDays(-10) -and $_.Length -lt 15MB }

    foreach ($f in $files) {
        # Filename match
        foreach ($sig in $cheatPatterns) {
            if ($f.Name -match [regex]::Escape($sig)) {
                Add-Finding -Severity "MEDIUM" -Category "Residual" -Title $f.Name -Details "Suspicious filename"
                $found++
                break
            }
        }

        # Content match (only small text files)
        if ($f.Length -lt 2MB -and $f.Extension -match '\.(log|txt|json|cfg|properties)$') {
            try {
                $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
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

    # USN Journal
    try {
        $usn = fsutil usn readjournal C: 2>$null | Select-String "\.jar"
        foreach ($line in $usn) {
            if ($line -match 'File Name\s+:\s+(.+\.jar)') {
                $jn = $Matches[1].Trim()
                foreach ($sig in $cheatPatterns) {
                    if ($jn -match [regex]::Escape($sig)) {
                        Add-Finding -Severity "HIGH" -Category "USN" -Title $jn -Details "Deleted/renamed JAR (self-destruct trace)"
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
        Write-Host "  ⚠  $found residual finding(s)." -ForegroundColor Red
    }
}
#endregion

#region Menu
function Show-Menu {
    Write-Host ""
    Write-Host "  1.  Scan Mods Folder          (threats only)" -ForegroundColor Green
    Write-Host "  2.  Scan JVM Injection        (live)" -ForegroundColor Yellow
    Write-Host "  3.  Scan Residual Artifacts   (self-destruct)" -ForegroundColor Cyan
    Write-Host "  4.  Full Scan" -ForegroundColor Magenta
    Write-Host "  5.  Export Report" -ForegroundColor White
    Write-Host "  6.  View Findings" -ForegroundColor Gray
    Write-Host "  7.  Clear Findings" -ForegroundColor DarkYellow
    Write-Host "  8.  Exit" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Banner

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "  [!] Run as Administrator for full residual + USN scan power." -ForegroundColor Red
}

do {
    Show-Menu
    $c = Read-Host "  Choice"

    switch ($c) {
        "1" {
            Write-Banner
            $p = Read-Host "  Mods folder path (Enter = default)"
            if ([string]::IsNullOrWhiteSpace($p)) {
                $p = "$env:APPDATA\.minecraft\mods"
            }
            Scan-Mods $p
            Read-Host "  Press Enter"
            Write-Banner
        }
        "2" {
            Write-Banner
            Scan-JVM
            Read-Host "  Press Enter"
            Write-Banner
        }
        "3" {
            Write-Banner
            Scan-Residual
            Read-Host "  Press Enter"
            Write-Banner
        }
        "4" {
            Write-Banner
            $p = Read-Host "  Mods folder path (Enter = default)"
            if ([string]::IsNullOrWhiteSpace($p)) {
                $p = "$env:APPDATA\.minecraft\mods"
            }
            Scan-Mods $p
            Scan-JVM
            Scan-Residual
            Write-Host ""
            Write-Host "  ════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "  FULL SCAN COMPLETE" -ForegroundColor White
            Write-Host "  ════════════════════════════════════════════" -ForegroundColor Red
            Read-Host "  Press Enter"
            Write-Banner
        }
        "5" {
            if ($script:Findings.Count -eq 0) {
                Write-Host "  No findings." -ForegroundColor Yellow
            } else {
                $json = $script:Findings | ConvertTo-Json -Depth 5
                $name = "MagiciansReveal_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                $json | Out-File "$name.json" -Encoding utf8
                Write-Host "  Saved → $name.json" -ForegroundColor Green

                $txt = "Magicians Reveal v3.0 Report`n" + ("="*50) + "`n`n"
                foreach ($f in $script:Findings) {
                    $txt += "[$($f.Severity)] $($f.Title)`n  $($f.Details)`n`n"
                }
                $txt | Out-File "$name.txt" -Encoding utf8
                Write-Host "  Saved → $name.txt" -ForegroundColor Green
            }
            Read-Host "  Press Enter"
            Write-Banner
        }
        "6" {
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
                    Write-Host "           $($f.Details)" -ForegroundColor DarkGray
                    Write-Host ""
                }
            }
            Read-Host "  Press Enter"
            Write-Banner
        }
        "7" {
            $script:Findings = @()
            Write-Host "  Findings cleared." -ForegroundColor Green
            Start-Sleep -Milliseconds 600
            Write-Banner
        }
        "8" {
            Write-Host ""
            Write-Host "  Exiting..." -ForegroundColor DarkGray
            exit
        }
        default {
            Write-Host "  Invalid." -ForegroundColor Red
            Start-Sleep -Milliseconds 400
            Write-Banner
        }
    }
} while ($true)
#endregion
