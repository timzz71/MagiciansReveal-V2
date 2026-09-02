<#
.SYNOPSIS
    MagiciansReveal v2.2 – Ultimate Minecraft Cheat Forensic Scanner
.DESCRIPTION
    High-precision detection of injectable clients, self-destructing cheats, obfuscated mods,
    residual artifacts and JVM injection. Built for serious screenshare investigations.
.AUTHOR
    Tim Cheese
.VERSION
    2.2.0
#>

#region Initialisation
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$Banner = @"
 ███╗   ███╗ █████╗  ██████╗ ██╗ ██████╗██╗ █████╗ ███╗   ██╗███████╗
 ████╗ ████║██╔══██╗██╔════╝ ██║██╔════╝██║██╔══██╗████╗  ██║██╔════╝
 ██╔████╔██║███████║██║  ███╗██║██║     ██║███████║██╔██╗ ██║███████╗
 ██║╚██╔╝██║██╔══██║██║   ██║██║██║     ██║██╔══██║██║╚██╗██║╚════██║
 ██║ ╚═╝ ██║██║  ██║╚██████╔╝██║╚██████╗██║██║  ██║██║ ╚████║███████║
 ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝ ╚═════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝

 ██████╗ ███████╗██╗   ██╗███████╗ █████╗ ██╗     
 ██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██║     
 ██████╔╝█████╗  ██║   ██║█████╗  ███████║██║     
 ██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██║██║     
 ██║  ██║███████╗ ╚████╔╝ ███████╗██║  ██║███████╗
 ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝
"@

function Write-Banner {
    Clear-Host
    Write-Host $Banner -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "                    MAGICIANS REVEAL  v2.2" -ForegroundColor White
    Write-Host "              Ultimate Cheat Forensic Scanner" -ForegroundColor DarkGray
    Write-Host ("━" * 78) -ForegroundColor Red
    Write-Host ""
}

Write-Banner

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "  [!]  WARNING: Not running as Administrator — USN Journal & deep residual scan limited" -ForegroundColor Red
    Write-Host ""
}
#endregion

#region Helper Functions
function Add-Finding {
    param(
        [string]$Tier,
        [string]$Title,
        [string]$Message,
        [string[]]$Details = @(),
        [hashtable]$Evidence = @{}
    )

    $script:Findings += @{
        Tier      = $Tier
        Title     = $Title
        Message   = $Message
        Details   = $Details
        Evidence  = $Evidence
        Timestamp = (Get-Date).ToString("o")
    }

    $color = switch ($Tier) {
        "CRITICAL"   { "Red" }
        "Bypass"     { "Magenta" }
        "Suspicious" { "Yellow" }
        "Obfuscated" { "Cyan" }
        "JVM"        { "Red" }
        "Residual"   { "DarkYellow" }
        default      { "Gray" }
    }

    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $color
    Write-Host "  ║  [$Tier]  $Title" -ForegroundColor $color
    Write-Host "  ╟────────────────────────────────────────────────────────────────────────────╢" -ForegroundColor DarkGray
    Write-Host "  ║  $Message" -ForegroundColor White

    if ($Details.Count -gt 0) {
        Write-Host "  ║" -ForegroundColor DarkGray
        foreach ($d in $Details) {
            Write-Host "  ║    →  $d" -ForegroundColor Gray
        }
    }

    Write-Host "  ╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $color
}

function Write-ScanHeader {
    param([string]$Text)
    Write-Host ""
    Write-Host "  ▶  $Text" -ForegroundColor Cyan
    Write-Host ("  " + ("─" * 72)) -ForegroundColor DarkGray
}

function Write-ScanSummary {
    param([int]$Flagged, [int]$Total)
    Write-Host ""
    if ($Flagged -eq 0) {
        Write-Host "  ✔  CLEAN — No suspicious / injected mods detected  ($Total scanned)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠  $Flagged FLAGGED ITEM(S)  out of $Total scanned" -ForegroundColor Red
    }
    Write-Host ""
}
#endregion

#region Signature Databases
$cheatPatterns = @(
    "AimAssist","AutoCrystal","AutoHitCrystal","CrystalAura","TriggerBot","SilentAim",
    "Criticals","Reach","ReachHack","ShieldBreaker","ShieldDisabler","AxeSpam",
    "KillAura","BowAimbot","AutoCrit","AutoAnchor","AnchorTweaks","DoubleAnchor",
    "SafeAnchor","AirAnchor","AutoBed","BedAura","NoBounce","LWFH Crystal",
    "WalksyCrystalOptimizerMod","AutoTotem","HoverTotem","InventoryTotem","LegitTotem",
    "AutoPot","AutoArmor","AutoDoubleHand","PopSwitch","MaceSwap","StunSlam",
    "FlyHack","SpeedHack","BHop","AntiFall","NoKnockback","AntiKB","StepHack",
    "WaterWalk","NoSlow","JumpReset","SprintReset","NoJumpDelay","ElytraSpeed",
    "FakeLag","PingSpoof","FakeInv","WTap","FakeNick","PackSpoof","Antiknockback",
    "AutoGap","AutoPearl","AutoTPA","BlockESP","PlayerESP","XRayHack","Tracers",
    "Freecam","FakeItem","NewChunks","FastPlace","ChestSteal","AutoClicker",
    "AutoEat","AutoMine","AutoFirework","ElytraSwap","FastXP","AutoBridge",
    "AutoBreach","GrimBypass","VulcanBypass","MatrixBypass","AACBypass",
    "VerusDisabler","WatchdogBypass","PacketMine","PacketFly","SessionStealer",
    "TokenLogger","TokenGrabber","KeyLogger","RemoteAccess","ReverseShell","Backdoor",
    "Asteria","Prestige","Xenon","Argon","Hellion","Virgin","Donut","VapeClient",
    "MeteorClient","LiquidBounce","RusherHack","FutureClient","Aristois","Pandaware",
    "AstolfoClient","Novoclient","IntentClient","org.chainlibs.module.impl.modules",
    "LicenseCheckMixin","ClientPlayerInteractionManagerAccessor","phantom-refmap.json",
    "client-refmap.json","cheat-refmap.json","jnativehook","imgui.binding","imgui.gl3","imgui.glfw"
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

$obfuscatorSignatures = @(
    "Skidfuscator","Paramorphism","Radon","Caesium","Bozar","Branchlock",
    "Binscure","SuperBlaubeere27","Qprotect","Zelix","Stringer","JNIC","Scuti","Smoke"
)

# High-signal only (reduced false positives)
$bypassPatterns = @(
    "runtime\.exec","-javaagent:","-Xbootclasspath","-agentlib:jdwp","-agentpath:",
    "URL\.openStream","HttpURLConnection","setRequestProperty"
)
#endregion

#region Core Analysis
function Get-FileSHA1 {
    param([string]$Path)
    try {
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $stream = [System.IO.File]::OpenRead($Path)
        $hash = $sha1.ComputeHash($stream)
        $stream.Close()
        return ([System.BitConverter]::ToString($hash) -replace '-','')
    } catch { return $null }
}

function Check-Modrinth {
    param([string]$Hash)
    try {
        $resp = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$Hash" -TimeoutSec 4 -ErrorAction Stop
        if ($resp -and $resp.project_id) {
            return @{ Verified = $true; Source = "Modrinth" }
        }
    } catch {}
    return $null
}

function Analyze-JAR {
    param([string]$FilePath)

    $hash = Get-FileSHA1 -Path $FilePath
    $verified = $null
    if ($hash) { $verified = Check-Modrinth -Hash $hash }

    $patterns   = [System.Collections.Generic.HashSet[string]]::new()
    $strings    = [System.Collections.Generic.HashSet[string]]::new()
    $fullwidth  = [System.Collections.Generic.HashSet[string]]::new()
    $bypass     = @()
    $obfuscationScore = 0
    $totalClasses = 0
    $singleLetter = 0
    $numeric = 0
    $unicode = 0
    $fullwidthCount = 0
    $japanese = 0
    $gibberish = 0
    $confusion = 0

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName

            foreach ($m in $patternRegex.Matches($name)) { [void]$patterns.Add($m.Value) }
            foreach ($bp in $bypassPatterns) { if ($name -match $bp) { $bypass += $bp } }

            if ($name -match '\.class$') {
                $totalClasses++
                $base = [System.IO.Path]::GetFileNameWithoutExtension($name)
                if ($base -match '^[A-Za-z]$') { $singleLetter++ }
                if ($base -match '^[0-9]+$') { $numeric++ }
                if ($base -match '[^\x00-\x7F]') { $unicode++ }
                if ($base -match "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]") { $fullwidthCount++ }
                if ($base -match '[\u3040-\u30FF\u4E00-\u9FAF]') { $japanese++ }
                if ($base -match '^[bcdfghjklmnpqrstvwxyz]+$' -and $base.Length -gt 3) { $gibberish++ }
                if ($base -match '^[O0Il1_]{2,}$') { $confusion++ }
            }

            if ($name -match '\.(class|json)$' -or $name -match 'MANIFEST\.MF') {
                try {
                    $stream = $entry.Open()
                    $ms = New-Object System.IO.MemoryStream
                    $stream.CopyTo($ms)
                    $stream.Close()
                    $bytes = $ms.ToArray()
                    $ms.Dispose()

                    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
                    $utf8  = [System.Text.Encoding]::UTF8.GetString($bytes)

                    foreach ($m in $patternRegex.Matches($ascii)) { [void]$patterns.Add($m.Value) }
                    foreach ($s in $cheatStrings) {
                        if ($ascii.Contains($s) -or $utf8.Contains($s)) { [void]$strings.Add($s) }
                    }
                    foreach ($m in $fullwidthRegex.Matches($utf8)) { [void]$fullwidth.Add($m.Value) }
                    foreach ($bp in $bypassPatterns) {
                        if ($ascii -match $bp -or $utf8 -match $bp) { $bypass += $bp }
                    }
                } catch {}
            }

            if ($name -match '\.jar$' -and $name -notmatch '^META-INF/') {
                $bypass += "NestedJAR"
            }
        }
        $archive.Dispose()
    } catch { return $null }

    if ($totalClasses -gt 0) {
        if (($singleLetter / $totalClasses) -gt 0.5) { $obfuscationScore += 2 }
        if (($numeric / $totalClasses) -gt 0.3)      { $obfuscationScore += 2 }
        if (($unicode / $totalClasses) -gt 0.2)      { $obfuscationScore += 3 }
        if (($fullwidthCount / $totalClasses) -gt 0.2){ $obfuscationScore += 3 }
        if (($japanese / $totalClasses) -gt 0.1)     { $obfuscationScore += 4 }
        if (($gibberish / $totalClasses) -gt 0.3)    { $obfuscationScore += 2 }
        if (($confusion / $totalClasses) -gt 0.2)    { $obfuscationScore += 2 }

        foreach ($sig in $obfuscatorSignatures) {
            if ($name -match $sig) { $obfuscationScore += 5; break }
        }
    }

    return @{
        Hash             = $hash
        Verified         = $verified
        Patterns         = $patterns
        Strings          = $strings
        Fullwidth        = $fullwidth
        BypassIndicators = $bypass
        ObfuscationScore = $obfuscationScore
        NestedJAR        = ($bypass -contains "NestedJAR")
    }
}
#endregion

#region Scan Functions
function Scan-Mods {
    param([string]$ModsPath)

    if (-not (Test-Path $ModsPath)) {
        Write-Host "  [!] Path not found: $ModsPath" -ForegroundColor Red
        return
    }

    $jars = Get-ChildItem -Path $ModsPath -Filter *.jar -ErrorAction SilentlyContinue
    if ($jars.Count -eq 0) {
        Write-Host "  [!] No JAR files found." -ForegroundColor Yellow
        return
    }

    Write-ScanHeader "Scanning $($jars.Count) mods — showing only flagged findings + detected strings"

    $flagged = 0
    $total = $jars.Count
    $i = 0

    foreach ($jar in $jars) {
        $i++
        Write-Progress -Activity "Deep analyzing JARs" -Status $jar.Name -PercentComplete (($i / $total) * 100)

        $result = Analyze-JAR -FilePath $jar.FullName
        if (-not $result) { continue }
        if ($result.Verified) { continue }   # skip clean verified mods

        $hasPatterns  = $result.Patterns.Count -gt 0
        $hasStrings   = $result.Strings.Count -gt 0
        $hasFullwidth = $result.Fullwidth.Count -gt 0
        $hasBypass    = $result.BypassIndicators.Count -gt 0 -or $result.NestedJAR
        $hasObfuscation = $result.ObfuscationScore -ge 5

        if (-not ($hasPatterns -or $hasStrings -or $hasFullwidth -or $hasBypass -or $hasObfuscation)) {
            continue
        }

        $flagged++
        $details = @()

        if ($hasStrings) {
            $details += "CHEAT STRINGS : $($result.Strings -join ', ')"
        }
        if ($hasPatterns) {
            $details += "PATTERNS      : $($result.Patterns -join ', ')"
        }
        if ($hasFullwidth) {
            $details += "FULLWIDTH     : $($result.Fullwidth -join ', ')"
        }
        if ($hasBypass) {
            $details += "BYPASS / INJECT: $($result.BypassIndicators -join ', ')"
            if ($result.NestedJAR) { $details += "NESTED JAR DETECTED" }
        }
        if ($hasObfuscation) {
            $details += "OBFUSCATION SCORE: $($result.ObfuscationScore)"
        }

        $tier = "Suspicious"
        if ($hasBypass -or $hasObfuscation) { $tier = "Bypass" }
        if ($hasStrings -and ($hasBypass -or $hasObfuscation)) { $tier = "CRITICAL" }

        Add-Finding -Tier $tier -Title $jar.Name -Message "Flagged mod detected" -Details $details `
            -Evidence @{
                File     = $jar.Name
                Strings  = $result.Strings
                Patterns = $result.Patterns
                Bypass   = $result.BypassIndicators
            }
    }

    Write-Progress -Activity "Deep analyzing JARs" -Completed
    Write-ScanSummary -Flagged $flagged -Total $total
}

function Scan-JVMInjection {
    Write-ScanHeader "Scanning live Java processes for injection"

    $java = Get-Process -Name java,javaw -ErrorAction SilentlyContinue
    if (-not $java) {
        Write-Host "  ✔  No Java processes running." -ForegroundColor Green
        return
    }

    $found = 0
    foreach ($p in $java) {
        try {
            $ci = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue
            $cmd = [string]$ci.CommandLine
            if (-not $cmd) { continue }

            $issues = @()
            if ($cmd -match '-javaagent:') {
                $agents = [regex]::Matches($cmd, '-javaagent:(?:"([^"]+)"|([^\s]+))')
                foreach ($ag in $agents) {
                    $path = if ($ag.Groups[1].Success) { $ag.Groups[1].Value } else { $ag.Groups[2].Value }
                    $name = [System.IO.Path]::GetFileName($path)
                    if ($name -notmatch 'jmxremote|yjp|jrebel|newrelic|jacoco|theseus') {
                        $issues += "Agent: $name"
                    }
                }
            }
            if ($cmd -match '-Xbootclasspath/p:') { $issues += "Xbootclasspath/p (prepend)" }
            if ($cmd -match '-Xbootclasspath/a:') { $issues += "Xbootclasspath/a (append)" }
            if ($cmd -match '-agentlib:jdwp')     { $issues += "JDWP debug agent" }
            if ($cmd -match '-agentpath:')        { $issues += "Native agentpath" }

            if ($issues.Count -gt 0) {
                Add-Finding -Tier "JVM" -Title "JVM Injection Detected" `
                    -Message "PID $($p.Id)" -Details $issues
                $found++
            }
        } catch {}
    }

    if ($found -eq 0) {
        Write-Host "  ✔  No JVM injection flags found." -ForegroundColor Green
    }
}

function Scan-ResidualArtifacts {
    Write-ScanHeader "Scanning residual artifacts + self-destruct traces"

    $roots = @(
        "$env:TEMP",
        "$env:USERPROFILE\AppData\Local\Temp",
        "$env:windir\Prefetch",
        "$env:USERPROFILE\AppData\Roaming\.minecraft\logs",
        "$env:USERPROFILE\AppData\Roaming\.minecraft\crash-reports",
        "$env:USERPROFILE\AppData\Local\CrashDumps",
        "$env:USERPROFILE\AppData\Roaming\.minecraft"
    ) | Where-Object { Test-Path $_ -PathType Container }

    $files = foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                -not $_.PSIsContainer -and
                $_.LastWriteTime -ge (Get-Date).AddDays(-14) -and
                $_.Length -le 25MB
            }
    }

    $found = 0

    foreach ($file in ($files | Sort-Object FullName -Unique)) {
        $content = $null
        try {
            if ($file.Length -lt 3MB -and $file.Extension -match '\.(log|txt|json|cfg|properties|xml|yml|yaml)$') {
                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
            }
        } catch {}

        if ($content) {
            foreach ($s in $cheatStrings) {
                if ($content -match [regex]::Escape($s)) {
                    Add-Finding -Tier "Residual" -Title "Cheat String in Residual File" `
                        -Message $file.FullName -Details @("String: $s")
                    $found++
                    break
                }
            }
        }

        foreach ($sig in $cheatPatterns) {
            if ($file.Name -match [regex]::Escape($sig)) {
                Add-Finding -Tier "Residual" -Title "Suspicious Residual Filename" `
                    -Message $file.Name -Details @("Signature: $sig")
                $found++
                break
            }
        }
    }

    # USN Journal
    try {
        $usn = fsutil usn readjournal C: 2>$null | Select-String -Pattern "File Name.*\.jar" -Context 2,0
        if ($usn) {
            foreach ($line in $usn) {
                $fileName = ($line -split "File Name\s+:\s+")[1].Trim()
                if ($fileName -match '\.jar$') {
                    foreach ($sig in $cheatPatterns) {
                        if ($fileName -match [regex]::Escape($sig)) {
                            Add-Finding -Tier "Residual" -Title "Self-Destruct Trace (USN Journal)" `
                                -Message $fileName -Details @("Signature: $sig")
                            $found++
                            break
                        }
                    }
                }
            }
        }
    } catch {}

    if ($found -eq 0) {
        Write-Host "  ✔  No residual / self-destruct traces found." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "  ⚠  $found residual / self-destruct finding(s)" -ForegroundColor Red
    }
}
#endregion

#region Menu
$script:Findings = @()
$script:ScanStart = Get-Date

function Show-Menu {
    Write-Host ""
    Write-Host "  1.  Scan mod folder          (only flagged + strings)" -ForegroundColor Green
    Write-Host "  2.  Scan JVM injection       (live processes)" -ForegroundColor Yellow
    Write-Host "  3.  Scan residual artifacts  (self-destruct)" -ForegroundColor Cyan
    Write-Host "  4.  Full Scan                (everything)" -ForegroundColor Magenta
    Write-Host "  5.  Export report            (JSON + TXT)" -ForegroundColor White
    Write-Host "  6.  View current findings" -ForegroundColor Gray
    Write-Host "  7.  Clear findings" -ForegroundColor DarkYellow
    Write-Host "  8.  Exit" -ForegroundColor DarkGray
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "  Enter choice"

    switch ($choice) {
        "1" {
            Write-Banner
            $path = Read-Host "  Enter full path to mods folder (or press Enter for default)"
            if ([string]::IsNullOrWhiteSpace($path)) {
                $path = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
            }
            Scan-Mods -ModsPath $path
            Read-Host "  Press Enter to continue"
            Write-Banner
        }
        "2" {
            Write-Banner
            Scan-JVMInjection
            Read-Host "  Press Enter to continue"
            Write-Banner
        }
        "3" {
            Write-Banner
            Scan-ResidualArtifacts
            Read-Host "  Press Enter to continue"
            Write-Banner
        }
        "4" {
            Write-Banner
            $path = Read-Host "  Enter mods folder path (or Enter for default)"
            if ([string]::IsNullOrWhiteSpace($path)) {
                $path = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
            }
            Scan-Mods -ModsPath $path
            Scan-JVMInjection
            Scan-ResidualArtifacts
            Write-Host ""
            Write-Host "  ════════════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "  FULL SCAN COMPLETE" -ForegroundColor White
            Write-Host "  ════════════════════════════════════════════════════════════════" -ForegroundColor Red
            Read-Host "  Press Enter to continue"
            Write-Banner
        }
        "5" {
            if ($script:Findings.Count -eq 0) {
                Write-Host "  No findings to export." -ForegroundColor Yellow
            } else {
                $report = @{
                    ScanTime = $script:ScanStart.ToString("o")
                    Findings = $script:Findings
                }
                $json = $report | ConvertTo-Json -Depth 6
                $jsonFile = "MagiciansReveal_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                $json | Out-File -FilePath $jsonFile -Encoding utf8
                Write-Host "  ✔  JSON → $jsonFile" -ForegroundColor Green

                $txt = "MagiciansReveal v2.2 Forensic Report`n" + ("=" * 60) + "`n"
                $txt += "Scan Time: $($report.ScanTime)`n`n"
                foreach ($f in $script:Findings) {
                    $txt += "[$($f.Tier)] $($f.Title)`n  $($f.Message)`n"
                    foreach ($d in $f.Details) { $txt += "    → $d`n" }
                    $txt += "`n"
                }
                $txtFile = "MagiciansReveal_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                $txt | Out-File -FilePath $txtFile -Encoding utf8
                Write-Host "  ✔  TXT  → $txtFile" -ForegroundColor Green
            }
            Read-Host "  Press Enter to continue"
            Write-Banner
        }
        "6" {
            Write-Banner
            if ($script:Findings.Count -eq 0) {
                Write-Host "  No findings." -ForegroundColor Yellow
            } else {
                Write-Host "  ── Current Findings ($($script:Findings.Count)) ──" -ForegroundColor Cyan
                foreach ($f in $script:Findings) {
                    $color = switch ($f.Tier) {
                        "CRITICAL"   { "Red" }
                        "Bypass"     { "Magenta" }
                        "Suspicious" { "Yellow" }
                        "Obfuscated" { "Cyan" }
                        "JVM"        { "Red" }
                        "Residual"   { "DarkYellow" }
                        default      { "Gray" }
                    }
                    Write-Host ""
                    Write-Host "  [$($f.Tier)] $($f.Title)" -ForegroundColor $color
                    Write-Host "    $($f.Message)" -ForegroundColor White
                    foreach ($d in $f.Details) {
                        Write-Host "      → $d" -ForegroundColor Gray
                    }
                }
            }
            Read-Host "  Press Enter to continue"
            Write-Banner
        }
        "7" {
            $script:Findings = @()
            Write-Host "  ✔  Findings cleared." -ForegroundColor Green
            Start-Sleep -Milliseconds 700
            Write-Banner
        }
        "8" {
            Write-Host ""
            Write-Host "  Exiting Magicians Reveal..." -ForegroundColor DarkGray
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
