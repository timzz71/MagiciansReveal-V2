<#
.SYNOPSIS
    MagiciansReveal v2.1 – Professional Minecraft Cheat Forensic Scanner
.DESCRIPTION
    Detects injectable cheats, self-destructing clients, obfuscated mods, and residual artifacts.
    Uses SHA-1 hash verification, 200+ signatures, bypass analysis, obfuscation scoring,
    JVM runtime inspection, and USN Journal/artifact scanning.
.AUTHOR
    Tim Cheese
.VERSION
    2.1.0
#>

#region Initialisation
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
Clear-Host

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
    Write-Host "                Magicians Reveal V2.1" -ForegroundColor White
    Write-Host "         Professional Cheat Forensic Scanner" -ForegroundColor DarkGray
    Write-Host ("━" * 76) -ForegroundColor Red
    Write-Host ""
}

Write-Banner

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    Write-Host "  [!] WARNING: Run as Administrator for full features (USN Journal + deep residual scan)" -ForegroundColor Red
    Write-Host ""
}
#endregion

#region Helper Functions
function Add-Finding {
    param(
        [string]$Tier,
        [string]$Category,
        [string]$Title,
        [string]$Message,
        [hashtable]$Evidence = @{}
    )

    $finding = @{
        Tier      = $Tier
        Category  = $Category
        Title     = $Title
        Message   = $Message
        Evidence  = $Evidence
        Timestamp = (Get-Date).ToString("o")
    }
    $script:Findings += $finding

    $color = switch ($Tier) {
        "Suspicious" { "Yellow" }
        "Bypass"     { "Magenta" }
        "Obfuscated" { "Cyan" }
        "JVM"        { "Red" }
        "Residual"   { "DarkYellow" }
        default      { "Gray" }
    }

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $color
    Write-Host "  ║  [$Tier] $Title" -ForegroundColor $color
    Write-Host "  ╟──────────────────────────────────────────────────────────────────────────╢" -ForegroundColor DarkGray
    Write-Host "  ║  $Message" -ForegroundColor White
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $color
}

function Write-ScanHeader {
    param([string]$Text)
    Write-Host ""
    Write-Host "  ▶ $Text" -ForegroundColor Cyan
    Write-Host ("  " + ("─" * 70)) -ForegroundColor DarkGray
}

function Write-ScanSummary {
    param([int]$Flagged, [int]$Total)

    Write-Host ""
    if ($Flagged -eq 0) {
        Write-Host "  ✔ Scan complete — No suspicious / injected mods found ($Total scanned)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Scan complete — $Flagged flagged item(s) out of $Total scanned" -ForegroundColor Red
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

# Only high-signal bypass indicators (reduced false positives)
$bypassPatterns = @(
    "runtime\.exec","ProcessBuilder","URL\.openStream","HttpURLConnection",
    "setRequestProperty","-javaagent:","-Xbootclasspath","-agentlib:jdwp","-agentpath:"
)
#endregion

#region Core Analysis Functions
function Get-FileSHA1 {
    param([string]$Path)
    try {
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $stream = [System.IO.File]::OpenRead($Path)
        $hash = $sha1.ComputeHash($stream)
        $stream.Close()
        return ([System.BitConverter]::ToString($hash) -replace '-','')
    } catch {
        return $null
    }
}

function Check-Modrinth {
    param([string]$Hash)
    try {
        $url = "https://api.modrinth.com/v2/version_file/$Hash"
        $resp = Invoke-RestMethod -Uri $url -TimeoutSec 4 -ErrorAction Stop
        if ($resp -and $resp.project_id) {
            return @{ Verified = $true; Source = "Modrinth"; Name = $resp.project_id }
        }
    } catch {}
    return $null
}

function Analyze-JAR {
    param([string]$FilePath)

    $hash = Get-FileSHA1 -Path $FilePath
    $verified = $null
    if ($hash) {
        $verified = Check-Modrinth -Hash $hash
    }

    $patterns = [System.Collections.Generic.HashSet[string]]::new()
    $strings  = [System.Collections.Generic.HashSet[string]]::new()
    $fullwidth = [System.Collections.Generic.HashSet[string]]::new()
    $bypassIndicators = @()
    $obfuscationScore = 0
    $totalClasses = 0
    $singleLetterClasses = 0
    $numericClasses = 0
    $unicodeClasses = 0
    $fullwidthClasses = 0
    $japaneseClasses = 0
    $gibberishClasses = 0
    $confusionClasses = 0

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName

            foreach ($m in $patternRegex.Matches($name)) {
                [void]$patterns.Add($m.Value)
            }

            foreach ($bp in $bypassPatterns) {
                if ($name -match $bp) {
                    $bypassIndicators += $bp
                }
            }

            if ($name -match '\.class$') {
                $totalClasses++
                $base = [System.IO.Path]::GetFileNameWithoutExtension($name)

                if ($base -match '^[A-Za-z]$') { $singleLetterClasses++ }
                if ($base -match '^[0-9]+$') { $numericClasses++ }
                if ($base -match '[^\x00-\x7F]') { $unicodeClasses++ }
                if ($base -match "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]") { $fullwidthClasses++ }
                if ($base -match '[\u3040-\u30FF\u4E00-\u9FAF]') { $japaneseClasses++ }
                if ($base -match '^[bcdfghjklmnpqrstvwxyz]+$' -and $base.Length -gt 3) { $gibberishClasses++ }
                if ($base -match '^[O0Il1_]{2,}$') { $confusionClasses++ }
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

                    foreach ($m in $patternRegex.Matches($ascii)) {
                        [void]$patterns.Add($m.Value)
                    }

                    foreach ($s in $cheatStrings) {
                        if ($ascii.Contains($s) -or $utf8.Contains($s)) {
                            [void]$strings.Add($s)
                        }
                    }

                    foreach ($m in $fullwidthRegex.Matches($utf8)) {
                        [void]$fullwidth.Add($m.Value)
                    }

                    foreach ($bp in $bypassPatterns) {
                        if ($ascii -match $bp -or $utf8 -match $bp) {
                            $bypassIndicators += $bp
                        }
                    }
                } catch {}
            }

            if ($name -match '\.jar$' -and $name -notmatch '^META-INF/') {
                $bypassIndicators += "NestedJAR"
            }
        }
        $archive.Dispose()
    } catch {
        return $null
    }

    if ($totalClasses -gt 0) {
        $singleLetterRatio = $singleLetterClasses / $totalClasses
        $numericRatio      = $numericClasses / $totalClasses
        $unicodeRatio      = $unicodeClasses / $totalClasses
        $fullwidthRatio    = $fullwidthClasses / $totalClasses
        $japaneseRatio     = $japaneseClasses / $totalClasses
        $gibberishRatio    = $gibberishClasses / $totalClasses
        $confusionRatio    = $confusionClasses / $totalClasses

        if ($singleLetterRatio -gt 0.5) { $obfuscationScore += 2 }
        if ($numericRatio -gt 0.3)      { $obfuscationScore += 2 }
        if ($unicodeRatio -gt 0.2)      { $obfuscationScore += 3 }
        if ($fullwidthRatio -gt 0.2)    { $obfuscationScore += 3 }
        if ($japaneseRatio -gt 0.1)     { $obfuscationScore += 4 }
        if ($gibberishRatio -gt 0.3)    { $obfuscationScore += 2 }
        if ($confusionRatio -gt 0.2)    { $obfuscationScore += 2 }

        foreach ($sig in $obfuscatorSignatures) {
            if ($name -match $sig) {
                $obfuscationScore += 5
                break
            }
        }
    }

    $fakeIdentity = ($name -match '(lithium|sodium|phosphor|canvas)\.jar') -and ($patterns.Count -gt 0 -or $strings.Count -gt 0)
    $nestedJAR = $bypassIndicators -contains "NestedJAR"

    return @{
        Hash              = $hash
        Verified          = $verified
        Patterns          = $patterns
        Strings           = $strings
        Fullwidth         = $fullwidth
        BypassIndicators  = $bypassIndicators
        ObfuscationScore  = $obfuscationScore
        SingleLetterRatio = if ($totalClasses -gt 0) { $singleLetterClasses / $totalClasses } else { 0 }
        NumericRatio      = if ($totalClasses -gt 0) { $numericClasses / $totalClasses } else { 0 }
        UnicodeRatio      = if ($totalClasses -gt 0) { $unicodeClasses / $totalClasses } else { 0 }
        FullwidthRatio    = if ($totalClasses -gt 0) { $fullwidthClasses / $totalClasses } else { 0 }
        JapaneseRatio     = if ($totalClasses -gt 0) { $japaneseClasses / $totalClasses } else { 0 }
        GibberishRatio    = if ($totalClasses -gt 0) { $gibberishClasses / $totalClasses } else { 0 }
        ConfusionRatio    = if ($totalClasses -gt 0) { $confusionClasses / $totalClasses } else { 0 }
        FakeIdentity      = $fakeIdentity
        NestedJAR         = $nestedJAR
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

    Write-ScanHeader "Scanning $($jars.Count) mods — only showing flagged / injected findings"

    $flagged = 0
    $total = $jars.Count
    $i = 0

    foreach ($jar in $jars) {
        $i++
        Write-Progress -Activity "Analyzing JARs" -Status $jar.Name -PercentComplete (($i / $total) * 100)

        $result = Analyze-JAR -FilePath $jar.FullName
        if (-not $result) { continue }

        # Skip clean / verified mods completely
        if ($result.Verified) { continue }

        $isFlagged = $false

        if ($result.BypassIndicators.Count -gt 0 -or $result.FakeIdentity -or $result.NestedJAR) {
            $extra = ""
            if ($result.FakeIdentity) { $extra += " (Fake identity)" }
            if ($result.NestedJAR)    { $extra += " (Nested JAR)" }

            Add-Finding -Tier "Bypass" -Category "File System" -Title "Bypass / Injection Detected" `
                -Message ("$($jar.Name)  →  " + ($result.BypassIndicators -join ', ') + $extra) `
                -Evidence @{File=$jar.Name; Bypass=$result.BypassIndicators}

            $isFlagged = $true
        }
        elseif ($result.ObfuscationScore -ge 5) {
            Add-Finding -Tier "Obfuscated" -Category "File System" -Title "Heavily Obfuscated Mod" `
                -Message "$($jar.Name)  →  Score $($result.ObfuscationScore) | Single-letter: $([math]::Round($result.SingleLetterRatio*100))% | Unicode: $([math]::Round($result.UnicodeRatio*100))%" `
                -Evidence @{File=$jar.Name; ObfuscationScore=$result.ObfuscationScore}

            $isFlagged = $true
        }
        elseif ($result.Patterns.Count -gt 0 -or $result.Strings.Count -gt 0 -or $result.Fullwidth.Count -gt 0) {
            $msgParts = @()
            if ($result.Patterns.Count -gt 0)  { $msgParts += "Patterns: $($result.Patterns -join ', ')" }
            if ($result.Strings.Count -gt 0)   { $msgParts += "Strings: $($result.Strings -join ', ')" }
            if ($result.Fullwidth.Count -gt 0) { $msgParts += "Fullwidth: $($result.Fullwidth -join ', ')" }

            Add-Finding -Tier "Suspicious" -Category "File System" -Title "Cheat-Related Content" `
                -Message ("$($jar.Name)  →  " + ($msgParts -join ' | ')) `
                -Evidence @{File=$jar.Name; Patterns=$result.Patterns; Strings=$result.Strings}

            $isFlagged = $true
        }

        if ($isFlagged) { $flagged++ }
    }

    Write-Progress -Activity "Analyzing JARs" -Completed
    Write-ScanSummary -Flagged $flagged -Total $total
}

function Scan-JVMInjection {
    Write-ScanHeader "Scanning live Java / JVM processes for injection"

    $java = Get-Process -Name java,javaw -ErrorAction SilentlyContinue
    if (-not $java) {
        Write-Host "  ✔ No Java processes running." -ForegroundColor Green
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
                Add-Finding -Tier "JVM" -Category "Runtime Injection" -Title "JVM Injection Detected" `
                    -Message ("PID $($p.Id)  →  " + ($issues -join ' | ')) `
                    -Evidence @{PID=$p.Id; Flags=$issues}
                $found++
            }
        } catch {}
    }

    if ($found -eq 0) {
        Write-Host "  ✔ No JVM injection flags found." -ForegroundColor Green
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
                $_.Length -le 30MB
            }
    }

    $found = 0

    foreach ($file in ($files | Sort-Object FullName -Unique)) {
        $content = $null
        try {
            if ($file.Length -lt 4MB -and $file.Extension -match '\.(log|txt|json|cfg|properties|xml|yml|yaml)$') {
                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
            }
        } catch {}

        if ($content) {
            foreach ($s in $cheatStrings) {
                if ($content -match [regex]::Escape($s)) {
                    Add-Finding -Tier "Residual" -Category "Residual Artifact" -Title "Cheat String Found in Residual File" `
                        -Message "String '$s'  →  $($file.FullName)" `
                        -Evidence @{File=$file.FullName; String=$s}
                    $found++
                    break
                }
            }
        }

        foreach ($sig in $cheatPatterns) {
            if ($file.Name -match [regex]::Escape($sig)) {
                Add-Finding -Tier "Residual" -Category "Residual Artifact" -Title "Suspicious Residual Filename" `
                    -Message "Filename matches signature '$sig'  →  $($file.Name)" `
                    -Evidence @{File=$file.FullName; Signature=$sig}
                $found++
                break
            }
        }
    }

    # USN Journal (self-destruct)
    try {
        $usn = fsutil usn readjournal C: 2>$null | Select-String -Pattern "File Name.*\.jar" -Context 3,0
        if ($usn) {
            foreach ($line in $usn) {
                $fileName = ($line -split "File Name\s+:\s+")[1].Trim()
                if ($fileName -match '\.jar$') {
                    foreach ($sig in $cheatPatterns) {
                        if ($fileName -match [regex]::Escape($sig)) {
                            Add-Finding -Tier "Residual" -Category "USN Journal" -Title "Deleted / Renamed Cheat JAR (Self-Destruct Trace)" `
                                -Message "USN Journal → '$fileName' (signature: $sig)" `
                                -Evidence @{File=$fileName; Signature=$sig}
                            $found++
                            break
                        }
                    }
                }
            }
        }
    } catch {}

    if ($found -eq 0) {
        Write-Host "  ✔ No residual / self-destruct traces found." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "  ⚠ $found residual / self-destruct finding(s) detected." -ForegroundColor Red
    }
}
#endregion

#region Menu & Main
$script:Findings = @()
$script:ScanStart = Get-Date

function Show-Menu {
    Write-Host ""
    Write-Host "  1.  Scan mod folder          (only flagged / injected)" -ForegroundColor Green
    Write-Host "  2.  Scan JVM injection       (live processes)" -ForegroundColor Yellow
    Write-Host "  3.  Scan residual artifacts  (self-destruct traces)" -ForegroundColor Cyan
    Write-Host "  4.  Full Scan                (all modules)" -ForegroundColor Magenta
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
            Write-Host "  ══════════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "  FULL SCAN COMPLETE" -ForegroundColor White
            Write-Host "  ══════════════════════════════════════════════════════════════" -ForegroundColor Red
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
                    Summary = @{
                        Total      = $script:Findings.Count
                        Suspicious = ($script:Findings | Where-Object { $_.Tier -eq "Suspicious" }).Count
                        Bypass     = ($script:Findings | Where-Object { $_.Tier -eq "Bypass" }).Count
                        Obfuscated = ($script:Findings | Where-Object { $_.Tier -eq "Obfuscated" }).Count
                        JVM        = ($script:Findings | Where-Object { $_.Tier -eq "JVM" }).Count
                        Residual   = ($script:Findings | Where-Object { $_.Tier -eq "Residual" }).Count
                    }
                }

                $json = $report | ConvertTo-Json -Depth 5
                $jsonFile = "MagiciansReveal_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                $json | Out-File -FilePath $jsonFile -Encoding utf8
                Write-Host "  ✔ JSON report saved → $jsonFile" -ForegroundColor Green

                $txt = "MagiciansReveal V2.1 Forensic Report`n" + ("=" * 55) + "`n"
                $txt += "Scan Time: $($report.ScanTime)`n`n"
                foreach ($f in $script:Findings) {
                    $txt += "[$($f.Tier)] $($f.Title)`n  $($f.Message)`n`n"
                }
                $txtFile = "MagiciansReveal_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                $txt | Out-File -FilePath $txtFile -Encoding utf8
                Write-Host "  ✔ Text report saved → $txtFile" -ForegroundColor Green
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
                        "Suspicious" { "Yellow" }
                        "Bypass"     { "Magenta" }
                        "Obfuscated" { "Cyan" }
                        "JVM"        { "Red" }
                        "Residual"   { "DarkYellow" }
                        default      { "Gray" }
                    }
                    Write-Host ""
                    Write-Host "  [$($f.Tier)] $($f.Title)" -ForegroundColor $color
                    Write-Host "    $($f.Message)" -ForegroundColor White
                }
            }
            Read-Host "  Press Enter to continue"
            Write-Banner
        }
        "7" {
            $script:Findings = @()
            Write-Host "  ✔ Findings cleared." -ForegroundColor Green
            Start-Sleep -Milliseconds 800
            Write-Banner
        }
        "8" {
            Write-Host ""
            Write-Host "  Exiting Magicians Reveal..." -ForegroundColor DarkGray
            exit
        }
        default {
            Write-Host "  Invalid choice." -ForegroundColor Red
            Start-Sleep -Milliseconds 600
            Write-Banner
        }
    }
} while ($true)
#endregion
