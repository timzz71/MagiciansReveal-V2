<#
.SYNOPSIS
    MagiciansReveal v2.0 – Professional Minecraft Cheat Forensic Scanner
.DESCRIPTION
    Detects injectable cheats, self-destructing clients, obfuscated mods, and residual artifacts.
    Uses SHA-1 hash verification, 200+ signatures, bypass analysis, obfuscation scoring,
    JVM runtime inspection, and USN Journal/artifact scanning.
.AUTHOR
    Tim Cheese
.VERSION
    2.0.0
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

Write-Host $Banner -ForegroundColor DarkYellow
Write-Host ""
Write-Host "                Magicians Reveal V2" -ForegroundColor White
Write-Host ("━" * 76) -ForegroundColor Red
Write-Host ""

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    Write-Host "WARNING: Run as Administrator for full features (USN Journal, JVM injection scan)." -ForegroundColor Red
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
        "Verified"   { "Green" }
        "Suspicious" { "Yellow" }
        "Bypass"     { "Magenta" }
        "Obfuscated" { "Cyan" }
        "JVM"        { "Red" }
        "Residual"   { "DarkYellow" }
        default      { "Gray" }
    }
    Write-Host "[$Tier] $Title" -ForegroundColor $color
    Write-Host "  $Message" -ForegroundColor White
}
#endregion

#region Signature Databases
$cheatPatterns = @(
    "AimAssist","AutoCrystal","AutoHitCrystal","CrystalAura","TriggerBot","SilentAim",
    "Criticals","Reach","ReachHack","ShieldBreaker","ShieldDisabler","AxeSpam",
    "KillAura","BowAimbot","AutoCrit",
    "AutoAnchor","AnchorTweaks","DoubleAnchor","SafeAnchor","AirAnchor","AutoBed",
    "BedAura","NoBounce","LWFH Crystal","WalksyCrystalOptimizerMod",
    "AutoTotem","HoverTotem","InventoryTotem","LegitTotem","AutoPot","AutoArmor",
    "AutoDoubleHand","PopSwitch","MaceSwap","StunSlam",
    "FlyHack","SpeedHack","BHop","AntiFall","NoKnockback","AntiKB","StepHack",
    "WaterWalk","NoSlow","JumpReset","SprintReset","NoJumpDelay","ElytraSpeed",
    "FakeLag","PingSpoof","FakeInv","WTap","FakeNick","PackSpoof","Antiknockback",
    "AutoGap","AutoPearl","AutoTPA",
    "BlockESP","PlayerESP","XRayHack","Tracers","Freecam","FakeItem","NewChunks",
    "FastPlace","ChestSteal","AutoClicker","AutoEat","AutoMine","AutoFirework",
    "ElytraSwap","FastXP","AutoBridge","AutoBreach",
    "GrimBypass","VulcanBypass","MatrixBypass","AACBypass","VerusDisabler",
    "WatchdogBypass","PacketMine","PacketFly",
    "SessionStealer","TokenLogger","TokenGrabber","KeyLogger","RemoteAccess",
    "ReverseShell","Backdoor",
    "Asteria","Prestige","Xenon","Argon","Hellion","Virgin","Donut","VapeClient",
    "MeteorClient","LiquidBounce","RusherHack","FutureClient","Aristois","Pandaware",
    "AstolfoClient","Novoclient","IntentClient",
    "org.chainlibs.module.impl.modules",
    "LicenseCheckMixin","ClientPlayerInteractionManagerAccessor",
    "phantom-refmap.json","client-refmap.json","cheat-refmap.json",
    "jnativehook","imgui.binding","imgui.gl3","imgui.glfw"
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

$bypassPatterns = @(
    "runtime\.exec","ProcessBuilder","java\.io\.File","URL\.openStream",
    "HttpURLConnection","setRequestProperty","getOutputStream","getInputStream",
    "System\.getProperty","System\.getenv"
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
        $resp = Invoke-RestMethod -Uri $url -TimeoutSec 5 -ErrorAction Stop
        if ($resp -and $resp.project_id) {
            return @{ Verified = $true; Source = "Modrinth"; Name = $resp.project_id }
        }
    } catch {}
    return $null
}

function Check-Megabase {
    param([string]$Hash)
    try {
        $url = "https://megabase.vercel.app/api/query?hash=$Hash"
        $resp = Invoke-RestMethod -Uri $url -TimeoutSec 5 -ErrorAction Stop
        if ($resp -and $resp.found) {
            return @{ Verified = $true; Source = "Megabase"; Name = $resp.name }
        }
    } catch {}
    return $null
}

function Get-DownloadSource {
    param([string]$FilePath)
    $ads = "$FilePath`:Zone.Identifier"
    if (Test-Path $ads) {
        try {
            $content = Get-Content -Path $ads -ErrorAction Stop
            $urlLine = $content | Where-Object { $_ -match '^HostUrl=' }
            if ($urlLine) {
                return ($urlLine -replace '^HostUrl=','')
            }
        } catch {}
    }
    return $null
}

function Analyze-JAR {
    param([string]$FilePath)

    $hash = Get-FileSHA1 -Path $FilePath
    $verified = $null
    if ($hash) {
        $verified = Check-Modrinth -Hash $hash
        if (-not $verified) {
            $verified = Check-Megabase -Hash $hash
        }
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

    # Obfuscation scoring
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
        if ($name -match '(?:^|/)[a-z]/[a-z]/') {
            $obfuscationScore += 3
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
        Write-Host "Path not found." -ForegroundColor Red
        return
    }

    $jars = Get-ChildItem -Path $ModsPath -Filter *.jar -ErrorAction SilentlyContinue
    if ($jars.Count -eq 0) {
        Write-Host "No JAR files." -ForegroundColor Yellow
        return
    }

    Write-Host "Scanning $($jars.Count) mods..." -ForegroundColor Green
    $total = $jars.Count
    $i = 0

    foreach ($jar in $jars) {
        $i++
        Write-Progress -Activity "Analyzing JARs" -Status $jar.Name -PercentComplete (($i / $total) * 100)

        $result = Analyze-JAR -FilePath $jar.FullName
        if (-not $result) { continue }

        if ($result.Verified) {
            Add-Finding -Tier "Verified" -Category "File System" -Title "Verified Mod" `
                -Message "$($jar.Name) – verified via $($result.Verified.Source)" `
                -Evidence @{File=$jar.Name; Source=$result.Verified.Source}
            continue
        }

        if ($result.BypassIndicators.Count -gt 0 -or $result.FakeIdentity -or $result.NestedJAR) {
            $extra = ""
            if ($result.FakeIdentity) { $extra += " (Fake identity)" }
            if ($result.NestedJAR)    { $extra += " (nested JAR)" }

            Add-Finding -Tier "Bypass" -Category "File System" -Title "Bypass/Injection Detected" `
                -Message ("$($jar.Name) – " + ($result.BypassIndicators -join ', ') + $extra) `
                -Evidence @{File=$jar.Name; Bypass=$result.BypassIndicators}
            continue
        }

        if ($result.ObfuscationScore -ge 5) {
            Add-Finding -Tier "Obfuscated" -Category "File System" -Title "Heavily Obfuscated" `
                -Message "$($jar.Name) – score $($result.ObfuscationScore) (single-letter: $([math]::Round($result.SingleLetterRatio*100))%, numeric: $([math]::Round($result.NumericRatio*100))%, Unicode: $([math]::Round($result.UnicodeRatio*100))%)" `
                -Evidence @{File=$jar.Name; ObfuscationScore=$result.ObfuscationScore}
            continue
        }

        if ($result.Patterns.Count -gt 0 -or $result.Strings.Count -gt 0 -or $result.Fullwidth.Count -gt 0) {
            $msgParts = @()
            if ($result.Patterns.Count -gt 0)  { $msgParts += "Patterns: $($result.Patterns -join ', ')" }
            if ($result.Strings.Count -gt 0)   { $msgParts += "Strings: $($result.Strings -join ', ')" }
            if ($result.Fullwidth.Count -gt 0) { $msgParts += "Fullwidth: $($result.Fullwidth -join ', ')" }

            Add-Finding -Tier "Suspicious" -Category "File System" -Title "Cheat-Related Content" `
                -Message ("$($jar.Name) – " + ($msgParts -join '; ')) `
                -Evidence @{File=$jar.Name; Patterns=$result.Patterns; Strings=$result.Strings; Fullwidth=$result.Fullwidth}
            continue
        }

        $source = Get-DownloadSource -FilePath $jar.FullName
        $src = if ($source) { $source } else { "Unknown" }

        Add-Finding -Tier "Unknown" -Category "File System" -Title "Unknown Mod" `
            -Message "$($jar.Name) – source: $src" `
            -Evidence @{File=$jar.Name; Source=$source}
    }

    Write-Progress -Activity "Analyzing JARs" -Completed
}

function Scan-JVMInjection {
    Write-Host "Scanning live Java processes..." -ForegroundColor Green
    $java = Get-Process -Name java,javaw -ErrorAction SilentlyContinue
    if (-not $java) {
        Write-Host "No Java processes." -ForegroundColor Yellow
        return
    }

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

            if ($cmd -match '-Xbootclasspath/p:') { $issues += "Xbootclasspath/p: prepend" }
            if ($cmd -match '-Xbootclasspath/a:') { $issues += "Xbootclasspath/a: append" }
            if ($cmd -match '-agentlib:jdwp')     { $issues += "JDWP debug agent" }
            if ($cmd -match '-agentpath:')        { $issues += "Native agent (agentpath)" }

            if ($issues.Count -gt 0) {
                Add-Finding -Tier "JVM" -Category "Runtime Injection" -Title "JVM Injection Flags" `
                    -Message ("PID $($p.Id) – " + ($issues -join '; ')) `
                    -Evidence @{PID=$p.Id; Flags=$issues}
            }
        } catch {}
    }
}

function Scan-ResidualArtifacts {
    Write-Host "Scanning residual artifacts (TEMP, Prefetch, Logs, CrashDumps, USN Journal)..." -ForegroundColor Green

    $roots = @(
        "$env:TEMP",
        "$env:USERPROFILE\AppData\Local\Temp",
        "$env:windir\Prefetch",
        "$env:USERPROFILE\AppData\Roaming\.minecraft\logs",
        "$env:USERPROFILE\AppData\Roaming\.minecraft\crash-reports",
        "$env:USERPROFILE\AppData\Local\CrashDumps"
    ) | Where-Object { Test-Path $_ -PathType Container }

    $files = foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                -not $_.PSIsContainer -and
                $_.LastWriteTime -ge (Get-Date).AddDays(-7) -and
                $_.Length -le 50MB
            }
    }

    foreach ($file in ($files | Sort-Object FullName -Unique)) {
        $content = $null
        try {
            if ($file.Length -lt 5MB) {
                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
            }
        } catch {}

        if ($content) {
            foreach ($s in $cheatStrings) {
                if ($content -match [regex]::Escape($s)) {
                    Add-Finding -Tier "Residual" -Category "Residual Artifact" -Title "Cheat String in Residual File" `
                        -Message "String '$s' found in $($file.FullName)" `
                        -Evidence @{File=$file.FullName; String=$s; LastWrite=$file.LastWriteTime.ToString("o")}
                    break
                }
            }

            foreach ($m in $patternRegex.Matches($content)) {
                Add-Finding -Tier "Residual" -Category "Residual Artifact" -Title "Pattern in Residual File" `
                    -Message "Pattern '$($m.Value)' found in $($file.FullName)" `
                    -Evidence @{File=$file.FullName; Pattern=$m.Value}
                break
            }
        }

        foreach ($sig in $cheatPatterns) {
            if ($file.Name -match [regex]::Escape($sig)) {
                Add-Finding -Tier "Residual" -Category "Residual Artifact" -Title "Suspicious Residual Filename" `
                    -Message "Filename '$($file.Name)' matches signature '$sig'" `
                    -Evidence @{File=$file.FullName; Signature=$sig}
                break
            }
        }
    }

    # USN Journal (self-destruct traces)
    try {
        $usn = fsutil usn readjournal C: 2>$null | Select-String -Pattern "File Name.*\.jar" -Context 5,0
        if ($usn) {
            foreach ($line in $usn) {
                $fileName = ($line -split "File Name\s+:\s+")[1].Trim()
                if ($fileName -match '\.jar$') {
                    foreach ($sig in $cheatPatterns) {
                        if ($fileName -match [regex]::Escape($sig)) {
                            Add-Finding -Tier "Residual" -Category "USN Journal" -Title "Deleted/Renamed Cheat JAR" `
                                -Message "USN Journal shows recent activity on '$fileName' (signature: $sig)" `
                                -Evidence @{File=$fileName; Signature=$sig}
                            break
                        }
                    }
                    foreach ($client in $cheatStrings) {
                        if ($fileName -match [regex]::Escape($client)) {
                            Add-Finding -Tier "Residual" -Category "USN Journal" -Title "Deleted/Renamed Cheat Client JAR" `
                                -Message "USN Journal shows recent activity on '$fileName' (client: $client)" `
                                -Evidence @{File=$fileName; Client=$client}
                            break
                        }
                    }
                }
            }
        }
    } catch {}

    Write-Host "Residual scan complete." -ForegroundColor Green
}
#endregion

#region Menu & Main
$script:Findings = @()
$script:ScanStart = Get-Date

function Show-Menu {
    Write-Host ""
    Write-Host "1. Scan mod folder (full analysis)" -ForegroundColor Green
    Write-Host "2. Scan JVM injection (live)" -ForegroundColor Yellow
    Write-Host "3. Scan residual artifacts (self-destruct traces)" -ForegroundColor Cyan
    Write-Host "4. Run Full Scan (all of the above)" -ForegroundColor Magenta
    Write-Host "5. Export report (JSON + TXT)" -ForegroundColor White
    Write-Host "6. View findings" -ForegroundColor Gray
    Write-Host "7. Clear findings" -ForegroundColor Red
    Write-Host "8. Exit" -ForegroundColor DarkGray
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "Enter choice"

    switch ($choice) {
        "1" {
            $path = Read-Host "Enter full path to mods folder"
            if ([string]::IsNullOrWhiteSpace($path)) {
                $path = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
            }
            Scan-Mods -ModsPath $path
            Read-Host "Press Enter to continue"
        }
        "2" {
            Scan-JVMInjection
            Read-Host "Press Enter to continue"
        }
        "3" {
            Scan-ResidualArtifacts
            Read-Host "Press Enter to continue"
        }
        "4" {
            $path = Read-Host "Enter mods folder path (or Enter for default)"
            if ([string]::IsNullOrWhiteSpace($path)) {
                $path = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
            }
            Scan-Mods -ModsPath $path
            Scan-JVMInjection
            Scan-ResidualArtifacts
            Read-Host "Full scan complete. Press Enter to continue"
        }
        "5" {
            if ($script:Findings.Count -eq 0) {
                Write-Host "No findings." -ForegroundColor Yellow
                continue
            }

            $report = @{
                ScanTime = $script:ScanStart.ToString("o")
                Findings = $script:Findings
                Summary = @{
                    Total      = $script:Findings.Count
                    Verified   = ($script:Findings | Where-Object { $_.Tier -eq "Verified" }).Count
                    Suspicious = ($script:Findings | Where-Object { $_.Tier -eq "Suspicious" }).Count
                    Bypass     = ($script:Findings | Where-Object { $_.Tier -eq "Bypass" }).Count
                    Obfuscated = ($script:Findings | Where-Object { $_.Tier -eq "Obfuscated" }).Count
                    JVM        = ($script:Findings | Where-Object { $_.Tier -eq "JVM" }).Count
                    Residual   = ($script:Findings | Where-Object { $_.Tier -eq "Residual" }).Count
                    Unknown    = ($script:Findings | Where-Object { $_.Tier -eq "Unknown" }).Count
                }
            }

            $json = $report | ConvertTo-Json -Depth 5
            $jsonFile = "MagiciansRevealV2_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $json | Out-File -FilePath $jsonFile -Encoding utf8
            Write-Host "JSON report saved to $jsonFile" -ForegroundColor Green

            $txt = "MagiciansReveal V2 Report`n" + ("=" * 50) + "`n"
            $txt += "Scan Time: $($report.ScanTime)`n`n"
            foreach ($f in $script:Findings) {
                $txt += "[$($f.Tier)] $($f.Title)`n  $($f.Message)`n"
            }
            $txtFile = "MagiciansRevealV2_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            $txt | Out-File -FilePath $txtFile -Encoding utf8
            Write-Host "Text report saved to $txtFile" -ForegroundColor Green

            Read-Host "Press Enter to continue"
        }
        "6" {
            if ($script:Findings.Count -eq 0) {
                Write-Host "No findings." -ForegroundColor Yellow
            } else {
                Write-Host "`n--- Findings ($($script:Findings.Count)) ---" -ForegroundColor Cyan
                foreach ($f in $script:Findings) {
                    $color = switch ($f.Tier) {
                        "Verified"   { "Green" }
                        "Suspicious" { "Yellow" }
                        "Bypass"     { "Magenta" }
                        "Obfuscated" { "Cyan" }
                        "JVM"        { "Red" }
                        "Residual"   { "DarkYellow" }
                        default      { "Gray" }
                    }
                    Write-Host "[$($f.Tier)] $($f.Title)" -ForegroundColor $color
                    Write-Host "  $($f.Message)" -ForegroundColor White
                }
            }
            Read-Host "Press Enter to continue"
        }
        "7" {
            $script:Findings = @()
            Write-Host "Findings cleared." -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }
        "8" {
            Write-Host "Exiting." -ForegroundColor Cyan
            exit
        }
        default {
            Write-Host "Invalid choice." -ForegroundColor Red
        }
    }
} while ($true)
#endregion
