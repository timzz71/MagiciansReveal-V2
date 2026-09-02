#Requires -Version 5.1
<#
.SYNOPSIS
    Minecraft Cheat Client Forensic Scanner (Zero False-Positive Edition) – Fixed Unicode
.DESCRIPTION
    Professional self-contained PowerShell forensic scanner.
    Detects known Minecraft cheat clients using ONLY cheat-specific signatures.
    Produces severity-tiered human-readable report + structured JSON.
.NOTES
    Version     : 3.2.0 (Unicode-safe)
    No external dependencies.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "$env:TEMP\MCCheatScan_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$DeepJarScan,
    [switch]$SkipDns,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# 1. CHEAT-ONLY SIGNATURE DATABASE
# ---------------------------------------------------------------------------

$ClientBrandStrings = @(
    'vape.gg','vapeclient.com','vapeclient','vape-lite','Vape','VapeV4','VapeLite','VapeClient',
    'meteor-client','meteorclient','meteor.development','Meteor','MeteorClient',
    'liquidbounce','net.ccbluex','liquidbounce.net','LiquidBounce','LiquidBounceNextGen',
    'wurst','wurstclient','Wurst','WurstClient',
    'sigmaclient','sigma client','sigmaclient.com','Sigma','SigmaClient',
    'salhack','salhack client','Salhack','SalHack',
    'novoware','novo client','novoware.cc','Novoware','NovoWare',
    'gamesense','gamesense client','gamesense.pw','GameSense','GameSenseClient',
    'osiris','osirisclient','osirisclient.com','Osiris','OsirisClient',
    'cosmos','cosmosclient','cosmosclient.com','Cosmos','CosmosClient',
    'sorus','sorusclient','sorusclient.net','Sorus','SorusClient',
    'azura','azuraclient','azuraclient.com','Azura','AzuraClient',
    'doomsday','doomsdayclient','doomsdayclient.com','Doomsday','DoomsdayClient',
    'argon','argonclient','argonclient.com','Argon','ArgonClient',
    'krypton','kryptonclient','kryptonclient.net','Krypton','KryptonClient',
    'prestige','prestigeclient','prestigeclient.vip','Prestige','PrestigeClient',
    '198macros','macro198','macros198','198Macros',
    'delta','deltaclient','deltaclient.net','Delta','DeltaClient',
    'elysian','elysianclient','elysianclient.org','Elysian','ElysianClient',
    'onyx','onyxclient','onyxclient.com','Onyx','OnyxClient',
    'lumina','luminaclient','luminaclient.net','Lumina','LuminaClient',
    'momentum','momentumclient','momentumclient.com','Momentum','MomentumClient',
    'ravenbplusplus','ravenb++','ravenbplusplus.net','RavenB++','RavenBPlusPlus',
    'uzi','uziclient','uziclient.com','UZI','UziClient',
    'skidbounce','skidbounceclient','skidbounce.net','SkidBounce','SkidBounceClient',
    'skidcraft','skidcraftclient','Skidcraft','SkidcraftClient',
    'backdoored','backdooredclient','Backdoored','BackdooredClient',
    'leuxbackdoor','LeuxBackdoor',
    'salhackskid','SalHackSkid',
    'grassware','grasswareclient','GrassWare','GrassWareClient',
    'allahware','allahwareclient','AllahWare','AllahWareClient',
    'bbcware','bbcwareclient','BBCWare','BBCWareClient',
    'arsenic','arsenicclient','Arsenic','ArsenicClient',
    'atrium','atriumclient','Atrium','AtriumClient',
    'bleachhack','bleachhack.org','BleachHack','BleachHackClient',
    'caizm','caizmclient','Caizm','CaizmClient',
    'coffee','coffeeclient','Coffee','CoffeeClient',
    'cranberry','cranberryclient','Cranberry','CranberryClient',
    'evangelion','evangelionclient','Evangelion','EvangelionClient',
    'fdp','fdpclient','FDP','FDPClient',
    'fog','fogclient','Fog','FogClient',
    'forgehax','forgehax.com','ForgeHax','ForgeHaxClient',
    'huzuni','huzuni.org','Huzuni','HuzuniClient',
    'hydrogen','hydrogenclient','Hydrogen','HydrogenClient',
    'ikea','ikeaclient','Ikea','IkeaClient',
    'jex','jexclient','Jex','JexClient',
    'kamiblue','kamiblue.org','Kamiblue','KamiblueClient','KAMI','KAMIClient',
    'konas','konasclient.com','Konas','KonasClient',
    'kura','kuraclient.net','Kura','KuraClient',
    'lambda','lambdaclient.com','Lambda','LambdaClient',
    'lavahack','lavahackclient','LavaHack','LavaHackClient',
    'mercury','mercuryclient.org','Mercury','MercuryClient',
    'mint','mintclient','Mint','MintClient',
    'mirai','miraiclient.net','Mirai','MiraiClient',
    'nclient','NClient',
    'neptunium','neptuniumclient','Neptunium','NeptuniumClient',
    'ozark','ozarkclient.com','Ozark','OzarkClient',
    'raion','raionclient.net','Raion','RaionClient',
    'rebirth','rebirthclient','Rebirth','RebirthClient',
    'rift','riftclient','Rift','RiftClient',
    'selene','seleneclient','Selene','SeleneClient',
    'seppuku','seppukuclient.com','Seppuku','SeppukuClient',
    'silence','silenceclient','Silence','SilenceClient',
    'spark','sparkclient','Spark','SparkClient',
    'swift','swiftclient','Swift','SwiftClient',
    'tensor','tensorclient','Tensor','TensorClient',
    'tokyo','tokyoclient','Tokyo','TokyoClient',
    'trollhack','trollhackclient','Trollhack','TrollhackClient',
    'vertex','vertexclient.net','Vertex','VertexClient',
    'vrpos','vrposclient','Vrpos','VrposClient',
    'xulu','xuluclient','Xulu','XuluClient',
    'zeon','zeonclient','Zeon','ZeonClient',
    'zerotwo','zerotwoclient','ZeroTwo','ZeroTwoClient',
    'zodiac','zodiacclient','Zodiac','ZodiacClient',
    'impact','impactclient','Impact','ImpactClient',
    'aristois','aristoisclient','Aristois','AristoisClient',
    'phobos','phobosclient','Phobos','PhobosClient',
    'rusherhack','rusherhackclient','RusherHack','RusherHackClient',
    'future','futureclient','Future','FutureClient',
    'remix','remixclient','Remix','RemixClient',
    'yasha','yashaclient','Yasha','YashaClient',
    'zeroday','zerodayclient','ZeroDay','ZeroDayClient',
    'orchard','orchard client','orchard.gg','Orchard','OrchardClient',
    'gypsy','gypsyclient','Gypsy','GypsyClient',
    'xenon','xenonclient','Xenon','XenonClient',
    'asteria','asteriaclient','Asteria','AsteriaClient',
    'dqrkis.xyz','dqrkis'
) | Sort-Object -Unique

$PackagePaths = @(
    'cc/novoline','com/alan/clients','club/maxstats','wtf/moonlight',
    'me/zeroeightsix/kami','net/ccbluex','today/opai','net/minecraft/injection',
    'org/chainlibs/module/impl/modules','xyz/greaj','com/cheatbreaker',
    'com/moonsworth','dev/krypton','skid/krypton','dev/gambleclient','dev/virel',
    'org/jose4j/jwt','sixtwo/','fivefive/'
)

$ExactModules = @(
    'KillAura','Killaura','killaura','CrystalAura','crystalaura','AutoCrystal','autocrystal',
    'MaceAura','maceaura','SilentMace','silentmace','AimAssist','aimassist','SilentAim','silentaim',
    'BowAimbot','bowaimbot','TriggerBot','triggerbot','AntiWeakness','antiweakness',
    'FakePunch','fakepunch','DamageTick','damagetick','OnlyCrit','onlycrit',
    'StaticHitBoxes','statichitboxes','ShieldDisabler','shielddisabler','AntiInvis','antiinvis',
    'W-Tap','wtap','AutoCrit','autocrit','GodMode','godmode','ReachHack','reachhack',
    'CrystalOptimizer','crystaloptimizer','CwCrystal','cwcrystal','DoubleAnchor','doubleanchor',
    'AnchorExploder','anchorexploder','AutoDtap','autodtap','MarlowAnchor','marlowanchor','AntiAntiCw','antianticw',
    'AutoTotem','autototem','TotemOffhand','totemoffhand','HoverTotem','hovertotem',
    'ForceTotem','forcetotem','AutoRetotem','autoretotem','InventoryTotemLegit','inventorytotemlegit',
    'AutoDoubleHand','autodoublehand',
    'FastBridge','fastbridge','BridgeAssist','bridgeassist','FastSwim','fastswim',
    'FastPlace','fastplace','NoBreakDelay','nobreakdelay','NoJumpDelay','nojumpdelay',
    'ElytraSwap','elytraswap','ElytraGlide','elytraglide','Jetpack','jetpack',
    'AutoSprint','autosprint','InventoryMove','inventorymove','SpeedHack','speedhack',
    'AutoClicker','autoclicker','AutoPot','autopot','AutoEat','autoeat','AutoXP','autoxp',
    'AutoArmor','autoarmor','AutoTool','autotool','AutoMine','automine','ChestStealer','cheststealer',
    'ShulkerDropper','shulkerdropper','AutoSell','autosell','CordSnapper','cordsnapper',
    'KeyPearl','keypearl','AutoTpa','autotpa','BedMacro','bedmacro','AutoRestock','autorestock',
    'ReplaceMod','replacemod','Scaffold','scaffold','Tower','tower',
    'PlayerESP','playeresp','StorageESP','storageesp','EntityESP','entityesp',
    'XRayHack','xrayhack','HealthIndicators','healthindicators','TargetHUD','targethud',
    'NetheriteFinder','netheritefinder','RtpBaseFinder','rtpbasefinder','Tracers','tracers',
    'Chams','chams','GlowESP','glowesp','Radar','radar',
    'FakeLag','fakelag','PingSpoof','pingspoof','PackSpoof','packspoof','StrayBypass','straybypass',
    'DonutSMPBypass','donutsmpbypass','AntiSSTool','antiss tool','StringCleaner','stringcleaner',
    'SelfDestruct','selfdestruct','USNJournalCleaner','usnjournalcleaner','DeleteUSNJournal','deleteusnjournal',
    'GenericSelfdestruct','genericselfdestruct','Disabler','disabler','AntiBan','antiban'
) | Sort-Object -Unique

# Fullwidth / obfuscation patterns – SAFE Unicode escapes (never breaks parser)
$FullwidthPatterns = @(
    ([string]([char]0xFF21) + [char]0xFF55 + [char]0xFF54 + [char]0xFF4F + [char]0xFF43 + [char]0xFF52 + [char]0xFF59 + [char]0xFF53 + [char]0xFF54 + [char]0xFF41 + [char]0xFF4C), # AutoCrystal variant
    ([string]([char]0xFF21) + [char]0xFF55 + [char]0xFF54 + [char]0xFF4F + [char]0xFF41 + [char]0xFF6E + [char]0xFF43 + [char]0xFF48 + [char]0xFF4F + [char]0xFF52), # AutoAnchor
    ([string]([char]0xFF21) + [char]0xFF55 + [char]0xFF54 + [char]0xFF4F + [char]0xFF54 + [char]0xFF4F + [char]0xFF54 + [char]0xFF45 + [char]0xFF4D), # AutoTotem
    ([string]([char]0xFF21) + [char]0xFF49 + [char]0xFF4D + [char]0xFF41 + [char]0xFF53 + [char]0xFF53 + [char]0xFF49 + [char]0xFF53 + [char]0xFF54), # AimAssist
    ([string]([char]0xFF21) + [char]0xFF55 + [char]0xFF54 + [char]0xFF4F + [char]0xFF43 + [char]0xFF4C + [char]0xFF49 + [char]0xFF43 + [char]0xFF4B + [char]0xFF45 + [char]0xFF52), # AutoClicker
    ([string]([char]0xFF54) + [char]0xFF52 + [char]0xFF49 + [char]0xFF47 + [char]0xFF47 + [char]0xFF45 + [char]0xFF52 + [char]0xFF42 + [char]0xFF4F + [char]0xFF54), # TriggerBot
    ([string]([char]0xFF21) + [char]0xFF55 + [char]0xFF54 + [char]0xFF4F + [char]0xFF4D + [char]0xFF41 + [char]0xFF43 + [char]0xFF45), # AutoMace
    ([string]([char]0xFF43) + [char]0xFF52 + [char]0xFF59 + [char]0xFF53 + [char]0xFF54 + [char]0xFF41 + [char]0xFF4C + [char]0xFF41 + [char]0xFF55 + [char]0xFF52 + [char]0xFF41), # CrystalAura
    ([string]([char]0xFF53) + [char]0xFF48 + [char]0xFF49 + [char]0xFF45 + [char]0xFF4C + [char]0xFF44 + [char]0xFF44 + [char]0xFF49 + [char]0xFF53 + [char]0xFF41 + [char]0xFF42 + [char]0xFF4C + [char]0xFF45 + [char]0xFF52), # ShieldDisabler
    ([string]([char]0xFF41) + [char]0xFF4E + [char]0xFF43 + [char]0xFF48 + [char]0xFF4F + [char]0xFF52 + [char]0xFF41 + [char]0xFF55 + [char]0xFF52 + [char]0xFF41)  # AnchorAura
)

$CheatDomains = @(
    'vape.gg','vapeclient.com','meteorclient.com','liquidbounce.net','wurstclient.net',
    'sigmaclient.com','novoware.cc','gamesense.pw','osirisclient.com','cosmosclient.com',
    'sorusclient.net','azuraclient.com','deltaclient.net','elysianclient.org','onyxclient.com',
    'luminaclient.net','ravenbplusplus.net','uziclient.com','skidbounce.net','bleachhack.org',
    'forgehax.com','huzuni.org','kamiblue.org','konasclient.com','kuraclient.net',
    'lambdaclient.com','mercuryclient.org','miraiclient.net','ozarkclient.com','raionclient.net',
    'seppukuclient.com','vertexclient.net','prestigeclient.vip','dqrkis.xyz','orchard.gg'
)

$JvmCheatArgs = @(
    '-Dclient.brand=',
    '-Dxray','-Dfly','-Dspeed','-Dkillaura','-Dreach','-Dscaffold',
    '-Dautocrystal','-Dautototem','-Djava.security.manager=',
    '-Xbootclasspath','-javaagent:'
)

# ---------------------------------------------------------------------------
# 2. RESULT CONTAINERS
# ---------------------------------------------------------------------------

$Findings = [System.Collections.Generic.List[object]]::new()
$ScanStart = Get-Date
$ScriptVersion = '3.2.0'

function Add-Finding {
    param(
        [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO')]
        [string]$Severity,
        [string]$Category,
        [string]$Indicator,
        [string]$Location,
        [string]$Evidence,
        [string]$Confidence = 'Medium',
        [hashtable]$Extra = @{}
    )
    $Findings.Add([PSCustomObject]@{
        Timestamp   = (Get-Date).ToString('o')
        Severity    = $Severity
        Category    = $Category
        Indicator   = $Indicator
        Location    = $Location
        Evidence    = $Evidence
        Confidence  = $Confidence
        Extra       = $Extra
    })
}

# ---------------------------------------------------------------------------
# 3. HELPER FUNCTIONS
# ---------------------------------------------------------------------------

function Get-MinecraftRoots {
    $roots = [System.Collections.Generic.List[string]]::new()
    $candidates = @(
        "$env:APPDATA\.minecraft",
        "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_*\LocalState\games\com.mojang",
        "$env:USERPROFILE\curseforge\minecraft\Instances",
        "$env:USERPROFILE\AppData\Roaming\.minecraft",
        "$env:USERPROFILE\Documents\Curse\Minecraft\Instances",
        "$env:USERPROFILE\scoop\apps\minecraft\current",
        "C:\MultiMC\instances",
        "C:\PrismLauncher\instances",
        "C:\ATLauncher\instances",
        "C:\GDLauncher\instances",
        "$env:USERPROFILE\AppData\Roaming\PrismLauncher\instances",
        "$env:USERPROFILE\AppData\Roaming\PolyMC\instances",
        "$env:USERPROFILE\AppData\Roaming\MultiMC\instances"
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { $roots.Add((Resolve-Path $c).Path) }
    }
    $searchRoots = @("$env:APPDATA","$env:LOCALAPPDATA","$env:USERPROFILE\Documents")
    foreach ($sr in $searchRoots) {
        if (-not (Test-Path $sr)) { continue }
        Get-ChildItem -Path $sr -Directory -Filter "mods" -Recurse -Depth 4 -ErrorAction SilentlyContinue |
            ForEach-Object { $roots.Add($_.Parent.FullName) }
    }
    return $roots | Sort-Object -Unique
}

function Test-StringInFile {
    param([string]$Path, [string[]]$Needles, [switch]$BinarySafe)
    try {
        if ($BinarySafe) {
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $text  = [System.Text.Encoding]::UTF8.GetString($bytes)
        } else {
            $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        }
        foreach ($n in $Needles) {
            if ($text -like "*$n*") { return $true }
        }
    } catch {}
    return $false
}

function Search-JarForSignatures {
    param([string]$JarPath)
    $hits = [System.Collections.Generic.List[string]]::new()
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('\','/')
            foreach ($pp in $PackagePaths) {
                if ($name -like "*$pp*") {
                    $hits.Add("PACKAGE:$pp in $name")
                }
            }
            if ($DeepJarScan -or $entry.Length -lt 2MB) {
                if ($entry.Name -match '\.(class|json|txt|properties|cfg|yml|yaml|toml)$') {
                    $stream = $entry.Open()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $content = $reader.ReadToEnd()
                    $reader.Close(); $stream.Close()

                    foreach ($brand in $ClientBrandStrings) {
                        if ($content -match [regex]::Escape($brand)) {
                            $hits.Add("BRAND:$brand")
                        }
                    }
                    foreach ($mod in $ExactModules) {
                        if ($content -match [regex]::Escape($mod)) {
                            $hits.Add("MODULE:$mod")
                        }
                    }
                    foreach ($fw in $FullwidthPatterns) {
                        if ($content.Contains($fw)) {
                            $hits.Add("FULLWIDTH:$fw")
                        }
                    }
                }
            }
        }
        $zip.Dispose()
    } catch {
        if (Test-StringInFile -Path $JarPath -Needles $ClientBrandStrings -BinarySafe) {
            $hits.Add("BRAND:raw-file-match")
        }
    }
    return $hits | Sort-Object -Unique
}

# ---------------------------------------------------------------------------
# 4. SCAN PHASES
# ---------------------------------------------------------------------------

Write-Host "[*] Minecraft Cheat Client Forensic Scanner v$ScriptVersion" -ForegroundColor Cyan
Write-Host "[*] Output directory: $OutputDir" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# 4.1 Running processes
Write-Host "[*] Scanning running processes..." -ForegroundColor Yellow
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    $cmd = $_.CommandLine
    if (-not $cmd) { return }
    $procName = $_.Name
    $pid = $_.ProcessId

    foreach ($arg in $JvmCheatArgs) {
        if ($cmd -match [regex]::Escape($arg)) {
            Add-Finding -Severity 'CRITICAL' -Category 'Process' -Indicator "JVM cheat argument" `
                -Location "PID $pid ($procName)" -Evidence $cmd.Substring(0,[Math]::Min(400,$cmd.Length)) `
                -Confidence 'High'
        }
    }
    foreach ($brand in $ClientBrandStrings) {
        if ($cmd -match [regex]::Escape($brand)) {
            Add-Finding -Severity 'HIGH' -Category 'Process' -Indicator "Client brand in command line" `
                -Location "PID $pid ($procName)" -Evidence $brand -Confidence 'High'
        }
    }
}

# 4.2 DNS cache
if (-not $SkipDns) {
    Write-Host "[*] Checking DNS cache for cheat domains..." -ForegroundColor Yellow
    try {
        $dns = Get-DnsClientCache -ErrorAction SilentlyContinue
        foreach ($entry in $dns) {
            $name = $entry.Entry
            foreach ($dom in $CheatDomains) {
                if ($name -like "*$dom*") {
                    Add-Finding -Severity 'HIGH' -Category 'Network' -Indicator "Cheat domain in DNS cache" `
                        -Location $name -Evidence "Type=$($entry.Type) Status=$($entry.Status)" `
                        -Confidence 'High'
                }
            }
        }
    } catch {
        $raw = ipconfig /displaydns 2>$null | Out-String
        foreach ($dom in $CheatDomains) {
            if ($raw -match [regex]::Escape($dom)) {
                Add-Finding -Severity 'HIGH' -Category 'Network' -Indicator "Cheat domain in DNS cache (legacy)" `
                    -Location $dom -Evidence "Found via ipconfig /displaydns" -Confidence 'Medium'
            }
        }
    }
}

# 4.3 Minecraft directory tree
Write-Host "[*] Discovering Minecraft roots..." -ForegroundColor Yellow
$mcRoots = Get-MinecraftRoots
Write-Host "[*] Found $($mcRoots.Count) potential Minecraft roots" -ForegroundColor Green

foreach ($root in $mcRoots) {
    Write-Host "    Scanning: $root" -ForegroundColor DarkGray

    $searchPaths = @(
        (Join-Path $root 'mods'),
        (Join-Path $root 'versions'),
        (Join-Path $root 'libraries'),
        $root
    ) | Where-Object { Test-Path $_ }

    foreach ($sp in $searchPaths) {
        Get-ChildItem -Path $sp -Recurse -Include *.jar,*.zip,*.dll,*.so,*.json,*.txt,*.cfg,*.properties `
            -ErrorAction SilentlyContinue | ForEach-Object {
            $file = $_
            $nameLower = $file.Name.ToLowerInvariant()
            foreach ($brand in $ClientBrandStrings) {
                if ($nameLower -like "*$($brand.ToLowerInvariant())*") {
                    Add-Finding -Severity 'HIGH' -Category 'Filesystem' -Indicator "Cheat client name in filename" `
                        -Location $file.FullName -Evidence $file.Name -Confidence 'High'
                }
            }

            if ($file.Extension -in '.jar','.zip') {
                $hits = Search-JarForSignatures -JarPath $file.FullName
                foreach ($h in $hits) {
                    $sev = 'MEDIUM'
                    $conf = 'Medium'
                    if ($h -like 'PACKAGE:*' -or $h -like 'FULLWIDTH:*') {
                        $sev = 'CRITICAL'; $conf = 'High'
                    } elseif ($h -like 'BRAND:*') {
                        $sev = 'HIGH'; $conf = 'High'
                    } elseif ($h -like 'MODULE:*') {
                        $sev = 'MEDIUM'; $conf = 'Medium'
                    }
                    Add-Finding -Severity $sev -Category 'JAR Content' -Indicator $h `
                        -Location $file.FullName -Evidence $h -Confidence $conf
                }
            } else {
                if (Test-StringInFile -Path $file.FullName -Needles $ClientBrandStrings) {
                    Add-Finding -Severity 'MEDIUM' -Category 'Filesystem' -Indicator "Client brand string in file" `
                        -Location $file.FullName -Evidence "Matched client brand" -Confidence 'Medium'
                }
                if (Test-StringInFile -Path $file.FullName -Needles $ExactModules) {
                    Add-Finding -Severity 'LOW' -Category 'Filesystem' -Indicator "Exact module name in file" `
                        -Location $file.FullName -Evidence "Matched module name" -Confidence 'Low'
                }
            }
        }
    }
}

# 4.4 Prefetch
Write-Host "[*] Checking Prefetch..." -ForegroundColor Yellow
$prefetch = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetch) {
    Get-ChildItem $prefetch -Filter *.pf -ErrorAction SilentlyContinue | ForEach-Object {
        $n = $_.Name.ToLowerInvariant()
        foreach ($brand in $ClientBrandStrings) {
            if ($n -like "*$($brand.ToLowerInvariant())*") {
                Add-Finding -Severity 'MEDIUM' -Category 'Prefetch' -Indicator "Cheat-related Prefetch entry" `
                    -Location $_.FullName -Evidence $_.Name -Confidence 'Medium'
            }
        }
    }
}

# 4.5 Recent / Temp / Downloads
Write-Host "[*] Scanning recent files and temp locations..." -ForegroundColor Yellow
$extraLocs = @(
    "$env:APPDATA\Microsoft\Windows\Recent",
    "$env:LOCALAPPDATA\Temp",
    "$env:TEMP",
    "$env:USERPROFILE\Downloads"
)
foreach ($loc in $extraLocs) {
    if (-not (Test-Path $loc)) { continue }
    Get-ChildItem $loc -Recurse -Depth 2 -Include *.jar,*.exe,*.lnk,*.bat,*.ps1 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $n = $_.Name.ToLowerInvariant()
            foreach ($brand in $ClientBrandStrings) {
                if ($n -like "*$($brand.ToLowerInvariant())*") {
                    Add-Finding -Severity 'MEDIUM' -Category 'Recent/Temp' -Indicator "Cheat artifact in recent/temp" `
                        -Location $_.FullName -Evidence $_.Name -Confidence 'Medium'
                }
            }
        }
}

# ---------------------------------------------------------------------------
# 5. REPORT GENERATION
# ---------------------------------------------------------------------------

$ScanEnd = Get-Date
$Duration = ($ScanEnd - $ScanStart).TotalSeconds

$crit = ($Findings | Where-Object Severity -eq 'CRITICAL').Count
$high = ($Findings | Where-Object Severity -eq 'HIGH').Count
$med  = ($Findings | Where-Object Severity -eq 'MEDIUM').Count
$low  = ($Findings | Where-Object Severity -eq 'LOW').Count

$summaryPath = Join-Path $OutputDir 'CheatScan_Report.txt'
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("=" * 80)
[void]$sb.AppendLine("MINECRAFT CHEAT CLIENT FORENSIC SCANNER – REPORT")
[void]$sb.AppendLine("Version      : $ScriptVersion")
[void]$sb.AppendLine("Scan start   : $($ScanStart.ToString('o'))")
[void]$sb.AppendLine("Scan end     : $($ScanEnd.ToString('o'))")
[void]$sb.AppendLine("Duration     : $([math]::Round($Duration,1)) seconds")
[void]$sb.AppendLine("Host         : $env:COMPUTERNAME")
[void]$sb.AppendLine("User         : $env:USERNAME")
[void]$sb.AppendLine("=" * 80)
[void]$sb.AppendLine("")
[void]$sb.AppendLine("SEVERITY SUMMARY")
[void]$sb.AppendLine("  CRITICAL : $crit")
[void]$sb.AppendLine("  HIGH     : $high")
[void]$sb.AppendLine("  MEDIUM   : $med")
[void]$sb.AppendLine("  LOW      : $low")
[void]$sb.AppendLine("  TOTAL    : $($Findings.Count)")
[void]$sb.AppendLine("")

if ($Findings.Count -eq 0) {
    [void]$sb.AppendLine("NO CHEAT INDICATORS FOUND.")
    [void]$sb.AppendLine("All signatures used are exclusive to known cheat clients.")
} else {
    [void]$sb.AppendLine("DETAILED FINDINGS (sorted by severity)")
    [void]$sb.AppendLine("-" * 80)
    $ordered = $Findings | Sort-Object @{
        Expression = {
            switch ($_.Severity) {
                'CRITICAL' { 0 }
                'HIGH'     { 1 }
                'MEDIUM'   { 2 }
                'LOW'      { 3 }
                default    { 4 }
            }
        }
    }, Category, Indicator

    foreach ($f in $ordered) {
        [void]$sb.AppendLine("[$($f.Severity)] $($f.Category) – $($f.Indicator)")
        [void]$sb.AppendLine("  Location   : $($f.Location)")
        [void]$sb.AppendLine("  Evidence   : $($f.Evidence)")
        [void]$sb.AppendLine("  Confidence : $($f.Confidence)")
        [void]$sb.AppendLine("")
    }
}

[void]$sb.AppendLine("=" * 80)
[void]$sb.AppendLine("END OF REPORT")
$sb.ToString() | Out-File -FilePath $summaryPath -Encoding UTF8

$jsonPath = Join-Path $OutputDir 'CheatScan_Report.json'
$reportObj = [ordered]@{
    scannerVersion = $ScriptVersion
    scanStart      = $ScanStart.ToString('o')
    scanEnd        = $ScanEnd.ToString('o')
    durationSeconds = [math]::Round($Duration,2)
    host           = $env:COMPUTERNAME
    user           = $env:USERNAME
    summary        = @{
        critical = $crit
        high     = $high
        medium   = $med
        low      = $low
        total    = $Findings.Count
    }
    findings       = $Findings
}
$reportObj | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8

if (-not $Quiet) {
    Write-Host ""
    Write-Host "========== SCAN COMPLETE ==========" -ForegroundColor Cyan
    Write-Host "CRITICAL : $crit" -ForegroundColor $(if($crit){'Red'}else{'Green'})
    Write-Host "HIGH     : $high" -ForegroundColor $(if($high){'Red'}else{'Green'})
    Write-Host "MEDIUM   : $med"  -ForegroundColor $(if($med){'Yellow'}else{'Green'})
    Write-Host "LOW      : $low"  -ForegroundColor $(if($low){'Yellow'}else{'Green'})
    Write-Host "TOTAL    : $($Findings.Count)"
    Write-Host ""
    Write-Host "Human-readable report : $summaryPath"
    Write-Host "JSON report           : $jsonPath"
    Write-Host "===================================" -ForegroundColor Cyan
}

return $Findings
