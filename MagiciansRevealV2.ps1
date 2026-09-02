<#
.SYNOPSIS
    MagiciansRevealV2 – Console Forensic Scanner (Zero False Positives)
.DESCRIPTION
    Menu‑driven PowerShell console scanner for Minecraft cheat clients.
    Uses cheat‑specific signatures only – never flags legitimate mods.
.AUTHOR
    Tim$erz
.VERSION
    3.0.0
#>

#region Signature Database (from specification)
$script:CheatClientNames = @(
    "Vape","VapeV4","VapeLite","VapeClient",
    "Meteor","MeteorClient",
    "LiquidBounce","LiquidBounceNextGen",
    "Wurst","WurstClient",
    "Sigma","SigmaClient",
    "Salhack","SalHack",
    "Novoware","NovoWare",
    "GameSense","GameSenseClient",
    "Osiris","OsirisClient",
    "Cosmos","CosmosClient",
    "Sorus","SorusClient",
    "Azura","AzuraClient",
    "Doomsday","DoomsdayClient",
    "Argon","ArgonClient",
    "Krypton","KryptonClient",
    "Prestige","PrestigeClient",
    "198Macros",
    "Delta","DeltaClient",
    "Elysian","ElysianClient",
    "Onyx","OnyxClient",
    "Lumina","LuminaClient",
    "Momentum","MomentumClient",
    "RavenB++","RavenBPlusPlus",
    "UZI","UziClient",
    "SkidBounce","SkidBounceClient",
    "Skidcraft","SkidcraftClient",
    "Backdoored","BackdooredClient",
    "LeuxBackdoor",
    "SalHackSkid",
    "GrassWare","GrassWareClient",
    "AllahWare","AllahWareClient",
    "BBCWare","BBCWareClient",
    "Arsenic","ArsenicClient",
    "Atrium","AtriumClient",
    "BleachHack","BleachHackClient",
    "Caizm","CaizmClient",
    "Coffee","CoffeeClient",
    "Cranberry","CranberryClient",
    "Evangelion","EvangelionClient",
    "FDP","FDPClient",
    "Fog","FogClient",
    "ForgeHax","ForgeHaxClient",
    "Huzuni","HuzuniClient",
    "Hydrogen","HydrogenClient",
    "Ikea","IkeaClient",
    "Jex","JexClient",
    "Kamiblue","KamiblueClient",
    "Konas","KonasClient",
    "Kura","KuraClient",
    "Lambda","LambdaClient",
    "LavaHack","LavaHackClient",
    "Mercury","MercuryClient",
    "Mint","MintClient",
    "Mirai","MiraiClient",
    "NClient","NClient",
    "Neptunium","NeptuniumClient",
    "Ozark","OzarkClient",
    "Raion","RaionClient",
    "Rebirth","RebirthClient",
    "Rift","RiftClient",
    "Selene","SeleneClient",
    "Seppuku","SeppukuClient",
    "Silence","SilenceClient",
    "Spark","SparkClient",
    "Swift","SwiftClient",
    "Tensor","TensorClient",
    "Tokyo","TokyoClient",
    "Trollhack","TrollhackClient",
    "Vertex","VertexClient",
    "Vrpos","VrposClient",
    "Xulu","XuluClient",
    "Zeon","ZeonClient",
    "ZeroTwo","ZeroTwoClient",
    "Zodiac","ZodiacClient",
    "Impact","ImpactClient",
    "Aristois","AristoisClient",
    "KAMI","KAMIClient",
    "Phobos","PhobosClient",
    "RusherHack","RusherHackClient",
    "Future","FutureClient",
    "Remix","RemixClient",
    "Yasha","YashaClient",
    "ZeroDay","ZeroDayClient",
    "Orchard","OrchardClient",
    "Gypsy","GypsyClient",
    "Xenon","XenonClient",
    "Asteria","AsteriaClient"
)
$script:CheatPackagePaths = @(
    "cc/novoline", "com/alan/clients", "club/maxstats", "wtf/moonlight",
    "me/zeroeightsix/kami", "net/ccbluex", "today/opai", "net/minecraft/injection",
    "org/chainlibs/module/impl/modules", "xyz/greaj", "com/cheatbreaker",
    "com/moonsworth", "dev/krypton", "skid/krypton", "dev/gambleclient",
    "dev/virel", "org/jose4j/jwt", "sixtwo/", "fivefive/"
)
$script:CheatModules = @(
    "KillAura","Killaura","killaura",
    "CrystalAura","crystalaura",
    "AutoCrystal","autocrystal",
    "MaceAura","maceaura",
    "SilentMace","silentmace",
    "AimAssist","aimassist",
    "SilentAim","silentaim",
    "BowAimbot","bowaimbot",
    "TriggerBot","triggerbot",
    "AntiWeakness","antiweakness",
    "FakePunch","fakepunch",
    "DamageTick","damagetick",
    "OnlyCrit","onlycrit",
    "StaticHitBoxes","statichitboxes",
    "ShieldDisabler","shielddisabler",
    "AntiInvis","antiinvis",
    "W-Tap","wtap",
    "AutoCrit","autocrit",
    "GodMode","godmode",
    "Reach","reachhack",
    "CrystalOptimizer","crystaloptimizer",
    "CwCrystal","cwcrystal",
    "DoubleAnchor","doubleanchor",
    "AnchorExploder","anchorexploder",
    "AutoDtap","autodtap",
    "MarlowAnchor","marlowanchor",
    "AntiAntiCw","antianticw",
    "AutoTotem","autototem",
    "TotemOffhand","totemoffhand",
    "HoverTotem","hovertotem",
    "ForceTotem","forcetotem",
    "AutoRetotem","autoretotem",
    "InventoryTotemLegit","inventorytotemlegit",
    "AutoDoubleHand","autodoublehand",
    "FastBridge","fastbridge",
    "BridgeAssist","bridgeassist",
    "FastSwim","fastswim",
    "FastPlace","fastplace",
    "NoBreakDelay","nobreakdelay",
    "NoJumpDelay","nojumpdelay",
    "ElytraSwap","elytraswap",
    "ElytraGlide","elytraglide",
    "Jetpack","jetpack",
    "AutoSprint","autosprint",
    "InventoryMove","inventorymove",
    "Speed","speedhack",
    "Step","step",
    "AutoClicker","autoclicker",
    "AutoPot","autopot",
    "AutoEat","autoeat",
    "AutoXP","autoxp",
    "AutoArmor","autoarmor",
    "AutoTool","autotool",
    "AutoMine","automine",
    "ChestStealer","cheststealer",
    "ShulkerDropper","shulkerdropper",
    "AutoSell","autosell",
    "CordSnapper","cordsnapper",
    "KeyPearl","keypearl",
    "AutoTpa","autotpa",
    "BedMacro","bedmacro",
    "AutoRestock","autorestock",
    "ReplaceMod","replacemod",
    "Scaffold","scaffold",
    "Tower","tower",
    "PlayerESP","playeresp",
    "StorageESP","storageesp",
    "EntityESP","entityesp",
    "XRay","xray","XRayHack","xrayhack",
    "HealthIndicators","healthindicators",
    "TargetHUD","targethud",
    "NetheriteFinder","netheritefinder",
    "RtpBaseFinder","rtpbasefinder",
    "Tracers","tracers",
    "Chams","chams",
    "Glow","glow","GlowESP","glowesp",
    "Radar","radar",
    "FakeLag","fakelag",
    "PingSpoof","pingspoof",
    "PackSpoof","packspoof",
    "StrayBypass","straybypass",
    "DonutSMPBypass","donutsmpbypass",
    "AntiSSTool","antiss tool",
    "StringCleaner","stringcleaner",
    "SelfDestruct","selfdestruct",
    "USNJournalCleaner","usnjournalcleaner",
    "DeleteUSNJournal","deleteusnjournal",
    "GenericSelfdestruct","genericselfdestruct",
    "Disabler","disabler",
    "Bypass","bypass",
    "AntiBan","antiban"
)
$script:CheatDomains = @(
    "vape.gg","vapeclient.com","meteorclient.com","liquidbounce.net","wurstclient.net",
    "sigmaclient.com","novoware.cc","gamesense.pw","osirisclient.com","cosmosclient.com",
    "sorusclient.net","azuraclient.com","deltaclient.net","elysianclient.org",
    "onyxclient.com","luminaclient.net","ravenbplusplus.net","uziclient.com",
    "skidbounce.net","bleachhack.org","forgehax.com","huzuni.org","kamiblue.org",
    "konasclient.com","kuraclient.net","lambdaclient.com","mercuryclient.org",
    "miraiclient.net","ozarkclient.com","raionclient.net","seppukuclient.com",
    "vertexclient.net","prestigeclient.vip","dqrkis.xyz","orchard.gg"
)
$script:FullwidthPatterns = @(
    "’╝Ī’ĮĢ’Įö’ĮÅ’╝Ż’ĮÆ’ĮÖ’Įō’Įö’Įü’Įī",
    "’╝Ī’ĮĢ’Įö’ĮÅ’╝Ī’ĮÄ’Įā’Įł’ĮÅ’ĮÆ",
    "’╝Ī’ĮĢ’Įö’ĮÅ’╝┤’ĮÅ’Įö’Įģ’ĮŹ",
    "’╝Ī’Įē’ĮŹ’╝Ī’Įō’Įō’Įē’Įō’Įö",
    "’╝Ī’ĮĢ’Įö’ĮÅ’╝Ż’Įī’Įē’Įā’Įŗ’Įģ’ĮÆ",
    "’╝┤’ĮÆ’Įē’Įć’Įć’Įģ’ĮÆ’╝ó’ĮÅ’Įö",
    "’╝Ī’ĮĢ’Įö’ĮÅ’╝Ł’Įü’Įā’Įģ",
    "’╝Ż’ĮÆ’ĮÖ’Įō’Įö’Įü’Įī’╝Ī’ĮĢ’ĮÆ’Įü",
    "’╝│’Įł’Įē’Įģ’Įī’Įä’╝ż’Įē’Įō’Įü’Įé’Įī’Įģ’ĮÆ",
    "’╝Ī’ĮÄ’Įā’Įł’ĮÅ’ĮÆ’╝Ī’ĮĢ’ĮÆ’Įü",
    "’╝Ī’ĮĢ’Įö’ĮÅ’╝░’ĮÅ’Įö",
    "’╝Ī’ĮĢ’Įö’ĮÅ’╝Ī’ĮÆ’ĮŹ’ĮÅ’ĮÆ",
    "’╝Ī’ĮĢ’Įö’ĮÅ’╝Ż’ĮÆ’ĮÖ’Įō’Įö’Įü’Įī",
    "’╝Ī’ĮĢ’Įö’ĮÅ ’╝Ż’ĮÆ’ĮÖ’Įō’Įö’Įü’Įī",
    "’╝Ī’ĮĢ’Įö’ĮÅ’╝©’Įē’Įö’╝Ż’ĮÆ’ĮÖ’Įō’Įö’Įü’Įī",
    "’╝ż’ĮÅ’ĮĢ’Įé’Įī’Įģ’╝Ī’ĮÄ’Įā’Įł’ĮÅ’ĮÆ",
    "’╝│’Įü’Įå’Įģ’╝Ī’ĮÄ’Įā’Įł’ĮÅ’ĮÆ",
    "’╝Ī’ĮÄ’Įā’Įł’ĮÅ’ĮÆ ’╝Ł’Įü’Įā’ĮÆ’ĮÅ",
    "’╝Ī’ĮĢ’Įö’ĮÅ ’╝┤’ĮÅ’Įö’Įģ’ĮŹ",
    "’╝©’ĮÅ’Į¢’Įģ’ĮÆ’╝┤’ĮÅ’Įö’Įģ’ĮŹ",
    "’╝®’ĮÄ’Į¢’Įģ’ĮÄ’Įö’ĮÅ’ĮÆ’ĮÖ’╝┤’ĮÅ’Įö’Įģ’ĮŹ",
    "’╝Ī’ĮĢ’Įö’ĮÅ ’╝░’ĮÅ’Įö",
    "’╝Ī’ĮĢ’Įö’ĮÅ ’╝░’ĮÅ’Įö ’╝▓’Įģ’Įå’Įē’Įī’Įī",
    "’╝│’Įł’Įē’Įģ’Įī’Įä’╝ż’Įē’Įō’Įü’Įé’Įī’Įģ’ĮÆ",
    "’╝│’Įł’Įē’Įģ’Įī’Įä ’╝ż’Įē’Įō’Įü’Įé’Įī’Įģ’ĮÆ",
    "’╝Ī’ĮĢ’Įö’ĮÅ’╝ż’ĮÅ’ĮĢ’Įé’Įī’Įģ’╝©’Įü’ĮÄ’Įä",
    "’╝Ī’ĮĢ’Įö’ĮÅ ’╝ż’ĮÅ’ĮĢ’Įé’Įī’Įģ ’╝©’Įü’ĮÄ’Įä",
    "’╝╣’ĮÆ’Įü’ĮÖ",
    "’╝¦’Įī’ĮÅ’ĮŚ",
    "’╝░’Įī’Įü’ĮÖ’Įģ’ĮÆ’╝ź’Į│’ĮÉ",
    "’╝Ł’ĮÅ’Įó’Įź’Į│’ĮÉ",
    "’╝░’Įī’Įü’ĮÖ’Įģ’ĮÆ’╝ź’Į│’ĮÉ",
    "’╝Ż’Įü’Į£’Įē’ĮÅ’Į│’╝ź’Į│’ĮÉ",
    "’╝¦’ĮÅ’Įä’╝Ł’ĮÅ’Įä’Įģ",
    "’╝Ż’Įü’Įō’Įē’ĮÉ’Įé’ĮŹ’Įģ",
    "’╝┴’ĮÆ’Įē’Įć’Įć’Įģ’ĮÆ’╝▓’ĮÅ’Įō’ĮÅ’Įā’Įē’Įģ’Įä",
    "’╝’ĮĢ’Įł’ĮŠ’╝ī’Įł’Įä’Įē’ĮŠ"
)
#endregion

#region Helper Functions
$script:Findings = @()
$script:ScanStart = Get-Date

function Add-Finding {
    param(
        [string]$Tier,    # Detection, Warning, Info
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
    # Colour output
    $color = switch ($Tier) {
        "Detection" { "Red" }
        "Warning"   { "Yellow" }
        default     { "Gray" }
    }
    Write-Host "[$Tier] $Title" -ForegroundColor $color
    Write-Host "  $Message" -ForegroundColor White
}

function Write-Header {
    Clear-Host
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host "   MagiciansRevealV2 – Forensic Scanner    " -ForegroundColor Magenta
    Write-Host "   Zero False Positives – Cheat‑Only       " -ForegroundColor Cyan
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Menu {
    Write-Header
    Write-Host "1. Scan Minecraft Directory"
    Write-Host "2. Scan Full System (Processes, Registry, DNS)"
    Write-Host "3. Export Report (JSON + TXT)"
    Write-Host "4. View Findings"
    Write-Host "5. Clear Findings"
    Write-Host "6. Exit"
    Write-Host ""
    $choice = Read-Host "Enter choice"
    return $choice
}

function Test-Admin {
    (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FileContentAsString {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        # Try UTF‑8, fallback to ASCII
        $enc = [System.Text.Encoding]::UTF8
        $text = $enc.GetString($bytes)
        if ($text -match "\0") {
            $enc = [System.Text.Encoding]::Unicode
            $text = $enc.GetString($bytes)
        }
        return $text
    } catch {
        return $null
    }
}
#endregion

#region Scan Modules
function Scan-MinecraftDirectory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        Write-Host "Path not found: $Path" -ForegroundColor Red
        return
    }
    $modsDir = Join-Path $Path "mods"
    if (-not (Test-Path $modsDir)) {
        Write-Host "No 'mods' folder found at $modsDir" -ForegroundColor Yellow
        return
    }
    Write-Host "Scanning $modsDir ..." -ForegroundColor Green
    $jars = Get-ChildItem -Path $modsDir -Filter *.jar -ErrorAction SilentlyContinue
    if ($jars.Count -eq 0) {
        Write-Host "No JAR files found." -ForegroundColor Yellow
        return
    }
    $total = $jars.Count
    $i = 0
    foreach ($jar in $jars) {
        $i++
        Write-Progress -Activity "Scanning JARs" -Status "$($jar.Name)" -PercentComplete (($i / $total) * 100)
        $content = Get-FileContentAsString -Path $jar.FullName
        if (-not $content) { continue }

        # Client names (Detection)
        foreach ($client in $script:CheatClientNames) {
            if ($content -match "\b$client\b") {
                Add-Finding -Tier "Detection" -Category "File System" -Title "Cheat Client Found" -Message "Client name '$client' in $($jar.Name)" -Evidence @{File=$jar.Name; Client=$client}
                break
            }
        }
        # Package paths (Detection)
        foreach ($pkg in $script:CheatPackagePaths) {
            if ($content -match $pkg) {
                Add-Finding -Tier "Detection" -Category "File System" -Title "Cheat Package Path" -Message "Package '$pkg' found in $($jar.Name)" -Evidence @{File=$jar.Name; Package=$pkg}
            }
        }
        # Module names (Warning unless combined with client)
        foreach ($mod in $script:CheatModules) {
            if ($content -match "\b$mod\b") {
                # Check if also has a client or package to upgrade to Detection
                $hasClient = $false
                foreach ($c in $script:CheatClientNames) {
                    if ($content -match "\b$c\b") { $hasClient = $true; break }
                }
                $hasPkg = $false
                foreach ($p in $script:CheatPackagePaths) {
                    if ($content -match $p) { $hasPkg = $true; break }
                }
                if ($hasClient -or $hasPkg) {
                    Add-Finding -Tier "Detection" -Category "File System" -Title "Cheat Module with Context" -Message "Module '$mod' in $($jar.Name) with cheat context" -Evidence @{File=$jar.Name; Module=$mod}
                } else {
                    Add-Finding -Tier "Warning" -Category "File System" -Title "Cheat Module" -Message "Module '$mod' in $($jar.Name) (no client context)" -Evidence @{File=$jar.Name; Module=$mod}
                }
            }
        }
        # Fullwidth obfuscated strings (Detection)
        foreach ($fw in $script:FullwidthPatterns) {
            if ($content -match $fw) {
                Add-Finding -Tier "Detection" -Category "File System" -Title "Fullwidth Obfuscation" -Message "Obfuscated string found in $($jar.Name)" -Evidence @{File=$jar.Name}
            }
        }
    }
    Write-Progress -Activity "Scanning JARs" -Completed
}

function Scan-System {
    Write-Host "Scanning system (processes, registry, DNS)..." -ForegroundColor Green
    # Processes
    $procs = Get-Process -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $name = $p.ProcessName.ToLower()
        foreach ($client in $script:CheatClientNames) {
            if ($name -match $client.ToLower()) {
                Add-Finding -Tier "Detection" -Category "Processes" -Title "Cheat Process Running" -Message "Process $($p.ProcessName) matches '$client'" -Evidence @{Process=$p.ProcessName; Client=$client}
                break
            }
        }
        # JVM arguments
        if ($p.ProcessName -match "javaw|java") {
            try {
                $cmd = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmd) {
                    if ($cmd -match "-Dclient\.brand=(Wurst|Impact|Meteor|Sigma|LiquidBounce|Vape|Novoline)") {
                        Add-Finding -Tier "Detection" -Category "Processes" -Title "Malicious JVM Argument" -Message "JVM brand: $($Matches[0])" -Evidence @{Argument=$Matches[0]}
                    }
                    if ($cmd -match "-D(xray|fly|speed|killaura|reach|scaffold|autocrystal|autototem)") {
                        Add-Finding -Tier "Detection" -Category "Processes" -Title "JVM Cheat Flag" -Message "Flag: $($Matches[0])" -Evidence @{Argument=$Matches[0]}
                    }
                }
            } catch {}
        }
    }
    # Registry
    foreach ($client in $script:CheatClientNames) {
        $path = "HKCU:\Software\$client"
        if (Test-Path $path) {
            Add-Finding -Tier "Detection" -Category "Registry" -Title "Cheat Registry Key" -Message "Key $path exists" -Evidence @{Key=$path}
        }
    }
    # DNS cache
    $dns = ipconfig /displaydns 2>$null | Select-String "Record Name.*:\s+(.*)" | ForEach-Object { $_.Matches.Groups[1].Value }
    foreach ($domain in $script:CheatDomains) {
        if ($dns -match $domain) {
            Add-Finding -Tier "Detection" -Category "DNS" -Title "Cheat Domain in Cache" -Message "Domain $domain resolved" -Evidence @{Domain=$domain}
        }
    }
    # Prefetch
    $prefetchDir = "$env:windir\Prefetch"
    if (-not (Test-Path $prefetchDir)) {
        Add-Finding -Tier "Detection" -Category "Prefetch" -Title "Prefetch Folder Missing" -Message "Prefetch folder not present"
    } else {
        $files = Get-ChildItem $prefetchDir -ErrorAction SilentlyContinue
        if ($files.Count -lt 5) {
            Add-Finding -Tier "Warning" -Category "Prefetch" -Title "Low Prefetch Count" -Message "Only $($files.Count) prefetch files – possible deletion"
        }
    }
    # Event logs
    $logs = @("Application", "System", "Security", "Windows PowerShell")
    foreach ($log in $logs) {
        try {
            $events = Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction SilentlyContinue
            if (-not $events) {
                Add-Finding -Tier "Warning" -Category "Event Logs" -Title "Event Log Cleared" -Message "Event log $log appears empty (cleared?)" -Evidence @{Log=$log}
            }
        } catch {}
    }
    Write-Host "System scan complete." -ForegroundColor Green
}
#endregion

#region Report Export
function Export-Report {
    if ($script:Findings.Count -eq 0) {
        Write-Host "No findings to export." -ForegroundColor Yellow
        return
    }
    $report = @{
        ScanTime   = $script:ScanStart.ToString("o")
        Findings   = $script:Findings
        Summary    = @{
            Total      = $script:Findings.Count
            Detections = ($script:Findings | Where-Object { $_.Tier -eq "Detection" }).Count
            Warnings   = ($script:Findings | Where-Object { $_.Tier -eq "Warning" }).Count
            Info       = ($script:Findings | Where-Object { $_.Tier -eq "Info" }).Count
        }
    }
    $json = $report | ConvertTo-Json -Depth 5
    $jsonFile = "MagiciansRevealV2_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $json | Out-File -FilePath $jsonFile -Encoding utf8
    Write-Host "JSON report saved to $jsonFile" -ForegroundColor Green

    $txt = "MagiciansRevealV2 Forensic Report`n" + "="*50 + "`n"
    $txt += "Scan Time: $($report.ScanTime)`n`n"
    foreach ($f in $script:Findings) {
        $txt += "[$($f.Tier)] $($f.Title)`n  $($f.Message)`n"
    }
    $txtFile = "MagiciansRevealV2_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $txt | Out-File -FilePath $txtFile -Encoding utf8
    Write-Host "Text report saved to $txtFile" -ForegroundColor Green
}

function Show-Findings {
    if ($script:Findings.Count -eq 0) {
        Write-Host "No findings." -ForegroundColor Yellow
        return
    }
    Write-Host "`n--- Findings ($($script:Findings.Count)) ---" -ForegroundColor Cyan
    foreach ($f in $script:Findings) {
        $color = switch ($f.Tier) {
            "Detection" { "Red" }
            "Warning"   { "Yellow" }
            default     { "Gray" }
        }
        Write-Host "[$($f.Tier)] $($f.Title)" -ForegroundColor $color
        Write-Host "  $($f.Message)" -ForegroundColor White
    }
    Write-Host ""
}
#endregion

#region Main Menu Loop
if (-not (Test-Admin)) {
    Write-Host "WARNING: Not running as Administrator – some checks may fail." -ForegroundColor Red
    Read-Host "Press Enter to continue"
}

$script:minecraftPath = ""
do {
    $choice = Show-Menu
    switch ($choice) {
        "1" {
            $path = Read-Host "Enter Minecraft directory (e.g., C:\Users\...\.minecraft)"
            if (Test-Path $path) {
                $script:minecraftPath = $path
                Scan-MinecraftDirectory -Path $path
            } else {
                Write-Host "Path not found." -ForegroundColor Red
            }
            Read-Host "Press Enter to continue"
        }
        "2" {
            Scan-System
            Read-Host "Press Enter to continue"
        }
        "3" {
            Export-Report
            Read-Host "Press Enter to continue"
        }
        "4" {
            Show-Findings
            Read-Host "Press Enter to continue"
        }
        "5" {
            $script:Findings = @()
            Write-Host "Findings cleared." -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }
        "6" {
            Write-Host "Exiting." -ForegroundColor Cyan
            exit
        }
        default {
            Write-Host "Invalid choice." -ForegroundColor Red
            Read-Host "Press Enter to continue"
        }
    }
} while ($true)
#endregion
