[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) 'MagiciansReveal-Reports'),
    [string]$SignatureDirectory = (Join-Path (Get-Location) 'sigs'),
    [string]$UploadUri,
    [string]$ScanToken,
    [string]$ModsPath = (Join-Path $env:APPDATA '.minecraft\mods'),
    [switch]$BuildExe,
    [switch]$IncludeProcessMemory,
    [switch]$IncludeUserFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScannerVersion = '2.0.0'
$Started = [DateTime]::UtcNow
$ReportId = [guid]::NewGuid().ToString()
$Flags = [System.Collections.Generic.List[object]]::new()
$ModulesRun = [System.Collections.Generic.List[string]]::new()
$ModulesSkipped = [System.Collections.Generic.List[string]]::new()
$EnvironmentUntrusted = $false
$StopScan = $false
$SystemInfo = @{}
$RulesetVersion = 'builtin-2.0.0'
$KnownClients = @(); $KnownHosts = @(); $KnownStrings = @(); $KnownHashes = @{}

$moduleNames = @(
    "AutoCrystal","AutoHitCrystal","AutoAnchor","DoubleAnchor","SafeAnchor","AirAnchor",
    "AutoTotem","InventoryTotem","HoverTotem","AutoPot","AutoPotRefill","AutoArmor",
    "ShieldBreaker","ShieldDisabler","AutoMace","MaceSwap","StunSlam","AxeSpam",
    "TriggerBot","AimAssist","SilentAim","FakeLag","PingSpoof","FakeInv","WTap",
    "KeyPearl","AutoFirework","ElytraSwap","FastPlace","SelfDestruct","KillAura",
    "CrystalAura","AnchorAura","BedAura","ReachHack","HitboxExpand","PlayerESP",
    "XRayHack","ScaffoldWalk","AutoClicker","BowAim","Criticals","NoJumpDelay",
    "AutoDoubleHand","AutoNethPot","AutoDtap","AutoWeb","AnchorAction","AntiWeb",
    "AutoBreach","FreezePlayer","LootYeeter","AutoTPA","BaseFinder","AutoEat","AutoMine"
)

$clientSignatures = @(
    "com/slither/cyemer","com/slither/velaris","dev/lvstrng/aidsfuscator",
    "dev.krypton","skid.krypton","dev.virel","org.chainlibs",
    "meteordevelopment","meteorclient","liquidbounce","fdp-client","net.ccbluex",
    "doomsdayclient","novaclient","vape.gg","vapeclient","intent.store",
    "rise.today","aristois","impactclient","rusherhack","catlean",
    "AsteriaClient","PrestigeClient","GypsyClient","XenonClient","dqrkis.xyz",
    "WalksyOptimizer","imgui.gl3","imgui.glfw","jnativehook","phantom-refmap.json",
    "ClientPlayerInteractionManagerAccessor","LicenseCheckMixin","obfuscatedAuth",
    "sixtwo/","fivefive/","com/alan/clients","club/maxstats",
    "wtf/moonlight","me/zeroeightsix/kami","today/opai","xyz/greaj",
    "com/cheatbreaker","com/moonsworth","novoware","novoclient","pandaware",
    "moonClient","astolfo","futureClient","exhibition",
    "org/chainlibs/module/impl/modules"
    # NOTE: generic single-word or generic-pattern signatures (e.g. bare
    # "mixin/accessors", "orchard", "gypsy", "argon", "inertia", "konas")
    # were deliberately excluded here — they're either normal Mixin/Fabric
    # plumbing or common English words that show up in legitimate mod
    # packages, and matching on them alone produces false positives like
    # flagging ferritecore/moreculling/BadOptimizations for using accessors.
)

# Literal in-jar strings that show up in configs / decompiled fragments of
# cheat clients. Includes fullwidth-unicode evasion variants some clients
# use to dodge plain ASCII string scans.
$literalCheatStrings = @(
    "AutoCrystal","autocrystal","dontPlaceCrystal","dontBreakCrystal","healPotSlot",
    "canPlaceCrystalServer","AutoHitCrystal","AutoAnchor","anchortweaks","anchorMacro",
    "AutoTotem","InventoryTotem","HoverTotem","legittotem","AutoPot","speedPotSlot",
    "strengthPotSlot","AutoArmor","preventSwordBlockBreaking","preventSwordBlockAttack",
    "ShieldDisabler","ShieldBreaker","Breaking shield with axe...","AutoDoubleHand",
    "Failed to switch to mace after axe!","AutoMace","MaceSwap","SpearSwap","StunSlam",
    "findKnockbackSword","attackRegisteredThisClick","AimAssist","triggerbot",
    "Silent Rotations","FakeInv","swapBackToOriginalSlot","FakeLag","pingspoof",
    "fakePunch","mace_swap","quick_strike","macro_198","stun_slam","safe_anchor",
    "double_anchor","auto_pot_refill","walksy_optimizer","key_pearl","aim_assist",
    "auto_neth_pot","auto_dtap","trigger_bot","auto_web","AnchorAction",
    "Places two anchors for massive damage","REOFFHAND_TOTEM","webmacro","AntiWeb",
    "AutoWeb","selfdestruct","autoCrystalPlaceClock","AutoFirework","ElytraSwap",
    "NoJumpDelay","AuthBypass","obfuscatedAuth","LicenseCheckMixin","BaseFinder",
    "invsee","ItemExploit","FreezePlayer","LWFH Crystal","KeyPearl","LootYeeter",
    "FastPlace","AutoBreach","setBlockBreakingCooldown","getBlockBreakingCooldown",
    "onBlockBreaking","invokeDoAttack","invokeDoItemUse","invokeOnMouseButton",
    "POT_CHEATS","Entity.isGlowing","No Bounce","Place Delay","Break Delay",
    "Place Chance","Break Chance","Stop On Kill","Anti Weakness","Trigger Key",
    "Totem Slot","Silent Rotations","Rotation Speed","Easing Strength",
    "Glowstone Delay","Explode Delay","Explode Chance","Anchor Macro",
    "Reach Distance","Attack Delay","Breach Delay","Require Elytra",
    "Check Line of Sight","Require Crit","Predict Damage","Check Shield",
    "Predict Crystals","Blatant","Force Totem","Vertical Speed","Swap Speed",
    "Mace Priority","Min Totems","Min Pearls","Drop Interval","Loot Yeeter",
    "Horizontal Aim Speed","Web Delay","Holding Web","Hit Delay",
    "Require Hold Axe","placeInterval","breakInterval","stopOnKill",
    "activateOnRightClick","holdCrystal","KillAura","ClickAura","MultiAura",
    "ForceField","LegitAura","AimBot","AutoAim","AimLock","HeadSnap","CrystalAura",
    "AnchorAura","AnchorFill","AnchorPlace","BedAura","AutoBed","BedBomb","BedPlace",
    "BowAimbot","BowSpam","AutoBow","AutoCrit","CritBypass","AlwaysCrit",
    "ReachHack","ExtendReach","LongReach","HitboxExpand","AntiKB","NoKnockback",
    "GrimVelocity","GrimDisabler","VelocitySpoof","KBReduce","OffhandTotem",
    "TotemSwitch","Burrow","SelfTrap","HoleFiller","AntiSurround","AntiBurrow",
    "WTap","TargetStrafe","AutoGap","AutoPearl","FlyHack","CreativeFlight",
    "BoatFly","PacketFly","AirJump","SpeedHack","BHop","BunnyHop","AntiFall",
    "NoFallDamage","StepHack","FastClimb","AutoStep","HighStep","WaterWalk",
    "LiquidWalk","LavaWalk","NoSlow","NoSlowdown","NoWeb","NoSoulSand","WallHack",
    "ElytraSpeed","InstantElytra","ScaffoldWalk","FastBridge","BuildHelper",
    "AutoBridge","Nuker","InstantBreak","GhostHand","NoSwing","PlaceAssist",
    "AirPlace","AutoPlace","InstantPlace","PlayerESP","MobESP","ItemESP",
    "StorageESP","ChestESP","Tracers","NameTagsHack","XRayHack","OreFinder",
    "CaveFinder","OreESP","NewChunks","ChunkBorders","TunnelFinder","TargetHUD",
    "DoubleClicker","JitterClick","ButterflyClick","CPSBoost","ChestStealer",
    "InvManager","AutoSprint","AntiAFK","AutoRespawn","PopSwitch","FakeLatency",
    "FakePing","SpoofRotation","PositionSpoof","GameSpeed","SpeedTimer",
    "GrimBypass","VulcanBypass","MatrixBypass","AACBypass","VerusDisabler",
    "IntaveBypass","WatchdogBypass","PacketMine","PacketWalk","PacketSneak",
    "PacketCancel","PacketDupe","PacketSpam","SelfDestruct","HideClient",
    "SessionStealer","TokenLogger","TokenGrabber","DiscordToken","RemoteAccess",
    "ReverseShell","C2Server","Backdoor","KeyLogger","StashFinder","TrailFinder",
    "JNativeHook","GlobalScreen","NativeKeyListener","client-refmap.json",
    "cheat-refmap.json",
    # Fullwidth-unicode variants (common obfuscation trick to dodge ASCII scans)
    "ＡｕｔｏＣｒｙｓｔａｌ","ＡｕｔｏＨｉｔＣｒｙｓｔａｌ","ＡｕｔｏＡｎｃｈｏｒ",
    "ＤｏｕｂｌｅＡｎｃｈｏｒ","ＳａｆｅＡｎｃｈｏｒ","ＡｕｔｏＴｏｔｅｍ",
    "ＨｏｖｅｒＴｏｔｅｍ","ＩｎｖｅｎｔｏｒｙＴｏｔｅｍ","ＡｕｔｏＰｏｔ",
    "ＡｕｔｏＡｒｍｏｒ","ＳｈｉｅｌｄＤｉｓａｂｌｅｒ","ＡｕｔｏＤｏｕｂｌｅＨａｎｄ",
    "ＡｕｔｏＣｌｉｃｋｅｒ","ＡｕｔｏＭａｃｅ","ＭａｃｅＳｗａｐ","ＡｉｍＡｓｓｉｓｔ",
    "ＴｒｉｇｇｅｒＢｏｔ","Ｓｉｌｅｎｔ Ｒｏｔａｔｉｏｎｓ","ＦａｋｅＬａｇ",
    "Ｆａｋｅ Ｐｕｎｃｈ","Ａｎｔｉ Ｗｅｂ","ＡｕｔｏＷｅｂ","Ｗａｌｋｓｙ Ｏｐｔｉｍｉｚｅｒ",
    "ＥｌｙｔｒａＳｗａｐ","ＬＷＦＨ Ｃｒｙｓｔａｌ","ＫｅｙＰｅａｒｌ","Ｆａｓｔ Ｐｌａｃｅ",
    "Ａｕｔｏ Ｂｒｅａｃｈ"
)

# Known cheat-grade obfuscators / packers seen wrapping hacked-client jars
$knownCheatObfuscators = @{
    "Skidfuscator"   = @("dev/skidfuscator", "Skidfuscator", "skidfuscator.dev")
    "Paramorphism"   = @("Paramorphism", "paramorphism-", "dev/paramorphism")
    "Radon"          = @("ItzSomebody/Radon", "me/itzsomebody/radon", "Radon Obfuscator")
    "Caesium"        = @("sim0n/Caesium", "Caesium Obfuscator", "dev/sim0n/caesium")
    "Bozar"          = @("vimasig/Bozar", "Bozar Obfuscator", "com/bozar")
    "Branchlock"     = @("Branchlock", "branchlock.dev")
    "Binscure"       = @("Binscure", "com/binscure")
    "Qprotect"       = @("Qprotect", "QProtect", "mdma.dev/qprotect")
}

$allIndicators = $moduleNames + $clientSignatures


function Add-Flag {
    param([ValidateSet('Info','Warning','Detection')][string]$Tier,[string]$Id,[string]$Category,[string]$Title,[string]$Message,[hashtable]$Evidence,[string]$Module)
    $Flags.Add([pscustomobject]@{ id=$Id; tier=$Tier; category=$Category; title=$Title; message=$Message; evidence=$Evidence; timestamp=[DateTime]::UtcNow.ToString('o'); module=$Module; ruleset_version=$script:RulesetVersion })
}
function Invoke-Module {
    param([string]$Name,[scriptblock]$Body)
    if ($script:StopScan) { $ModulesSkipped.Add($Name); return }
    $ModulesRun.Add($Name)
    try { & $Body }
    catch { Add-Flag Info 'module_error' 'scanner' 'Module error' "Module '$Name' could not complete: $($_.Exception.Message)" @{ module=$Name } $Name }
}
function Read-TextFile { param([string]$Path)
    try { if (Test-Path -LiteralPath $Path -PathType Leaf) { Get-Content -LiteralPath $Path -Raw -ErrorAction Stop } } catch { $null }
}
function Get-NormalizedForms { param([string]$Text)
    $forms = [System.Collections.Generic.List[object]]::new(); if ([string]::IsNullOrWhiteSpace($Text)) { return $forms }
    $forms.Add([pscustomobject]@{ text=$Text; method='raw' })
    $full = $Text.Normalize([Text.NormalizationForm]::FormKC); if ($full -ne $Text) { $forms.Add([pscustomobject]@{text=$full;method='unicode_normalized'}) }
    $leet = $full.ToLowerInvariant().Replace('0','o').Replace('3','e').Replace('4','a').Replace('1','i').Replace('5','s').Replace('7','t').Replace('@','a').Replace('$','s')
    if ($leet -ne $full) { $forms.Add([pscustomobject]@{text=$leet;method='leet_normalized'}) }
    return $forms
}
function Get-Signatures {
    $script:RulesetVersion = 'builtin-2.0.0'
    if (Test-Path -LiteralPath (Join-Path $SignatureDirectory 'VERSION')) { $script:RulesetVersion = (Get-Content (Join-Path $SignatureDirectory 'VERSION') -Raw).Trim() }
    $script:KnownClients = @($clientSignatures); $script:KnownHosts = @(); $script:KnownStrings = @($moduleNames + $literalCheatStrings); $script:KnownHashes = @{}
    foreach ($name in 'known-clients.txt','obfuscated.txt','jvm-args.txt','known-hosts.txt') {
        $p=Join-Path $SignatureDirectory "strings\$name"; if (Test-Path $p) { $vals=Get-Content $p | Where-Object { $_ -and -not $_.Trim().StartsWith('#') } | ForEach-Object Trim
            if ($name -eq 'known-clients.txt') {$script:KnownClients += $vals}; if ($name -eq 'known-hosts.txt') {$script:KnownHosts += $vals}; if ($name -in 'obfuscated.txt','jvm-args.txt') {$script:KnownStrings += $vals} }
    }
    $csv=Join-Path $SignatureDirectory 'strings\known-hashes.csv'; if (Test-Path $csv) { foreach($r in (Import-Csv $csv)) { if($r.hash){$script:KnownHashes[$r.hash.ToLowerInvariant()]=$r} } }
    Add-Flag Info 'ruleset.loaded' 'signatures' 'Signature set loaded' "Ruleset $script:RulesetVersion loaded. Built-in supplied signatures plus external rules are active: $($KnownClients.Count) client names, $($KnownStrings.Count) strings, $($KnownHosts.Count) hosts, and $($KnownHashes.Count) hashes." @{ signature_directory=$SignatureDirectory; builtin_modules=$moduleNames.Count; builtin_clients=$clientSignatures.Count; builtin_literal_strings=$literalCheatStrings.Count; obfuscators=$knownCheatObfuscators.Keys } 'signatures'
}
function Get-ProcessCommandLineSafe { param($Process)
    try { (Get-CimInstance Win32_Process -Filter "ProcessId=$($Process.Id)" -ErrorAction Stop).CommandLine } catch { $null }
}
function Build-StandaloneExe {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $cmd = Get-Command Invoke-PS2EXE -ErrorAction SilentlyContinue
    if (-not $cmd) { Add-Flag Info 'packaging.ps2exe_unavailable' 'packaging' 'EXE packaging unavailable' 'The optional PS2EXE command was not found. Install the PS2EXE module, then rerun with -BuildExe.' @{required_command='Invoke-PS2EXE'} 'packaging'; return }
    $exe = Join-Path $OutputDirectory 'MagiciansRevealV2.exe'
    try { & $cmd.Source -InputFile $PSCommandPath -OutputFile $exe -NoConsole:$false -ErrorAction Stop; Add-Flag Info 'packaging.exe_created' 'packaging' 'Standalone EXE created' "Created $exe using PS2EXE." @{path=$exe} 'packaging' } catch { Add-Flag Warning 'packaging.exe_failed' 'packaging' 'EXE packaging failed' $_.Exception.Message @{} 'packaging' }
}
function Get-JarText {
    param([string]$Path)
    $zip=$null; $parts=[System.Collections.Generic.List[string]]::new()
    try { $zip=[IO.Compression.ZipFile]::OpenRead($Path); foreach($e in $zip.Entries | Where-Object {$_.FullName -match '\.(class|json|mf|properties|txt)$'}) { if($e.Length -gt 2MB){continue}; $ms=[IO.MemoryStream]::new();$e.Open().CopyTo($ms);$parts.Add([Text.Encoding]::UTF8.GetString($ms.ToArray()));$parts.Add([Text.Encoding]::ASCII.GetString($ms.ToArray()));$ms.Dispose() } } catch {} finally { if($zip){$zip.Dispose()} }; $parts -join "`n"
}
Invoke-Module 'minecraft_mods' {
    if(-not (Test-Path -LiteralPath $ModsPath -PathType Container)){ Add-Flag Info 'minecraft.mods_not_found' 'minecraft' 'Mods directory not found' "No mods directory was found at $ModsPath." @{path=$ModsPath} 'minecraft_mods'; return }
    $jars=Get-ChildItem -LiteralPath $ModsPath -Filter '*.jar' -File -ErrorAction SilentlyContinue
    Add-Flag Info 'minecraft.mods_inventory' 'minecraft' 'Minecraft mods inventoried' "Found $(@($jars).Count) JAR file(s) in the selected mods directory." @{path=$ModsPath;count=@($jars).Count} 'minecraft_mods'
    foreach($jar in $jars){ $hash=(Get-FileHash -LiteralPath $jar.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); if($KnownHashes.ContainsKey($hash)){ $r=$KnownHashes[$hash]; Add-Flag ([string]$r.tier) 'minecraft.known_mod_hash' 'minecraft' 'Known mod hash matched' "The JAR matches the signature catalog entry '$($r.cheat_name)'." @{path=$jar.FullName;sha256=$hash} 'minecraft_mods'; continue }; $txt=Get-JarText $jar.FullName; $hits=@(); foreach($s in ($KnownClients+$KnownStrings)){if($txt -match [regex]::Escape($s)){$hits+=$s}}; $hits=@($hits|Sort-Object -Unique); if($hits.Count -gt 0){Add-Flag Detection 'minecraft.jar_signature' 'minecraft' 'Signature found in Minecraft JAR' "Detected $($hits.Count) signature(s) in $($jar.Name): $([string]::Join(', ',($hits|Select-Object -First 12)))." @{path=$jar.FullName;sha256=$hash;matches=$hits} 'minecraft_mods'}; $classes=@([regex]::Matches($txt,'(?:^|[/\\])([Il1O0]{1,2})(?:[/\\])').Count); if($classes -ge 8){Add-Flag Warning 'minecraft.obfuscated_structure' 'obfuscation' 'Obfuscated JAR structure' "The JAR contains repeated single/confusion-character package segments; this is a heuristic and requires review." @{path=$jar.FullName;indicator_count=$classes} 'minecraft_mods'}; if($txt -match 'java/lang/Runtime' -and $txt -match 'getRuntime' -and $txt -match '(?i)exec'){Add-Flag Warning 'minecraft.runtime_exec' 'execution' 'Runtime command execution reference' "The JAR contains references consistent with Java Runtime.exec; this is not proof of malicious behavior." @{path=$jar.FullName} 'minecraft_mods'}; if($txt -match '(?i)https?://|java/net/URL|HttpURLConnection' -and $txt -match '(?i)openStream|download|POST'){Add-Flag Warning 'minecraft.network_loader' 'execution' 'Runtime network loader indicators' 'The JAR contains network and download-related references; review alongside other evidence.' @{path=$jar.FullName} 'minecraft_mods'} }
}
if($BuildExe){ Invoke-Module 'packaging' { Build-StandaloneExe } }

Get-Signatures
Invoke-Module 'system_snapshot' {
    $os=Get-CimInstance Win32_OperatingSystem; $cs=Get-CimInstance Win32_ComputerSystem
    $script:SystemInfo=@{ computer_name=$env:COMPUTERNAME; user=$env:USERNAME; os=$os.Caption; os_version=$os.Version; install_date=$os.InstallDate; manufacturer=$cs.Manufacturer; model=$cs.Model; powershell=$PSVersionTable.PSVersion.ToString() }
    Add-Flag Info 'system.snapshot' 'system' 'System snapshot collected' "Collected read-only system metadata for $($os.Caption) $($os.Version)." $script:SystemInfo 'system_snapshot'
}
Invoke-Module 'hardware_environment' {
    $ts=(Get-CimInstance Win32_ComputerSystem).BootupState
    $test=$false; try { $test=(bcdedit /enum '{current}' 2>$null) -match 'testsigning\s+Yes' } catch {}
    if($test){ Add-Flag Detection 'hw.test_signing_enabled' 'hardware' 'Test signing enabled' 'Windows test-signing mode is enabled; remaining modules were skipped because the environment is untrusted.' @{ boot_state=$ts } 'hardware_environment'; $script:EnvironmentUntrusted=$true; $script:StopScan=$true }
    foreach($v in Get-CimInstance Win32_Volume){ if($v.FileSystem -in 'FAT32','exFAT') { Add-Flag Info 'hw.no_journal_coverage' 'hardware' 'Volume lacks NTFS journal coverage' "$($v.DriveLetter) uses $($v.FileSystem), which does not provide NTFS USN coverage." @{ drive=$v.DriveLetter; filesystem=$v.FileSystem } 'hardware_environment' } }
}
Invoke-Module 'eventlog' {
    $since=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    foreach($log in 'System','Security','Application'){ try { $events=Get-WinEvent -FilterHashtable @{LogName=$log;Id=104,1102;StartTime=$since} -MaxEvents 100 -ErrorAction Stop; foreach($e in $events){ $tier=if($log -eq 'Application'){'Warning'}else{'Detection'}; Add-Flag $tier "eventlog.$log.cleared" 'eventlog' "$log log cleared" "Event $($e.Id) indicates the $log event log was cleared at $($e.TimeCreated.ToUniversalTime().ToString('o'))." @{log=$log;event_id=$e.Id;record_id=$e.RecordId;time=$e.TimeCreated.ToString('o')} 'eventlog' } } catch {} }
}
Invoke-Module 'registry_sweep' {
    $paths='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    foreach($p in $paths){ if(Test-Path $p){ foreach($x in (Get-ItemProperty $p).PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'}) { $val=[string]$x.Value; if($val -notmatch '\\Windows\\|\\Program Files\\'){ Add-Flag Warning 'registry.unusual_autorun' 'registry' 'Unusual autorun entry' "Autorun '$($x.Name)' points outside standard Windows or Program Files locations." @{path=$p;name=$x.Name;value=$val} 'registry_sweep' } } } }
}
Invoke-Module 'processes_and_jvm' {
    foreach($p in Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -match 'javaw?|launcher|powershell|pwsh|discord|chrome|msedge|brave|firefox'}) { $cmd=Get-ProcessCommandLineSafe $p; if(!$cmd){continue}; $text=($cmd | Out-String)
        foreach($c in $KnownClients){ foreach($f in Get-NormalizedForms $text){if($f.text -match [regex]::Escape($c)){Add-Flag Detection 'jvm.known_client' 'minecraft' 'Known client reference in live process' "Process $($p.ProcessName) contains a known client signature ($c) using $($f.method)." @{pid=$p.Id;process=$p.ProcessName;match=$c;normalization=$f.method} 'processes_and_jvm';break}} }
        if($p.ProcessName -match 'java|launcher' -and $text -match '(?i)-D(client\.brand|.*cheat.*)='){Add-Flag Detection 'jvm.cheat_property' 'minecraft' 'Suspicious JVM property' 'The live Minecraft JVM command line contains a cheat-related client property.' @{pid=$p.Id;command_line=$text.Trim()} 'processes_and_jvm'}
        if($p.ProcessName -match 'java|launcher' -and $text -match '(?i)-D(fly|speed|reach|killaura|xray|autocrystal)='){Add-Flag Detection 'jvm.cheat_feature_property' 'minecraft' 'Cheat-feature JVM property' 'The live Minecraft JVM command line contains a known cheat-feature property.' @{pid=$p.Id;command_line=$text.Trim()} 'processes_and_jvm'}
    }
}
Invoke-Module 'minecraft_profiles' {
    $roots=@($env:APPDATA,$env:LOCALAPPDATA) | Where-Object {$_}; $files=foreach($r in $roots){Get-ChildItem $r -Filter launcher_profiles.json -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 20}
    foreach($f in $files){$raw=Read-TextFile $f.FullName; foreach($c in $KnownClients){foreach($form in Get-NormalizedForms $raw){if($form.text -match [regex]::Escape($c)){Add-Flag Detection 'minecraft.known_client_profile' 'minecraft' 'Known client in launcher profile' "Launcher profile contains signature '$c'." @{path=$f.FullName;match=$c;normalization=$form.method} 'minecraft_profiles';break}}}}
    if(!$files){Add-Flag Info 'minecraft.profile_not_found' 'minecraft' 'Launcher profile not found' 'No standard launcher_profiles.json was found in the accessible user profile locations.' @{} 'minecraft_profiles'}
}
Invoke-Module 'file_signatures' {
    $targets=@($env:TEMP,(Join-Path $env:APPDATA '.minecraft'),(Join-Path $env:LOCALAPPDATA '.minecraft')) | Where-Object {$_ -and (Test-Path $_)}
    foreach($root in $targets){foreach($f in Get-ChildItem $root -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Length -lt 200MB} | Select-Object -First 3000){try{$sha=(Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant();if($KnownHashes.ContainsKey($sha)){ $r=$KnownHashes[$sha]; Add-Flag ([string]$r.tier) 'file.known_hash' 'signatures' 'Known signature hash matched' "File matches the supplied signature catalog: $($r.cheat_name)." @{path=$f.FullName;sha256=$sha;name=$r.cheat_name} 'file_signatures'}}catch{}}}
}
Invoke-Module 'network_context' {
    $proxy=(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).ProxyEnable -eq 1
    $vpn=(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceDescription -match 'TAP|WireGuard|VPN|Wintun'} | Select-Object -ExpandProperty Name)
    Add-Flag Info 'network.proxy_context' 'network' 'Proxy/VPN context' "Proxy enabled: $proxy; matching VPN adapters: $([string]::Join(', ',@($vpn)))." @{proxy_enabled=$proxy;vpn_adapters=@($vpn)} 'network_context'
}

$finished=[DateTime]::UtcNow
$report=[ordered]@{report_id=$ReportId;scanner_version=$ScannerVersion;ruleset_version=$RulesetVersion;started_at=$Started.ToString('o');finished_at=$finished.ToString('o');environment_untrusted=$EnvironmentUntrusted;system=$SystemInfo;flags=@($Flags);modules_run=@($ModulesRun);modules_skipped=@($ModulesSkipped);read_only=$true;consent_notice='This report was produced by a user-run, read-only scan. Findings require investigator review and are not an automated verdict.'}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$jsonPath=Join-Path $OutputDirectory "MagiciansReveal-$ReportId.json"; $txtPath=Join-Path $OutputDirectory "MagiciansReveal-$ReportId.txt"
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$lines=@("MagiciansReveal V$ScannerVersion","Report: $ReportId","Ruleset: $RulesetVersion","Environment untrusted: $EnvironmentUntrusted",'')
foreach($tier in 'Detection','Warning','Info'){ $lines += "[$tier]"; foreach($f in $Flags | Where-Object tier -eq $tier){$lines += "- $($f.title): $($f.message)"};$lines += '' }
$lines | Set-Content -LiteralPath $txtPath -Encoding UTF8
if($UploadUri){try{$headers=@{'Authorization'="Bearer $ScanToken"};Invoke-RestMethod -Uri $UploadUri -Method Post -Headers $headers -ContentType 'application/json' -Body ($report|ConvertTo-Json -Depth 12) -ErrorAction Stop | Out-Null;Add-Content $txtPath "Uploaded successfully to $UploadUri"}catch{Add-Content $txtPath "Upload failed; local report retained. $($_.Exception.Message)"}}
Write-Host "Scan complete. JSON: $jsonPath" -ForegroundColor Green
Write-Host "Summary: $txtPath"
Write-Host "Findings: $($Flags.Count) | Detection: $(($Flags|? tier -eq Detection).Count) | Warning: $(($Flags|? tier -eq Warning).Count)"
