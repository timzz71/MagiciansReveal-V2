<#
.SYNOPSIS
    MagiciansRevealV2 – Console Forensic Scanner
.DESCRIPTION
    Menu-driven PowerShell scanner for Minecraft cheat clients.
    Uses signature matching, fullwidth detection, obfuscation analysis and runtime checks.
.AUTHOR
    Magician
.VERSION
    3.0.1
#>

#region Initialisation
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
Clear-Host
Write-Host "Running MagiciansRevealV2 v3.0.2 from: $($MyInvocation.MyCommand.Path)" -ForegroundColor DarkGray

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
Write-Host "                Forensic Scanner" -ForegroundColor DarkGray
Write-Host ""
Write-Host ("━" * 76) -ForegroundColor Red
Write-Host ""
#endregion

#region Helper Functions
if (-not ('MagiciansReveal.NativeMemory' -as [type])) {
Add-Type @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public static class MagiciansRevealNativeMemory {
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr read);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
  [StructLayout(LayoutKind.Sequential)] struct MBI { public IntPtr Base; public IntPtr Alloc; public uint Protect; public UIntPtr Size; public uint State; public uint Type; }
  const uint VM_READ=0x10, QUERY=0x400, COMMIT=0x1000, GUARD=0x100, NOACCESS=1;
  static bool Readable(uint p) { p &= 0xff; return p!=NOACCESS && p!=0x01 && p!=0x02 && p!=0x10; }
  public static string[] Scan(int pid, string[] needles, int maxRegionMB) {
    var found=new HashSet<string>(StringComparer.OrdinalIgnoreCase); var h=OpenProcess(VM_READ|QUERY,false,pid); if(h==IntPtr.Zero)return new string[0];
    try { IntPtr a=IntPtr.Zero; long cap=(long)maxRegionMB*1024*1024;
      while(true) { MBI m; if(VirtualQueryEx(h,a,out m,(IntPtr)Marshal.SizeOf(typeof(MBI)))==IntPtr.Zero)break; long n=(long)m.Size; if(n<=0)break;
        if(m.State==COMMIT && (m.Protect&GUARD)==0 && Readable(m.Protect) && n<=cap) {
          int chunk=1024*1024; byte[] b=new byte[chunk]; for(long off=0;off<n;off+=chunk) { int want=(int)Math.Min(chunk,n-off); IntPtr got; if(!ReadProcessMemory(h,IntPtr.Add(m.Base,(int)Math.Min(off,int.MaxValue)),b,want,out got))continue; int count=got.ToInt64()>int.MaxValue?0:(int)got.ToInt64(); if(count==0)continue;
            string s=Encoding.ASCII.GetString(b,0,count); foreach(string x in needles) if(!String.IsNullOrWhiteSpace(x)&&s.IndexOf(x,StringComparison.OrdinalIgnoreCase)>=0)found.Add(x); }
        } a=IntPtr.Add(m.Base,(int)Math.Min(n,int.MaxValue)); if(a==IntPtr.Zero)break;
      }
    } finally { CloseHandle(h); } return new List<string>(found).ToArray();
  }
}
'@
}

function Scan-JavaMemory {
    param([int]$ProcessId)
    Write-Host "Scanning readable memory for Java PID $ProcessId..." -ForegroundColor Green
    try {
        $hits = [MagiciansRevealNativeMemory]::Scan($ProcessId, [string[]]$cheatStrings, 100)
        foreach ($hit in $hits) {
            Add-Finding -Tier "Detection" -Category "Process Memory" -Title "Signature Found in Java Memory" `
                -Message "'$hit' found in readable memory of PID $ProcessId" -Evidence @{PID=$ProcessId; String=$hit}
        }
        if ($hits.Count -eq 0) { Write-Host "No configured signatures found in readable memory." -ForegroundColor Yellow }
    } catch { Write-Host "Memory scan failed for PID ${ProcessId}: $($_.Exception.Message)" -ForegroundColor Red }
}

function Test-Admin {
    (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Header {
    Clear-Host
    Write-Host $Banner -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host ("━" * 76) -ForegroundColor Red
    Write-Host ""
}

function Show-Menu {
    Write-Header
    Write-Host "1. Scan Minecraft Directory (mods folder)" -ForegroundColor Green
    Write-Host "2. Scan Full System (Processes, Registry, DNS, JVM)" -ForegroundColor Yellow
    Write-Host "3. Export Report (JSON + TXT)" -ForegroundColor Magenta
    Write-Host "4. View Current Findings" -ForegroundColor Cyan
    Write-Host "5. Clear All Findings" -ForegroundColor Red
    Write-Host "6. Exit" -ForegroundColor Gray
    Write-Host ""
    $choice = Read-Host "Enter choice"
    return $choice
}

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
        "Detection" { "Red" }
        "Warning"   { "Yellow" }
        default     { "Gray" }
    }
    Write-Host "[$Tier] $Title" -ForegroundColor $color
    Write-Host "  $Message" -ForegroundColor White
}

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

    $txt = "MagiciansRevealV2 Forensic Report`n" + ("=" * 50) + "`n"
    $txt += "Scan Time: $($report.ScanTime)`n`n"
    foreach ($f in $script:Findings) {
        $txt += "[$($f.Tier)] $($f.Title)`n  $($f.Message)`n"
    }
    $txtFile = "MagiciansRevealV2_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $txt | Out-File -FilePath $txtFile -Encoding utf8
    Write-Host "Text report saved to $txtFile" -ForegroundColor Green
}
#endregion

#region Signature Databases
# Only ASCII-safe strings – fullwidth detection is handled by regex below
$suspiciousPatterns = @(
    "AimAssist", "AnchorTweaks", "AutoAnchor", "AutoCrystal", "AutoDoubleHand",
    "AutoHitCrystal", "AutoPot", "AutoTotem", "AutoArmor", "InventoryTotem",
    "LegitTotem", "PingSpoof", "SelfDestruct", "ShieldBreaker", "TriggerBot",
    "AxeSpam", "WebMacro", "FastPlace", "WalksyOptimizer", "walsky.optimizer",
    "WalksyCrystalOptimizerMod", "Donut", "Replace Mod", "ShieldDisabler",
    "SilentAim", "Totem Hit", "Wtap", "FakeLag", "dev.virel", "orchard",
    "BlockESP", "dev.krypton", "skid.krypton", "skid/krypton", "AntiMissClick",
    "LagReach", "PopSwitch", "SprintReset", "ChestSteal", "AntiBot",
    "ElytraSwap", "FastXP", "FastExp", "Refill", "AirAnchor", "jnativehook",
    "FakeInv", "HoverTotem", "AutoClicker", "AutoFirework", "PackSpoof",
    "Antiknockback", "catlean", "AuthBypass", "Asteria", "Prestige",
    "AutoEat", "AutoMine", "MaceSwap", "Macro198", "StunSlam", "SafeAnchor",
    "DoubleAnchor", "AutoTPA", "BaseFinder", "Xenon", "gypsy", "AutoPotRefill",
    "KeyPearl", "AutoNethPot", "AutoDtap", "AutoWeb", "AnchorAction",
    "org.chainlibs.module.impl.modules.Crystal", "org.chainlibs.module.impl.modules.Blatant",
    "imgui.gl3", "imgui.glfw", "BowAim", "Criticals", "Fakenick", "FakeItem",
    "invsee", "ItemExploit", "Hellion", "hellion", "LicenseCheckMixin",
    "ClientPlayerInteractionManagerAccessor", "ClientPlayerEntityMixim",
    "dev.gambleclient", "obfuscatedAuth", "phantom-refmap.json", "xyz.greaj"
)

$cheatStrings = @(
    # Generic module labels: useful when the client brand/name has been removed
    "Aim Assist", "Auto Switch", "Health Indicators", "Horizontal Speed",
    "In Air", "No Jump Delay", "NoJumpDelay", "Place Delay", "Player ESP",
    "Self Destruct", "Speed Multiplier", "Storage ESP", "Switch Back",
    "Switch Delay", "TriggerBot", "Vertical Speed", "Auto Web", "Autoclicker",
    "AutoCrystal", "autocrystal", "auto crystal", "cw crystal",
    "dontPlaceCrystal", "dontBreakCrystal", "dev.virel", "orchard",
    "AutoHitCrystal", "autohitcrystal", "canPlaceCrystalServer", "healPotSlot",
    "AutoAnchor", "autoanchor", "auto anchor", "DoubleAnchor", "HasAnchor",
    "anchortweaks", "anchor macro", "safe anchor", "safeanchor", "SafeAnchor",
    "AirAnchor", "anchorMacro", "AutoTotem", "autototem", "auto totem",
    "InventoryTotem", "inventorytotem", "HoverTotem", "hover totem", "legittotem",
    "AutoPot", "autopot", "auto pot", "speedPotSlot", "strengthPotSlot",
    "AutoArmor", "autoarmor", "auto armor", "AutoPotRefill",
    "preventSwordBlockBreaking", "preventSwordBlockAttack",
    "ShieldDisabler", "ShieldBreaker", "Breaking shield with axe...",
    "AutoDoubleHand", "autodoublehand", "auto double hand", "AutoClicker",
    "Failed to switch to mace after axe!", "AutoMace", "MaceSwap", "SpearSwap",
    "StunSlam", "Donut", "JumpReset", "axespam", "axe spam",
    "findKnockbackSword", "attackRegisteredThisClick",
    "AimAssist", "aimassist", "aim assist", "triggerbot", "trigger bot",
    "Silent Rotations", "SilentRotations", "FakeInv", "swapBackToOriginalSlot",
    "FakeLag", "pingspoof", "ping spoof", "fakePunch", "Fake Punch",
    "mace_swap", "quick_strike", "macro_198", "stun_slam", "safe_anchor",
    "double_anchor", "auto_pot_refill", "walksy_optimizer", "key_pearl",
    "aim_assist", "auto_neth_pot", "auto_dtap", "trigger_bot", "auto_web",
    "DOUBLE_ESCAPE", "DOUBLE_RIGHTCLICK_FIRST", "DOUBLE_RIGHTCLICK_SECOND",
    "POST_CYCLE_DELAY", "PLACE_OBI", "WAIT_OBI", "PLACE_CRYSTAL", "BREAK_CRYSTAL",
    "ROTATING_DOWN", "ROTATING_BACK", "REFILLING", "PLANTING", "BONEMEALING",
    "AnchorAction", "Places two anchors for massive damage", "REOFFHAND_TOTEM",
    "webmacro", "web macro", "AntiWeb", "AutoWeb",
    "lvstrng", "dqrkis", "selfdestruct", "self destruct",
    "WalksyCrystalOptimizerMod", "WalksyOptimizer", "WalskyOptimizer",
    "autoCrystalPlaceClock", "AutoFirework", "ElytraSwap", "FastXP", "FastExp",
    "NoJumpDelay", "PackSpoof", "Antiknockback", "catlean", "AuthBypass",
    "obfuscatedAuth", "LicenseCheckMixin", "BaseFinder", "invsee", "ItemExploit",
    "FreezePlayer", "LWFH Crystal", "KeyPearl", "LootYeeter", "FastPlace",
    "AutoBreach", "setBlockBreakingCooldown", "getBlockBreakingCooldown",
    "blockBreakingCooldown", "onBlockBreaking", "setItemUseCooldown",
    "invokeDoAttack", "invokeDoItemUse", "invokeOnMouseButton",
    "onPushOutOfBlocks", "onIsGlowing",
    "Automatically switches to sword when hitting with totem",
    "arrayOfString", "POT_CHEATS", "Dqrkis Client", "Entity.isGlowing",
    "Activate Key", "Click Simulation", "On RMB", "No Count Glitch",
    "No Bounce", "NoBounce", "Place Delay", "Break Delay", "Fast Mode",
    "Place Chance", "Break Chance", "Stop On Kill", "Damage Tick", "damagetick",
    "Anti Weakness", "Particle Chance", "Trigger Key", "Switch Delay",
    "Totem Slot", "Silent Rotations", "Smooth Rotations", "Rotation Speed",
    "Use Easing", "Easing Strength", "While Use", "Stop on Kill",
    "Glowstone Delay", "Glowstone Chance", "Explode Delay", "Explode Chance",
    "Explode Slot", "Only Charge", "Anchor Macro", "Reach Distance",
    "Min Height", "Min Fall Speed", "Attack Delay", "Breach Delay",
    "Require Elytra", "Auto Switch Back", "Check Line of Sight",
    "Only When Falling", "Require Crit", "Show Status Display",
    "Stop On Crystal", "Check Shield", "On Pop", "Predict Damage",
    "On Ground", "Check Players", "Predict Crystals", "Check Aim",
    "Check Items", "Activates Above", "Blatant", "Force Totem",
    "Stay Open For", "Auto Inventory Totem", "Only On Pop", "Vertical Speed",
    "Hover Totem", "Swap Speed", "Strict One-Tick", "Mace Priority",
    "Min Totems", "Min Pearls", "Totem First", "Drop Interval",
    "Random Pattern", "Loot Yeeter", "Horizontal Aim Speed",
    "Vertical Aim Speed", "Include Head", "Web Delay", "Holding Web",
    "Not When Affects Player", "Hit Delay", "Require Hold Axe",
    "Fake Punch", "placeInterval", "breakInterval", "stopOnKill",
    "activateOnRightClick", "holdCrystal",
    "KillAura", "ClickAura", "MultiAura", "ForceField", "LegitAura",
    "AimBot", "AutoAim", "SilentAim", "AimLock", "HeadSnap", "CrystalAura",
    "AnchorAura", "AnchorFill", "AnchorPlace", "BedAura", "AutoBed",
    "BedBomb", "BedPlace", "BowAimbot", "BowSpam", "AutoBow",
    "AutoCrit", "CritBypass", "AlwaysCrit", "CriticalHit",
    "ReachHack", "ExtendReach", "LongReach", "HitboxExpand",
    "AntiKB", "NoKnockback", "GrimVelocity", "GrimDisabler", "VelocitySpoof",
    "KBReduce", "OffhandTotem", "TotemSwitch", "AutoWeapon", "AutoSword",
    "AutoCity", "Burrow", "SelfTrap", "HoleFiller", "AntiSurround",
    "AntiBurrow", "WTap", "TargetStrafe", "AutoGap", "AutoPearl",
    "FlyHack", "CreativeFlight", "BoatFly", "PacketFly", "AirJump",
    "SpeedHack", "BHop", "BunnyHop", "AntiFall", "NoFallDamage", "SafeFall",
    "StepHack", "FastClimb", "AutoStep", "HighStep", "WaterWalk",
    "LiquidWalk", "LavaWalk", "NoSlow", "NoSlowdown", "NoWeb", "NoSoulSand",
    "WallHack", "ElytraSpeed", "InstantElytra", "ScaffoldWalk", "FastBridge",
    "BuildHelper", "AutoBridge", "Nuker", "NukerLegit", "InstantBreak",
    "GhostHand", "NoSwing", "PlaceAssist", "AirPlace", "AutoPlace",
    "InstantPlace", "PlayerESP", "MobESP", "ItemESP", "StorageESP",
    "ChestESP", "Tracers", "NameTagsHack", "XRayHack", "OreFinder",
    "CaveFinder", "OreESP", "NewChunks", "ChunkBorders", "TunnelFinder",
    "TargetHUD", "ReachDisplay", "DoubleClicker", "JitterClick",
    "ButterflyClick", "CPSBoost", "ChestStealer", "InvManager",
    "InvMovebypass", "AutoSprint", "AntiAFK", "AutoRespawn", "PopSwitch",
    "FakeLatency", "FakePing", "SpoofRotation", "PositionSpoof",
    "GameSpeed", "SpeedTimer", "GrimBypass", "VulcanBypass", "MatrixBypass",
    "AACBypass", "VerusDisabler", "IntaveBypass", "WatchdogBypass",
    "PacketMine", "PacketWalk", "PacketSneak", "PacketCancel", "PacketDupe",
    "PacketSpam", "SelfDestruct", "HideClient", "SessionStealer",
    "TokenLogger", "TokenGrabber", "DiscordToken", "RemoteAccess",
    "ReverseShell", "C2Server", "Backdoor", "KeyLogger", "StashFinder",
    "TrailFinder", "imgui.binding", "JNativeHook", "GlobalScreen",
    "NativeKeyListener", "client-refmap.json", "cheat-refmap.json",
    "meteordevelopment", "cc/novoline", "com/alan/clients", "club/maxstats",
    "wtf/moonlight", "me/zeroeightsix/kami", "net/ccbluex", "today/opai",
    "net/minecraft/injection", "org/chainlibs/module/impl/modules",
    "xyz/greaj", "com/cheatbreaker", "com/moonsworth", "doomsdayclient",
    "DoomsdayClient", "doomsday.jar", "novaclient", "api.novaclient.lol",
    "WalksyOptimizer", "LWFH Crystal", "vape.gg", "vapeclient", "VapeClient",
    "VapeLite", "intent.store", "IntentClient", "rise.today", "riseclient.com",
    "meteor-client", "meteorclient", "meteordevelopment.meteorclient",
    "liquidbounce", "fdp-client", "novoware", "novoclient", "aristois",
    "impactclient", "azura", "pandaware", "skilled", "moonClient", "astolfo",
    "futureClient", "konas", "rusherhack", "inertia", "exhibition",
    "dev.krypton", "dev/krypton", "skid.krypton", "skid/krypton",
    "VirginClient", "virgin client", "catlean", "CatleanClient",
    "catlean client", "ArgonClient", "argon client", "Asteria",
    "AsteriaClient", "asteria client", "Prestige", "PrestigeClient",
    "prestige client", "prestigeclient.vip", "gypsy", "GypsyClient",
    "gypsy client", "Xenon", "XenonClient", "xenon client", "GrimClient",
    "grim client", "phantom-refmap.json", "dqrkis.xyz", "Dqrkis Client"
)

$patternRegex = [regex]::new(
    '(?<![A-Za-z])(' + ($suspiciousPatterns -join '|') + ')(?![A-Za-z])',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$cheatStringSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($s in $cheatStrings) { [void]$cheatStringSet.Add($s) }

# Detect any sequence of fullwidth alphanumeric characters (used by many obfuscated clients)
$fullwidthRegex = [regex]::new(
    "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{3,}",
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)
#endregion

#region JAR Analysis
function Scan-JAR {
    param([string]$FilePath)

    $foundPatterns  = [System.Collections.Generic.HashSet[string]]::new()
    $foundStrings   = [System.Collections.Generic.HashSet[string]]::new()
    $foundFullwidth = [System.Collections.Generic.HashSet[string]]::new()

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName

            foreach ($m in $patternRegex.Matches($name)) {
                [void]$foundPatterns.Add($m.Value)
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
                        [void]$foundPatterns.Add($m.Value)
                    }

                    foreach ($s in $cheatStringSet) {
                        if ($ascii.Contains($s) -or $utf8.Contains($s)) {
                            [void]$foundStrings.Add($s)
                        }
                    }

                    foreach ($m in $fullwidthRegex.Matches($utf8)) {
                        [void]$foundFullwidth.Add($m.Value)
                    }
                } catch {}
            }
        }
        $archive.Dispose()
    } catch {
        return $null
    }

    return @{
        Patterns  = $foundPatterns
        Strings   = $foundStrings
        Fullwidth = $foundFullwidth
    }
}
#endregion

#region System Scan
function Scan-System {
    Write-Host "Scanning system (processes, registry, DNS, JVM)..." -ForegroundColor Green

    $procs = Get-Process -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $name = $p.ProcessName.ToLower()
        foreach ($client in $cheatStrings) {
            if ($name -match [regex]::Escape($client.ToLower())) {
                Add-Finding -Tier "Detection" -Category "Processes" -Title "Cheat Process Running" `
                    -Message "Process $($p.ProcessName) matches '$client'" `
                    -Evidence @{Process=$p.ProcessName; Client=$client}
                break
            }
        }

        if ($p.ProcessName -match "javaw|java") {
            try {
                $cmd = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmd) {
                    if ($cmd -match "-Dclient\.brand=(Wurst|Impact|Meteor|Sigma|LiquidBounce|Vape|Novoline)") {
                        Add-Finding -Tier "Detection" -Category "JVM" -Title "Malicious JVM Argument" `
                            -Message "JVM brand: $($Matches[0])" -Evidence @{Argument=$Matches[0]}
                    }
                    if ($cmd -match "-D(xray|fly|speed|killaura|reach|scaffold|autocrystal|autototem)") {
                        Add-Finding -Tier "Detection" -Category "JVM" -Title "JVM Cheat Flag" `
                            -Message "Flag: $($Matches[0])" -Evidence @{Argument=$Matches[0]}
                    }

                    $agentMatches = [regex]::Matches($cmd, '-javaagent:(?:"([^"]+)"|([^\s]+))')
                    $legitAgents = @("jmxremote","yjp","jrebel","newrelic","jacoco","theseus")
                    foreach ($am in $agentMatches) {
                        $agentPath = if ($am.Groups[1].Success) { $am.Groups[1].Value } else { $am.Groups[2].Value }
                        $agentName = [System.IO.Path]::GetFileName($agentPath)
                        $isLegit = $false
                        foreach ($la in $legitAgents) {
                            if ($agentName -match $la) { $isLegit = $true; break }
                        }
                        if (-not $isLegit) {
                            Add-Finding -Tier "Warning" -Category "JVM" -Title "Suspicious Java Agent" `
                                -Message "Agent: $agentName (path: $agentPath)" `
                                -Evidence @{Agent=$agentName; Path=$agentPath}
                        }
                    }
                    if ($cmd -match '-Xbootclasspath') {
                        Add-Finding -Tier "Warning" -Category "JVM" -Title "Bootclasspath Modification" `
                            -Message "Xbootclasspath flag detected" -Evidence @{Flag=$Matches[0]}
                    }

                    # Loaded module paths survive a client self-destruct more often
                    # than the process name or command line. Access is best-effort.
                    foreach ($module in ($p.Modules | Where-Object { $_.FileName })) {
                        $modulePath = $module.FileName
                        $moduleLeaf = [System.IO.Path]::GetFileName($modulePath)
                        foreach ($sig in $suspiciousPatterns) {
                            if ($modulePath -imatch [regex]::Escape($sig)) {
                                Add-Finding -Tier "Warning" -Category "Loaded Modules" -Title "Suspicious Java Module Path" `
                                    -Message "Loaded module path matches '$sig': $modulePath" `
                                    -Evidence @{Process=$p.Id; Module=$moduleLeaf; Path=$modulePath; Signature=$sig}
                                break
                            }
                        }
                    }
                }
            } catch {}
        }
    }

    foreach ($client in $cheatStrings) {
        $path = "HKCU:\Software\$client"
        if (Test-Path $path) {
            Add-Finding -Tier "Detection" -Category "Registry" -Title "Cheat Registry Key" `
                -Message "Key $path exists" -Evidence @{Key=$path}
        }
    }

    $dns = ipconfig /displaydns 2>$null | Select-String "Record Name.*:\s+(.*)" | ForEach-Object { $_.Matches.Groups[1].Value }
    $cheatDomains = @(
        "vape.gg","vapeclient.com","meteorclient.com","liquidbounce.net","wurstclient.net",
        "sigmaclient.com","novoware.cc","gamesense.pw","osirisclient.com","cosmosclient.com",
        "sorusclient.net","azuraclient.com","deltaclient.net","elysianclient.org",
        "onyxclient.com","luminaclient.net","ravenbplusplus.net","uziclient.com",
        "skidbounce.net","bleachhack.org","forgehax.com","huzuni.org","kamiblue.org",
        "konasclient.com","kuraclient.net","lambdaclient.com","mercuryclient.org",
        "miraiclient.net","ozarkclient.com","raionclient.net","seppukuclient.com",
        "vertexclient.net","prestigeclient.vip","dqrkis.xyz","orchard.gg"
    )
    foreach ($domain in $cheatDomains) {
        if ($dns -match $domain) {
            Add-Finding -Tier "Detection" -Category "DNS" -Title "Cheat Domain in Cache" `
                -Message "Domain $domain resolved" -Evidence @{Domain=$domain}
        }
    }

    $prefetchDir = "$env:windir\Prefetch"
    if (-not (Test-Path $prefetchDir)) {
        Add-Finding -Tier "Detection" -Category "Prefetch" -Title "Prefetch Folder Missing" `
            -Message "Prefetch folder not present"
    } else {
        $files = Get-ChildItem $prefetchDir -ErrorAction SilentlyContinue
        if ($files.Count -lt 5) {
            Add-Finding -Tier "Warning" -Category "Prefetch" -Title "Low Prefetch Count" `
                -Message "Only $($files.Count) prefetch files – possible deletion"
        }
    }

    $logs = @("Application", "System", "Security", "Windows PowerShell")
    foreach ($log in $logs) {
        try {
            $events = Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction SilentlyContinue
            if (-not $events) {
                Add-Finding -Tier "Warning" -Category "Event Logs" -Title "Event Log Cleared" `
                    -Message "Event log $log appears empty (cleared?)" -Evidence @{Log=$log}
            }
        } catch {}
    }

    # Residual-artifact scan: catches names/content left after a client removes its
    # main JAR. This is intentionally bounded to high-value forensic locations.
    $residualRoots = @(
        "$env:USERPROFILE\AppData\Roaming\.minecraft\logs",
        "$env:USERPROFILE\AppData\Roaming\.minecraft\crash-reports",
        "$env:USERPROFILE\AppData\Local\Temp",
        "$env:windir\Prefetch"
    ) | Where-Object { Test-Path $_ -PathType Container }

    $residualFiles = foreach ($root in $residualRoots) {
        Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -ge (Get-Date).AddDays(-30) -and $_.Length -le 50MB }
    }
    foreach ($file in ($residualFiles | Sort-Object FullName -Unique)) {
        $nameHit = $false
        foreach ($sig in $suspiciousPatterns) {
            if ($file.Name -imatch [regex]::Escape($sig)) {
                Add-Finding -Tier "Detection" -Category "Residual Artifacts" -Title "Suspicious Residual Filename" `
                    -Message "Recent artifact matches '$sig': $($file.FullName)" `
                    -Evidence @{File=$file.FullName; Signature=$sig; LastWrite=$file.LastWriteTime.ToString("o")}
                $nameHit = $true
                break
            }
        }
        if (-not $nameHit -and $file.Extension -in @('.log','.txt','.json','.xml','.dmp')) {
            try {
                    $hit = Select-String -LiteralPath $file.FullName -Pattern $cheatStrings -SimpleMatch -CaseSensitive:$false -List -ErrorAction SilentlyContinue
                    if ($hit) {
                        $matchedText = [string]$hit.Pattern
                        if ([string]::IsNullOrWhiteSpace($matchedText)) { $matchedText = [string]$hit.Line }
                        Add-Finding -Tier "Warning" -Category "Residual Artifacts" -Title "Cheat String in Residual Artifact" `
                            -Message "Possible signature found in $($file.FullName)" `
                            -Evidence @{File=$file.FullName; String=$matchedText; LastWrite=$file.LastWriteTime.ToString("o")}
                }
            } catch {}
        }
    }

    Write-Host "System scan complete." -ForegroundColor Green
}

function Scan-MinecraftUniverse {
    Write-Host "Discovering Minecraft, Java, and launcher locations..." -ForegroundColor Green
    $roots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $userProfileRoot = $env:USERPROFILE
    $minecraftTargets = @()
    foreach ($p in (Get-Process -Name java,javaw -ErrorAction SilentlyContinue)) {
        try {
            $ci = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue
            $cmdLine = [string]$ci.CommandLine
            # Java Update and unrelated JVMs are excluded unless Minecraft evidence exists.
            if ($cmdLine -match '(?i)(minecraft|\.minecraft|fabric|forge|quilt|lwjgl|net\.minecraft|prism|modrinth|multimc)') {
                $minecraftTargets += [pscustomobject]@{ PID=$p.Id; Process=$p.ProcessName; Active=(-not $p.HasExited); CommandLine=$cmdLine }
            }
        } catch {}
    }
    if ($minecraftTargets.Count -eq 0) {
        Write-Host "DENIED: Minecraft is not currently open; live-process scan requires an active Minecraft JVM." -ForegroundColor Red
        Add-Finding -Tier "Info" -Category "Minecraft Session" -Title "Live Scan Denied" -Message "No active Minecraft Java process was found. Start Minecraft and run the scan again."
        return
    }
    Write-Host "Active Minecraft JVM(s):" -ForegroundColor Cyan
    foreach ($target in $minecraftTargets) {
        Write-Host "  PID $($target.PID) | $($target.Process) | Active: $($target.Active)" -ForegroundColor White
        Add-Finding -Tier "Info" -Category "Minecraft Session" -Title "Active Minecraft Process" `
            -Message "Minecraft JVM PID $($target.PID) is active." -Evidence @{PID=$target.PID; Process=$target.Process; Active=$target.Active}
        Scan-JavaMemory -ProcessId $target.PID
        # Do not treat the complete command line as a filesystem path.
        if ($target.CommandLine -match '(?i)-gameDir\s+"([^"]+)"') {
            $gameDir = $Matches[1]
            if (Test-Path $gameDir -PathType Container) { [void]$roots.Add((Resolve-Path $gameDir).Path) }
        }
        foreach ($token in [regex]::Matches($target.CommandLine, '(?i)([A-Za-z]:\\[^" ]*(?:minecraft|\.minecraft|mods|libraries)[^" ]*)')) {
            $candidate = $token.Groups[1].Value.TrimEnd('"')
            if (Test-Path $candidate) { [void]$roots.Add((Resolve-Path $candidate).Path) }
        }
        try {
            $targetProcess = Get-Process -Id $target.PID -ErrorAction Stop
            foreach ($module in ($targetProcess.Modules | Where-Object { $_.FileName })) {
                if ($module.FileName -match '(?i)(minecraft|fabric|forge|quilt|lwjgl|\.minecraft)') {
                    [void]$roots.Add((Split-Path $module.FileName -Parent))
                }
            }
        } catch {}
    }
    @(
        "$userProfileRoot\AppData\Roaming\.minecraft",
        "$userProfileRoot\AppData\Roaming\.minecraft\logs",
        "$userProfileRoot\AppData\Roaming\PrismLauncher",
        "$userProfileRoot\AppData\Roaming\MultiMC",
        "$userProfileRoot\AppData\Roaming\ATLauncher",
        "$userProfileRoot\AppData\Local\Packages\Microsoft.4297127D64EC6_8wekyb3d8bbwe\LocalCache\Local\game",
        "$userProfileRoot\AppData\Local\Temp"
    ) | ForEach-Object { if (Test-Path $_ -PathType Container) { [void]$roots.Add((Resolve-Path $_).Path) } }

    # Discover actual paths rather than assuming the default .minecraft folder.
    $since = $script:ScanStart
    $textExt = @('.log','.txt','.json','.xml','.cfg','.config','.properties','.dat','.json5','.crash')
    foreach ($root in $roots) {
        Write-Host "Scanning $root" -ForegroundColor DarkGray
        $files = Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -ge $since -and $_.Length -le 100MB }
        foreach ($file in $files) {
            foreach ($sig in $suspiciousPatterns) {
                if ($file.Name -imatch [regex]::Escape($sig)) {
                    Add-Finding -Tier "Detection" -Category "Minecraft Timeline" -Title "Suspicious Minecraft-Linked Artifact" `
                        -Message "$($file.FullName) changed after the SS session started" -Evidence @{File=$file.FullName; Signature=$sig; Since=$since.ToString("o")}
                    break
                }
            }
            if ($textExt -contains $file.Extension.ToLowerInvariant()) {
                try {
                    $hit = Select-String -LiteralPath $file.FullName -Pattern $cheatStrings -SimpleMatch -CaseSensitive:$false -List -ErrorAction SilentlyContinue
                    if ($hit) {
                        $matchedText = [string]$hit.Pattern
                        if ([string]::IsNullOrWhiteSpace($matchedText)) { $matchedText = [string]$hit.Line }
                        Add-Finding -Tier "Warning" -Category "Minecraft Timeline" -Title "Cheat String in Minecraft-Linked File" `
                            -Message "Possible signature found in $($file.FullName)" -Evidence @{File=$file.FullName; String=$matchedText}
                    }
                } catch {}
            }
            if ($file.Extension -ieq '.jar') {
                $result = Scan-JAR -FilePath $file.FullName
                if ($result -and (($result.Patterns.Count + $result.Strings.Count + $result.Fullwidth.Count) -gt 0)) {
                    Add-Finding -Tier "Detection" -Category "Minecraft Timeline" -Title "Signature in Recent Minecraft JAR" `
                        -Message "$($file.FullName) contains one or more scanner signatures" -Evidence @{File=$file.FullName; LastWrite=$file.LastWriteTime.ToString("o")}
                }
            }
        }
    }
    Write-Host "Minecraft/launcher timeline scan complete." -ForegroundColor Green
}
#endregion

#region Main
if (-not (Test-Admin)) {
    Write-Host "WARNING: Not running as Administrator – some checks may fail." -ForegroundColor Red
    Read-Host "Press Enter to continue"
}

$script:Findings = @()
$script:ScanStart = Get-Date
$script:minecraftPath = ""

do {
    $choice = Show-Menu
    switch ($choice) {
        "1" {
            $path = Read-Host "Enter Minecraft mods folder path (or press Enter for default)"
            if ([string]::IsNullOrWhiteSpace($path)) {
                $path = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
            }
            if (Test-Path $path -PathType Container) {
                $script:minecraftPath = $path
                Write-Host "Scanning JARs in $path ..." -ForegroundColor Green
                $jars = Get-ChildItem -Path $path -Filter *.jar -ErrorAction SilentlyContinue
                if ($jars.Count -eq 0) {
                    Write-Host "No JAR files found." -ForegroundColor Yellow
                } else {
                    $total = $jars.Count
                    $i = 0
                    foreach ($jar in $jars) {
                        $i++
                        Write-Progress -Activity "Scanning JARs" -Status $jar.Name -PercentComplete (($i / $total) * 100)
                        $result = Scan-JAR -FilePath $jar.FullName
                        if ($result) {
                            $hasHit = ($result.Patterns.Count -gt 0) -or ($result.Strings.Count -gt 0) -or ($result.Fullwidth.Count -gt 0)
                            if ($hasHit) {
                                foreach ($p in $result.Patterns) {
                                    Add-Finding -Tier "Detection" -Category "File System" -Title "Pattern Match" `
                                        -Message "Pattern '$p' in $($jar.Name)" -Evidence @{File=$jar.Name; Pattern=$p}
                                }
                                foreach ($s in $result.Strings) {
                                    Add-Finding -Tier "Warning" -Category "File System" -Title "String Match" `
                                        -Message "String '$s' in $($jar.Name)" -Evidence @{File=$jar.Name; String=$s}
                                }
                                foreach ($fw in $result.Fullwidth) {
                                    Add-Finding -Tier "Detection" -Category "File System" -Title "Fullwidth Obfuscation" `
                                        -Message "Fullwidth sequence '$fw' in $($jar.Name)" -Evidence @{File=$jar.Name; Fullwidth=$fw}
                                }
                            }
                        }
                    }
                    Write-Progress -Activity "Scanning JARs" -Completed
                }
            } else {
                Write-Host "Path not found: $path" -ForegroundColor Red
            }
            Read-Host "Press Enter to continue"
        }
        "2" {
            Scan-System
            Scan-MinecraftUniverse
            Read-Host "Press Enter to continue"
        }
        "3" {
            Export-Report
            Read-Host "Press Enter to continue"
        }
        "4" {
            if ($script:Findings.Count -eq 0) {
                Write-Host "No findings." -ForegroundColor Yellow
            } else {
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
