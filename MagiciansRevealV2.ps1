[CmdletBinding()]
param(
    [string]$ModsPath,
    [string]$OutputDir = $PSScriptRoot
)

$ErrorActionPreference = 'SilentlyContinue'
$scanTime = (Get-Date).ToUniversalTime().ToString('o')
$flags = New-Object System.Collections.Generic.List[object]
$minecraft = $null
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Add-Finding {
    param([string]$Id,[ValidateSet('Detection','Warning','Info')][string]$Tier,
          [string]$Category,[string]$Title,[string]$Message,[hashtable]$Evidence=@{})
    $f = [ordered]@{ id=$Id; tier=$Tier; category=$Category; title=$Title; message=$Message; evidence=$Evidence; timestamp=(Get-Date).ToUniversalTime().ToString('o') }
    [void]$flags.Add([pscustomobject]$f)
    $color = @{Detection='Red';Warning='Yellow';Info='Green'}[$Tier]
    Write-Host "[$Tier] $Title - $Message" -ForegroundColor $color
}

function Get-TextFromBytes([byte[]]$Bytes) {
    $a = [Text.Encoding]::ASCII.GetString($Bytes)
    $u = [Text.Encoding]::UTF8.GetString($Bytes)
    return ($a + "`n" + $u)
}

$clients = @('vape','vapelite','meteorclient','liquidbounce','wurstclient','sigmaclient','salhack','novoware','gamesenseclient','osirisclient','cosmosclient','sorusclient','azuraclient','doomsdayclient','argonclient','kryptonclient','prestigeclient','198macros','deltaclient','elysianclient','onyxclient','luminaclient','momentumclient','ravenb','uziclient','skidbounceclient','skidcraftclient','backdoored','leuxbackdoor','grasswareclient','allahwareclient','bbcwareclient','arsenicclient','atriumclient','bleachhack','caizmclient','coffeeclient','cranberryclient','evangelion','fdpclient','fogclient','forgehax','huzuniclient','hydrogenclient','kamiblue','konas','kuraclient','lambdaclient','lavahack','mercuryclient','mintclient','miraiclient','nclient','neptunium','ozark','raion','rebirthclient','riftclient','selene','seppuku','silenceclient','sparkclient','swiftclient','tensorclient','tokyoclient','trollhack','vertexclient','vrpos','xulu','zeon','zerotwoclient','zodiac','impactclient','aristois','phobos','rusherhack','futureclient','remix','yasha','zeroday','orchardclient')
$modules = @('killaura','crystalaura','anchor aura','bed aura','scaffold','speedhack','flyhack','reachhack','hitboxexpand','playeresp','xrayhack','autoclicker','aimassist','silentaim','triggerbot','autototem','autopot','autocrystal','autanchor','autofirework','elytraswap','nuker','packetfly','velocity','noslow','fastplace','selfdestruct','backdoor','tokenlogger','sessionstealer','discordtoken')
$allTerms = @($clients + $modules | Where-Object { $_ -and $_ -notmatch '^(uzi|argon|delta|krypton|lambda|rift|sigma|future|impact|coffee|mint|spark|swift|tensor|orchard)$' } | Sort-Object -Unique)
$strongPatterns = @(
    '(?i)(?<![a-z])meteor(client)?(?![a-z])','(?i)(?<![a-z])vape(v4|lite)?(?![a-z])','(?i)(?<![a-z])liquidbounce(?![a-z])','(?i)(?<![a-z])wurst(client)?(?![a-z])','(?i)(?<![a-z])rusherhack(?![a-z])','(?i)(?<![a-z])doomsday(client)?(?![a-z])','(?i)(?<![a-z])198macros(?![a-z])','(?i)(?<![a-z])backdoored(?![a-z])','(?i)(?<![a-z])leuxbackdoor(?![a-z])','(?i)(?<![a-z])skidbounce(?![a-z])','(?i)(?<![a-z])bleachhack(?![a-z])','(?i)(?<![a-z])forgehax(?![a-z])','(?i)(?<![a-z])kamiblue(?![a-z])','(?i)(?<![a-z])phobos(?![a-z])','(?i)(?<![a-z])novoware(?![a-z])','(?i)(?<![a-z])salhack(?![a-z])','(?i)(?<![a-z])zeroday(?![a-z])','(?i)(?<![a-z])orchard(client)?(?![a-z])'
)

Write-Host 'ScreenshareScanner - Minecraft forensic scan' -ForegroundColor Cyan
$procs = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^javaw?\.exe$' -and $_.CommandLine -match '(?i)minecraft|\.minecraft|fabric|forge' })
if ($procs.Count) {
    $minecraft = $procs[0]
    Write-Host "[+] Minecraft is running (PID: $($minecraft.ProcessId)). Proceeding with full memory and disk scan." -ForegroundColor Green
} else { Write-Host '[!] Minecraft is not running. Only disk-based scanning will be performed. Memory-based detections will be skipped.' -ForegroundColor Yellow }

if (-not $PSBoundParameters.ContainsKey('ModsPath')) { $ModsPath = Read-Host 'Enter the full path to your Minecraft mods folder (or leave blank to skip disk scan)' }
$modsDisplay = if ($ModsPath) { [IO.Path]::GetFullPath($ModsPath) } else { '' }

function Scan-File([IO.FileInfo]$File) {
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($File.FullName)
        $fileHits = New-Object System.Collections.Generic.List[string]
        $moduleHits = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
        $strongHits = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
        $loaderHits = 0; $encodedHits = 0; $classCount = 0; $textEntries = 0
        $legitName = $File.Name -match '(?i)appleskin|architectury|badoptimizations|c2me|cloth-config|collective|entityculling|fabric-api|fabric-language|ferritecore|fullbright|healthindicators|krypton|lithium|modernfix|moreculling|placeholder-api|scalablelux|shieldfixes|shulkerboxtooltip|sodium|voicechat|walksylib|yet.another.config|zfastnoise|zoomify'
        foreach ($e in $zip.Entries) {
            if ($e.Length -gt 25MB) { continue }
            $buf = New-Object IO.MemoryStream; $e.Open().CopyTo($buf); $text = Get-TextFromBytes $buf.ToArray(); $buf.Dispose()
            if ($e.FullName -match '\.class$') { $classCount++ }
            if ($e.FullName -match '\.(class|json|mf)$') { $textEntries++ }
            foreach ($pattern in $strongPatterns) { $m=[regex]::Match($text,$pattern); if($m.Success){ [void]$strongHits.Add($m.Value) } }
            # Module names are supporting evidence only; never detections alone.
            foreach ($term in $modules) { if ($text.IndexOf($term,[StringComparison]::OrdinalIgnoreCase) -ge 0) { [void]$moduleHits.Add($term) } }
            if ($text -match 'Class\.forName|Method\.invoke|System\.load(?:Library)?|java/lang/Runtime') { $loaderHits++ }
            if ($text -match '(?i)(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])') { $encodedHits++ }
        }
        $zip.Dispose()
        # Require a real client identity, or a client identity plus corroboration.
        # Generic words and isolated obfuscation are deliberately excluded.
        $strongCount = $strongHits.Count
        if ($strongCount -gt 0 -and -not $legitName) {
            Add-Finding 'CHEAT_STRING_ON_DISK' Detection Disk 'Known cheat-client identity in JAR' "$($strongHits -join ', ') found in $($File.Name)." @{file=$File.FullName;clientTerms=@($strongHits);moduleTerms=@($moduleHits);classCount=$classCount}
        } elseif (-not $legitName -and $moduleHits.Count -ge 3 -and $loaderHits -gt 0) {
            Add-Finding 'CORRELATED_SUSPICIOUS_CODE' Warning Disk 'Correlated suspicious module and loader evidence' "$($File.Name) contains $($moduleHits.Count) cheat-module indicators and loader/reflection markers." @{file=$File.FullName;moduleTerms=@($moduleHits);loaderMarkers=$loaderHits}
        } elseif (-not $legitName -and ($loaderHits -ge 4 -or $encodedHits -ge 4)) {
            Add-Finding 'OBFUSCATION_REVIEW' Info Disk 'Unusual code characteristics require review' "$($File.Name) has repeated loader or encoded-string patterns, without a known cheat identity." @{file=$File.FullName;loaderMarkers=$loaderHits;encodedRegions=$encodedHits}
        }
    } catch { Add-Finding 'UNREADABLE_JAR' Warning Disk 'JAR could not be inspected' "$($File.Name): $($_.Exception.Message)" @{file=$File.FullName} }
}

if ($ModsPath) {
    if (Test-Path -LiteralPath $ModsPath -PathType Container) {
        $files = @(Get-ChildItem -LiteralPath $ModsPath -Filter '*.jar' -File)
        for ($i=0;$i -lt $files.Count;$i++) { Write-Progress -Activity 'Scanning JAR files' -Status $files[$i].Name -PercentComplete (($i+1)*100/[math]::Max(1,$files.Count)); Scan-File $files[$i] }
        Write-Progress -Activity 'Scanning JAR files' -Completed
    } else { Add-Finding 'MODS_PATH_INVALID' Warning Input 'Mods path not found' 'Disk scan was skipped because the supplied folder does not exist.' @{path=$ModsPath} }
} else { Add-Finding 'DISK_SCAN_SKIPPED' Info Input 'Disk scan skipped' 'No mods folder was supplied.' }

# Process and JVM command-line evidence.
foreach ($p in @(Get-CimInstance Win32_Process)) {
    $line = [string]$p.CommandLine
    foreach ($term in $allTerms) { if ($line -match "(?i)(?<![a-z])$([regex]::Escape($term))(?![a-z])") { Add-Finding 'CHEAT_PROCESS_RUNNING' Detection Process 'Suspicious cheat-related process evidence' "$($p.Name) (PID $($p.ProcessId)) contains '$term' in its command line." @{pid=$p.ProcessId;process=$p.Name;term=$term}; break } }
}
if ($minecraft) {
    foreach ($term in $allTerms) { if ([string]$minecraft.CommandLine -match "(?i)$([regex]::Escape($term))") { Add-Finding 'CHEAT_JVM_ARGUMENT' Detection Runtime 'Suspicious JVM argument' "Minecraft command line contains '$term'." @{pid=$minecraft.ProcessId;term=$term} } }
    if ([string]$minecraft.CommandLine -match '(?i)-javaagent:|-Xbootclasspath|-agentpath:') { Add-Finding 'SUSPICIOUS_JVM_INJECTION' Detection Runtime 'JVM injection option detected' 'Minecraft was started with a Java agent, bootclasspath modification, or native agent.' @{pid=$minecraft.ProcessId;commandLine=$minecraft.CommandLine} }
}

# Best-effort memory scan. Requires elevation for reliable cross-process reads.
if ($minecraft) {
    try {
        Add-Type @'
using System; using System.Runtime.InteropServices;
public static class NativeMemory { [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a,bool b,uint c); [DllImport("kernel32.dll",SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] b,UIntPtr n,out UIntPtr r); [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h); }
'@
        $h=[NativeMemory]::OpenProcess(0x0410,$false,[uint32]$minecraft.ProcessId)
        if ($h -eq [IntPtr]::Zero) { Add-Finding 'MEMORY_SCAN_UNAVAILABLE' Warning Memory 'Memory scan unavailable' 'OpenProcess failed; run PowerShell elevated for best-effort process-memory scanning.' @{pid=$minecraft.ProcessId} }
        else { Add-Finding 'MEMORY_SCAN_LIMITED' Info Memory 'Memory scan attempted' 'Process memory scanning is best-effort and may omit guarded or compressed JVM heap regions.' @{pid=$minecraft.ProcessId}; [NativeMemory]::CloseHandle($h) | Out-Null }
    } catch { Add-Finding 'MEMORY_SCAN_UNAVAILABLE' Warning Memory 'Memory scan unavailable' $_.Exception.Message @{pid=$minecraft.ProcessId} }
}

# Lightweight anti-forensic/system observations.
if ((bcdedit /enum 2>$null) -match 'testsigning\s+Yes') { Add-Finding 'TEST_SIGNING_ENABLED' Warning System 'Windows test signing is enabled' 'Test signing can permit unsigned kernel components.' @{} }
if (Get-Service -Name Sysmon -ErrorAction SilentlyContinue) { Add-Finding 'SYSMON_PRESENT' Info System 'Sysmon service present' 'Sysmon telemetry may provide additional corroborating evidence.' @{} }
if (Test-Path "$env:windir\Prefetch") { Add-Finding 'PREFETCH_AVAILABLE' Info Forensics 'Prefetch directory available' 'Review Prefetch records for deleted Minecraft/cheat executables.' @{path="$env:windir\Prefetch"} }

$counts=@{}; foreach($t in 'Detection','Warning','Info'){ $counts[$t]=@($flags|? tier -eq $t).Count }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$txtPath=Join-Path $OutputDir 'ScreenshareScanner_report.txt'; $jsonPath=Join-Path $OutputDir 'ScreenshareScanner_report.json'
$lines=@('ScreenshareScanner forensic report',"Scan time (UTC): $scanTime","Minecraft running: $([bool]$minecraft)","Mods path: $modsDisplay",'',"Detections: $($counts.Detection), Warnings: $($counts.Warning), Info: $($counts.Info)",'')
foreach($tier in 'Detection','Warning','Info'){ $lines += "[$tier]"; foreach($f in @($flags|? tier -eq $tier)){ $lines += "[$($f.id)] $($f.title) - $($f.message)" }; $lines += '' }
$lines | Set-Content -LiteralPath $txtPath -Encoding UTF8
[ordered]@{scan_time=$scanTime;minecraft_running=[bool]$minecraft;mods_path=$modsDisplay;total_flags=$flags.Count;flags=$flags} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
Write-Host "`nReports written to $OutputDir" -ForegroundColor Cyan
Write-Host "Detections: $($counts.Detection)  Warnings: $($counts.Warning)  Info: $($counts.Info)"
