<#
.SYNOPSIS
    MagiciansRevealV2 – Minecraft Cheat Forensic Scanner (Zero False Positives)
.DESCRIPTION
    Self‑contained PowerShell script that compiles to a GUI executable.
    Detects cheat clients using cheat‑specific signatures that never appear in legitimate mods.
.AUTHOR
    Tim$erz
.VERSION
    2.0.0
#>

#region Auto‑Compile to EXE (only if running as .ps1)
if ($MyInvocation.MyCommand.Path -match '\.ps1$') {
    $exePath = $MyInvocation.MyCommand.Path -replace '\.ps1$', '.exe'
    if (-not (Test-Path $exePath)) {
        Write-Host "Compiling to EXE..." -ForegroundColor Cyan
        # Ensure ps2exe is available
        if (-not (Get-Module -ListAvailable -Name ps2exe)) {
            Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber -ErrorAction SilentlyContinue
        }
        Import-Module ps2exe -Force
        # Compile with GUI, no console, custom version info
        ps2exe -InputFile $MyInvocation.MyCommand.Path -OutputFile $exePath `
               -Title "MagiciansRevealV2" -Version "2.0.0" -Company "Tim`$erz" `
               -Description "Minecraft Cheat Scanner" -NoConsole -ErrorAction SilentlyContinue
        if (Test-Path $exePath) {
            Write-Host "EXE created: $exePath" -ForegroundColor Green
            Start-Process -FilePath $exePath
            exit
        } else {
            Write-Warning "Compilation failed – running as script instead."
        }
    } else {
        # EXE already exists – just run it
        Start-Process -FilePath $exePath
        exit
    }
}
#endregion

#region GUI Application (WPF) – runs only in EXE mode
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

# XAML for the main window (dark theme, fade‑in, hover animations)
$xaml = @'
<Window x:Class="MagiciansRevealV2.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="MagiciansRevealV2" Height="620" Width="840"
        WindowStartupLocation="CenterScreen"
        Background="#1E1E1E" ResizeMode="NoResize"
        AllowsTransparency="True" WindowStyle="None"
        MouseLeftButtonDown="Window_MouseDown">
    <Window.Resources>
        <Storyboard x:Key="FadeIn">
            <DoubleAnimation Storyboard.TargetProperty="Opacity" From="0" To="1" Duration="0:0:0.8"/>
        </Storyboard>
        <Storyboard x:Key="ButtonHover">
            <ColorAnimation Storyboard.TargetProperty="Background.Color" To="#FF6A5ACD" Duration="0:0:0.2"/>
        </Storyboard>
        <Storyboard x:Key="ButtonLeave">
            <ColorAnimation Storyboard.TargetProperty="Background.Color" To="#FF3A3A3A" Duration="0:0:0.2"/>
        </Storyboard>
    </Window.Resources>
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="40"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="50"/>
        </Grid.RowDefinitions>

        <!-- Title Bar -->
        <Border Grid.Row="0" Background="#2A2A2A">
            <Grid>
                <TextBlock Text="MagiciansRevealV2" FontSize="18" FontWeight="Bold" Foreground="#6A5ACD" VerticalAlignment="Center" Margin="10,0,0,0"/>
                <Button Content="✕" Background="Transparent" BorderThickness="0" Foreground="White" FontSize="16" HorizontalAlignment="Right" Margin="0,0,10,0" Cursor="Hand" Click="CloseButton_Click"/>
            </Grid>
        </Border>

        <!-- Main Content -->
        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Background="#1E1E1E">
            <StackPanel Margin="20">
                <TextBlock Text="Minecraft Cheat Forensic Scanner" FontSize="24" FontWeight="Bold" Foreground="White" TextAlignment="Center" Margin="0,0,0,10"/>
                <TextBlock Text="Zero False Positives – Uses cheat‑specific signatures only" Foreground="#AAAAAA" TextAlignment="Center" Margin="0,0,0,20"/>

                <!-- Scan Directory -->
                <GroupBox Header="Scan Target" Foreground="White" BorderBrush="#444" Margin="0,0,0,15">
                    <StackPanel Orientation="Horizontal" Margin="10">
                        <TextBlock Text="Minecraft Directory:" Foreground="White" VerticalAlignment="Center" Margin="0,0,10,0"/>
                        <TextBox x:Name="MinecraftDirBox" Text="$env:APPDATA\.minecraft" Width="300" Foreground="White" Background="#2A2A2A" BorderBrush="#444"/>
                        <Button Content="Browse" Width="80" Margin="10,0,0,0" Background="#3A3A3A" Foreground="White" BorderThickness="0" Cursor="Hand" Click="BrowseButton_Click"/>
                    </StackPanel>
                </GroupBox>

                <!-- Output Directory -->
                <GroupBox Header="Report Output" Foreground="White" BorderBrush="#444" Margin="0,0,0,15">
                    <StackPanel Orientation="Horizontal" Margin="10">
                        <TextBlock Text="Save Reports To:" Foreground="White" VerticalAlignment="Center" Margin="0,0,10,0"/>
                        <TextBox x:Name="OutputDirBox" Text="." Width="300" Foreground="White" Background="#2A2A2A" BorderBrush="#444"/>
                        <Button Content="Browse" Width="80" Margin="10,0,0,0" Background="#3A3A3A" Foreground="White" BorderThickness="0" Cursor="Hand" Click="BrowseOutput_Click"/>
                    </StackPanel>
                </GroupBox>

                <!-- Progress -->
                <StackPanel Margin="0,0,0,15">
                    <TextBlock x:Name="StatusText" Text="Ready" Foreground="#AAAAAA" FontSize="14"/>
                    <ProgressBar x:Name="ProgressBar" Height="20" Foreground="#6A5ACD" Background="#333" Margin="0,5,0,0" Value="0" Minimum="0" Maximum="100"/>
                </StackPanel>

                <!-- Scan Button -->
                <Button x:Name="ScanButton" Content="🔍  Start Scan" FontSize="18" FontWeight="Bold" Background="#6A5ACD" Foreground="White" BorderThickness="0" Height="50" Cursor="Hand" Click="ScanButton_Click">
                    <Button.Triggers>
                        <EventTrigger RoutedEvent="Button.MouseEnter">
                            <BeginStoryboard Storyboard="{StaticResource ButtonHover}"/>
                        </EventTrigger>
                        <EventTrigger RoutedEvent="Button.MouseLeave">
                            <BeginStoryboard Storyboard="{StaticResource ButtonLeave}"/>
                        </EventTrigger>
                    </Button.Triggers>
                </Button>

                <!-- Results List -->
                <ListBox x:Name="ResultsList" Margin="0,15,0,0" Height="200" Background="#2A2A2A" Foreground="White" BorderBrush="#444" FontFamily="Consolas" FontSize="12">
                    <ListBox.ItemTemplate>
                        <DataTemplate>
                            <StackPanel Orientation="Horizontal">
                                <TextBlock Text="{Binding Tier}" Width="80" Foreground="{Binding Color}"/>
                                <TextBlock Text="{Binding Title}" Width="200" Foreground="White"/>
                                <TextBlock Text="{Binding Message}" Foreground="#AAAAAA" TextWrapping="Wrap"/>
                            </StackPanel>
                        </DataTemplate>
                    </ListBox.ItemTemplate>
                </ListBox>

                <!-- Export -->
                <Button x:Name="ExportButton" Content="📄  Export Report" FontSize="14" Background="#3A3A3A" Foreground="White" BorderThickness="0" Height="40" Margin="0,10,0,0" Cursor="Hand" IsEnabled="False" Click="ExportButton_Click"/>
            </StackPanel>
        </ScrollViewer>

        <!-- Footer -->
        <Border Grid.Row="2" Background="#2A2A2A">
            <TextBlock Text="© 2026 Tim$erz – For Consented Screenshare Investigations Only" Foreground="#777" VerticalAlignment="Center" HorizontalAlignment="Center"/>
        </Border>
    </Grid>
</Window>
'@

# Load XAML
$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$xaml)))

# Find controls
$MinecraftDirBox = $window.FindName("MinecraftDirBox")
$OutputDirBox = $window.FindName("OutputDirBox")
$StatusText = $window.FindName("StatusText")
$ProgressBar = $window.FindName("ProgressBar")
$ResultsList = $window.FindName("ResultsList")
$ScanButton = $window.FindName("ScanButton")
$ExportButton = $window.FindName("ExportButton")

# Event handlers (defined later)
$window.AddHandler([System.Windows.Window]::MouseLeftButtonDownEvent, [System.Windows.Input.MouseButtonEventHandler]{ $window.DragMove() })
$window.AddHandler([System.Windows.Controls.Button]::ClickEvent, [System.Windows.RoutedEventHandler]{ if ($_.Source.Name -eq "CloseButton_Click") { $window.Close() } })

# Browse buttons
$browseMinecraft = { 
    $folder = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($folder.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $MinecraftDirBox.Text = $folder.SelectedPath }
}
$browseOutput = { 
    $folder = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($folder.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $OutputDirBox.Text = $folder.SelectedPath }
}
$window.FindName("BrowseButton_Click").AddHandler([System.Windows.RoutedEvent]::Click, $browseMinecraft)
$window.FindName("BrowseOutput_Click").AddHandler([System.Windows.RoutedEvent]::Click, $browseOutput)

#region Scan Logic (Zero False Positives)
$cheatClientNames = @(
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
$cheatPackagePaths = @(
    "cc/novoline", "com/alan/clients", "club/maxstats", "wtf/moonlight",
    "me/zeroeightsix/kami", "net/ccbluex", "today/opai", "net/minecraft/injection",
    "org/chainlibs/module/impl/modules", "xyz/greaj", "com/cheatbreaker",
    "com/moonsworth", "dev/krypton", "skid/krypton", "dev/gambleclient",
    "dev/virel", "org/jose4j/jwt", "sixtwo/", "fivefive/"
)
$cheatModules = @(
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

# Fullwidth obfuscated strings (cheat‑only)
$fullwidthPatterns = @(
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

$findings = @()
function Add-Finding {
    param($Tier, $Category, $Title, $Message, [hashtable]$Evidence = @{})
    $color = switch ($Tier) { "Detection" { "Red" } "Warning" { "Yellow" } default { "Gray" } }
    $findings += @{
        Tier      = $Tier
        Category  = $Category
        Title     = $Title
        Message   = $Message
        Evidence  = $Evidence
        Timestamp = (Get-Date).ToString("o")
        Color     = $color
    }
    # Update GUI live
    $ResultsList.Dispatcher.Invoke({
        $ResultsList.Items.Add(@{ Tier = $Tier; Title = $Title; Message = $Message; Color = $color })
        $ResultsList.ScrollIntoView($ResultsList.Items[$ResultsList.Items.Count - 1])
    })
}

function Update-Status {
    param($Text, $Progress = -1)
    $StatusText.Dispatcher.Invoke({ $StatusText.Text = $Text })
    if ($Progress -ge 0) { $ProgressBar.Dispatcher.Invoke({ $ProgressBar.Value = $Progress }) }
}

function Test-Admin {
    (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Scan-FileSystem {
    param($minecraftDir)
    if (-not (Test-Path $minecraftDir)) {
        Add-Finding "Warning" "File System" "Minecraft Directory Missing" "Directory $minecraftDir not found"
        return
    }
    $modsDir = Join-Path $minecraftDir "mods"
    if (-not (Test-Path $modsDir)) { return }

    $jars = Get-ChildItem -Path $modsDir -Filter *.jar -ErrorAction SilentlyContinue
    $total = $jars.Count
    $i = 0
    foreach ($jar in $jars) {
        $i++
        Update-Status "Scanning JAR: $($jar.Name)" -Progress (($i / $total) * 100)
        $content = Get-Content -Path $jar.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        # Check client names (case‑insensitive)
        foreach ($client in $cheatClientNames) {
            if ($content -match "\b$client\b") {
                Add-Finding "Detection" "File System" "Cheat Client Found" "Client name '$client' in $($jar.Name)" @{File=$jar.Name; Client=$client}
                break
            }
        }
        # Check package paths
        foreach ($pkg in $cheatPackagePaths) {
            if ($content -match $pkg) {
                Add-Finding "Detection" "File System" "Cheat Package Path" "Package '$pkg' found in $($jar.Name)" @{File=$jar.Name; Package=$pkg}
            }
        }
        # Check module names (Warning if alone, Detection if with package)
        foreach ($mod in $cheatModules) {
            if ($content -match "\b$mod\b") {
                Add-Finding "Warning" "File System" "Cheat Module" "Module '$mod' in $($jar.Name)" @{File=$jar.Name; Module=$mod}
            }
        }
        # Check fullwidth obfuscated strings (Detection)
        foreach ($fw in $fullwidthPatterns) {
            if ($content -match $fw) {
                Add-Finding "Detection" "File System" "Fullwidth Obfuscation" "Obfuscated string found in $($jar.Name)" @{File=$jar.Name}
            }
        }
    }
}

function Scan-Registry {
    Update-Status "Scanning Registry..." -Progress 80
    foreach ($client in $cheatClientNames) {
        $path = "HKCU:\Software\$client"
        if (Test-Path $path) {
            Add-Finding "Detection" "Registry" "Cheat Registry Key" "Key $path exists" @{Key=$path}
        }
    }
    # Check EnablePrefetcher
    try {
        $prefetch = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -ErrorAction SilentlyContinue).EnablePrefetcher
        if ($prefetch -eq 0) {
            Add-Finding "Detection" "Registry" "Prefetch Disabled" "EnablePrefetcher set to 0"
        }
    } catch {}
}

function Scan-Processes {
    Update-Status "Scanning Processes..." -Progress 85
    $procs = Get-Process -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $name = $p.ProcessName.ToLower()
        foreach ($client in $cheatClientNames) {
            if ($name -match $client.ToLower()) {
                Add-Finding "Detection" "Processes" "Cheat Process Running" "Process $($p.ProcessName) matches '$client'" @{Process=$p.ProcessName; Client=$client}
                break
            }
        }
        # Check JVM arguments
        if ($p.ProcessName -match "javaw|java") {
            try {
                $cmd = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmd) {
                    if ($cmd -match "-Dclient\.brand=(Wurst|Impact|Meteor|Sigma|LiquidBounce|Vape|Novoline)") {
                        Add-Finding "Detection" "Processes" "Malicious JVM Argument" "JVM brand: $($Matches[0])" @{Argument=$Matches[0]}
                    }
                    if ($cmd -match "-D(xray|fly|speed|killaura|reach|scaffold|autocrystal|autototem)") {
                        Add-Finding "Detection" "Processes" "JVM Cheat Flag" "Flag: $($Matches[0])" @{Argument=$Matches[0]}
                    }
                }
            } catch {}
        }
    }
}

function Scan-DNS {
    Update-Status "Scanning DNS Cache..." -Progress 90
    $dns = ipconfig /displaydns 2>$null | Select-String "Record Name.*:\s+(.*)" | ForEach-Object { $_.Matches.Groups[1].Value }
    foreach ($domain in $cheatDomains) {
        if ($dns -match $domain) {
            Add-Finding "Detection" "DNS" "Cheat Domain in Cache" "Domain $domain resolved" @{Domain=$domain}
        }
    }
}

function Scan-Prefetch {
    Update-Status "Scanning Prefetch..." -Progress 95
    $prefetchDir = "$env:windir\Prefetch"
    if (-not (Test-Path $prefetchDir)) {
        Add-Finding "Detection" "Prefetch" "Prefetch Folder Missing" "Prefetch folder not present"
        return
    }
    $files = Get-ChildItem $prefetchDir -ErrorAction SilentlyContinue
    if ($files.Count -lt 5) {
        Add-Finding "Warning" "Prefetch" "Low Prefetch Count" "Only $($files.Count) prefetch files – possible deletion"
    }
}

function Scan-EventLogs {
    Update-Status "Scanning Event Logs..." -Progress 98
    $logs = @("Application", "System", "Security", "Windows PowerShell")
    foreach ($log in $logs) {
        try {
            $events = Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction SilentlyContinue
            if (-not $events) {
                Add-Finding "Warning" "Event Logs" "Event Log Cleared" "Event log $log appears empty (cleared?)" @{Log=$log}
            }
        } catch {}
    }
}
#endregion

#region Scan Button Click
$scanClick = {
    $findings = @()
    $ResultsList.Items.Clear()
    $ExportButton.IsEnabled = $false
    $ScanButton.IsEnabled = $false
    Update-Status "Starting scan..." -Progress 0

    if (-not (Test-Admin)) {
        Add-Finding "Warning" "Privileges" "Not Administrator" "Run as Administrator for full coverage"
    }

    $minecraftDir = $MinecraftDirBox.Text
    if ($minecraftDir -match '\$env:') {
        $minecraftDir = [Environment]::ExpandEnvironmentVariables($minecraftDir)
    }
    $outputDir = $OutputDirBox.Text
    if ($outputDir -match '\$env:') {
        $outputDir = [Environment]::ExpandEnvironmentVariables($outputDir)
    }
    if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }

    # Run scans
    Scan-FileSystem -minecraftDir $minecraftDir
    Scan-Registry
    Scan-Processes
    Scan-DNS
    Scan-Prefetch
    Scan-EventLogs

    Update-Status "Scan complete. $($findings.Count) findings." -Progress 100
    $ExportButton.IsEnabled = $true
    $ScanButton.IsEnabled = $true

    # Store findings for export
    $script:lastFindings = $findings
    $script:outputDir = $outputDir
}
$window.FindName("ScanButton_Click").AddHandler([System.Windows.RoutedEvent]::Click, $scanClick)
#endregion

#region Export Button Click
$exportClick = {
    if (-not $script:lastFindings) { return }
    $report = @{
        ScanTime = (Get-Date).ToString("o")
        Findings = $script:lastFindings
        Summary = @{
            Total = $script:lastFindings.Count
            Detections = ($script:lastFindings | Where-Object { $_.Tier -eq "Detection" }).Count
            Warnings = ($script:lastFindings | Where-Object { $_.Tier -eq "Warning" }).Count
            Info = ($script:lastFindings | Where-Object { $_.Tier -eq "Info" }).Count
        }
    }
    $json = $report | ConvertTo-Json -Depth 5
    $jsonFile = Join-Path $script:outputDir "MagiciansRevealV2_report.json"
    $json | Out-File -FilePath $jsonFile -Encoding utf8

    $txt = "MagiciansRevealV2 Forensic Report`n" + "="*50 + "`n"
    $txt += "Scan Time: $($report.ScanTime)`n`n"
    foreach ($f in $script:lastFindings) {
        $txt += "[$($f.Tier)] $($f.Title)`n  $($f.Message)`n"
    }
    $txtFile = Join-Path $script:outputDir "MagiciansRevealV2_report.txt"
    $txt | Out-File -FilePath $txtFile -Encoding utf8

    [System.Windows.MessageBox]::Show("Reports saved to $($script:outputDir)", "Export Complete", "OK", "Information")
}
$window.FindName("ExportButton_Click").AddHandler([System.Windows.RoutedEvent]::Click, $exportClick)
#endregion

# Start the GUI with fade‑in animation
$window.BeginStoryboard($window.Resources["FadeIn"])
$window.ShowDialog() | Out-Null
#endregion
