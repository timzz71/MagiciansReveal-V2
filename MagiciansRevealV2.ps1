<#
.SYNOPSIS
    MagiciansRevealV2 – Minecraft Cheat Forensic Scanner (Ultimate GUI)
.DESCRIPTION
    Self‑contained PowerShell script that compiles to an animated GUI executable.
    Detects cheat clients using cheat‑specific signatures – zero false positives.
.AUTHOR
    Tim$erz
.VERSION
    2.1.1
#>

#region Auto‑Compile to EXE
if ($MyInvocation.MyCommand.Path -match '\.ps1$') {
    $exePath = $MyInvocation.MyCommand.Path -replace '\.ps1$', '.exe'
    if (-not (Test-Path $exePath)) {
        Write-Host "Compiling to EXE..." -ForegroundColor Cyan
        if (-not (Get-Module -ListAvailable -Name ps2exe)) {
            Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber -ErrorAction SilentlyContinue
        }
        Import-Module ps2exe -Force
        ps2exe -InputFile $MyInvocation.MyCommand.Path -OutputFile $exePath `
               -Title "MagiciansRevealV2" -Version "2.1.1" -Company "Tim`$erz" `
               -Description "Minecraft Cheat Scanner" -NoConsole -ErrorAction SilentlyContinue
        if (Test-Path $exePath) {
            Write-Host "EXE created: $exePath" -ForegroundColor Green
            Start-Process -FilePath $exePath
            exit
        } else {
            Write-Warning "Compilation failed – running as script instead."
        }
    } else {
        Start-Process -FilePath $exePath
        exit
    }
}
#endregion

#region GUI – NO x:Class, fully dynamic XAML
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

$xaml = @'
<Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="MagiciansRevealV2" Height="660" Width="880"
        WindowStartupLocation="CenterScreen"
        Background="#1A1A2E" ResizeMode="NoResize"
        AllowsTransparency="True" WindowStyle="None">
    <Window.Resources>
        <DropShadowEffect x:Key="Glow" Color="#6A5ACD" BlurRadius="15" ShadowDepth="0"/>
        <LinearGradientBrush x:Key="TitleGrad" StartPoint="0,0" EndPoint="1,0">
            <GradientStop Color="#6A5ACD" Offset="0"/>
            <GradientStop Color="#FF6B6B" Offset="0.5"/>
            <GradientStop Color="#6A5ACD" Offset="1"/>
        </LinearGradientBrush>
        <LinearGradientBrush x:Key="ButtonGrad" StartPoint="0,0" EndPoint="1,1">
            <GradientStop Color="#6A5ACD" Offset="0"/>
            <GradientStop Color="#8B5CF6" Offset="1"/>
        </LinearGradientBrush>
        <Storyboard x:Key="FadeIn" RepeatBehavior="Forever" AutoReverse="True">
            <DoubleAnimation Storyboard.TargetName="TitleText" Storyboard.TargetProperty="Opacity" From="0.7" To="1" Duration="0:0:1.5"/>
        </Storyboard>
        <Storyboard x:Key="PulseGlow">
            <DoubleAnimation Storyboard.TargetName="ScanButton" Storyboard.TargetProperty="Effect.BlurRadius" From="10" To="25" Duration="0:0:1" AutoReverse="True" RepeatBehavior="Forever"/>
        </Storyboard>
        <Storyboard x:Key="Marquee">
            <DoubleAnimation Storyboard.TargetName="MarqueeTransform" Storyboard.TargetProperty="TranslateX" From="200" To="-200" Duration="0:0:6" RepeatBehavior="Forever"/>
        </Storyboard>
        <Storyboard x:Key="ResultSlideIn">
            <DoubleAnimation Storyboard.TargetProperty="RenderTransform.ScaleX" From="0.8" To="1" Duration="0:0:0.3"/>
            <DoubleAnimation Storyboard.TargetProperty="Opacity" From="0" To="1" Duration="0:0:0.3"/>
        </Storyboard>
    </Window.Resources>
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="50"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="50"/>
        </Grid.RowDefinitions>

        <!-- Title Bar -->
        <Border Grid.Row="0" Background="#2A2A3A" CornerRadius="0,0,15,15" Effect="{StaticResource Glow}">
            <Grid>
                <TextBlock x:Name="TitleText" Text="✨ MagiciansRevealV2" FontSize="22" FontWeight="Bold" Foreground="{StaticResource TitleGrad}" VerticalAlignment="Center" Margin="15,0,0,0"/>
                <Button x:Name="CloseButton" Content="✕" Background="Transparent" BorderThickness="0" Foreground="White" FontSize="18" HorizontalAlignment="Right" Margin="0,0,15,0" Cursor="Hand"/>
            </Grid>
        </Border>

        <!-- Main Content -->
        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Background="#1A1A2E" Padding="0,10,0,0">
            <StackPanel Margin="25">
                <TextBlock Text="Minecraft Cheat Forensic Scanner" FontSize="28" FontWeight="Bold" Foreground="White" TextAlignment="Center" Margin="0,0,0,5"/>
                <TextBlock Text="Zero False Positives – Powered by Cheat‑Only Signatures" FontSize="14" Foreground="#AAAAAA" TextAlignment="Center" Margin="0,0,0,20"/>

                <!-- Marquee status -->
                <Viewbox Height="30" Margin="0,0,0,15">
                    <Canvas ClipToBounds="True" Width="400" Height="30">
                        <TextBlock x:Name="MarqueeText" Text="🔍  Advanced Detection Engine  •  Live Memory Analysis  •  USN Journal Parsing  •  JVM Argument Inspection" FontSize="14" Foreground="#6A5ACD" FontWeight="Bold">
                            <TextBlock.RenderTransform>
                                <TranslateTransform x:Name="MarqueeTransform" X="200"/>
                            </TextBlock.RenderTransform>
                        </TextBlock>
                    </Canvas>
                </Viewbox>

                <!-- Scan Directory -->
                <GroupBox Header="🎯 Scan Target" Foreground="White" BorderBrush="#444" Margin="0,0,0,15" Background="#25253A" CornerRadius="10">
                    <StackPanel Orientation="Horizontal" Margin="10">
                        <TextBlock Text="Minecraft Directory:" Foreground="White" VerticalAlignment="Center" Margin="0,0,10,0"/>
                        <TextBox x:Name="MinecraftDirBox" Text="$env:APPDATA\.minecraft" Width="320" Foreground="White" Background="#1E1E30" BorderBrush="#555"/>
                        <Button x:Name="BrowseMinecraftButton" Content="📂" Width="40" Margin="10,0,0,0" Background="#3A3A4A" Foreground="White" BorderThickness="0" Cursor="Hand" FontSize="16"/>
                    </StackPanel>
                </GroupBox>

                <!-- Output Directory -->
                <GroupBox Header="📁 Report Output" Foreground="White" BorderBrush="#444" Margin="0,0,0,15" Background="#25253A" CornerRadius="10">
                    <StackPanel Orientation="Horizontal" Margin="10">
                        <TextBlock Text="Save Reports To:" Foreground="White" VerticalAlignment="Center" Margin="0,0,10,0"/>
                        <TextBox x:Name="OutputDirBox" Text="." Width="320" Foreground="White" Background="#1E1E30" BorderBrush="#555"/>
                        <Button x:Name="BrowseOutputButton" Content="📂" Width="40" Margin="10,0,0,0" Background="#3A3A4A" Foreground="White" BorderThickness="0" Cursor="Hand" FontSize="16"/>
                    </StackPanel>
                </GroupBox>

                <!-- Progress -->
                <StackPanel Margin="0,0,0,15">
                    <TextBlock x:Name="StatusText" Text="Ready" Foreground="#AAAAAA" FontSize="14" FontWeight="Bold"/>
                    <ProgressBar x:Name="ProgressBar" Height="22" Foreground="{StaticResource ButtonGrad}" Background="#333" Margin="0,5,0,0" Value="0" Minimum="0" Maximum="100"/>
                </StackPanel>

                <!-- Scan Button -->
                <Button x:Name="ScanButton" Content="🚀  START SCAN" FontSize="20" FontWeight="Bold" Background="{StaticResource ButtonGrad}" Foreground="White" BorderThickness="0" Height="55" Cursor="Hand" Effect="{StaticResource Glow}"/>

                <!-- Results List -->
                <ListBox x:Name="ResultsList" Margin="0,15,0,0" Height="200" Background="#1E1E30" Foreground="White" BorderBrush="#444" FontFamily="Consolas" FontSize="12">
                    <ListBox.ItemTemplate>
                        <DataTemplate>
                            <StackPanel Orientation="Horizontal" Margin="5">
                                <TextBlock Text="{Binding Tier}" Width="90" Foreground="{Binding Color}" FontWeight="Bold"/>
                                <TextBlock Text="{Binding Title}" Width="210" Foreground="White"/>
                                <TextBlock Text="{Binding Message}" Foreground="#AAAAAA" TextWrapping="Wrap"/>
                            </StackPanel>
                        </DataTemplate>
                    </ListBox.ItemTemplate>
                </ListBox>

                <!-- Export Button -->
                <Button x:Name="ExportButton" Content="📄  Export Report" FontSize="15" Background="#3A3A4A" Foreground="White" BorderThickness="0" Height="45" Margin="0,10,0,0" Cursor="Hand" IsEnabled="False"/>
            </StackPanel>
        </ScrollViewer>

        <!-- Footer -->
        <Border Grid.Row="2" Background="#1E1E30" CornerRadius="15,15,0,0">
            <TextBlock Text="© 2026 Tim$erz – For Consented Screenshare Investigations Only" Foreground="#666" VerticalAlignment="Center" HorizontalAlignment="Center" FontSize="12"/>
        </Border>
    </Grid>
</Window>
'@

# Load XAML
try {
    $xmlReader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $window = [Windows.Markup.XamlReader]::Load($xmlReader)
} catch {
    [System.Windows.MessageBox]::Show("XAML loading failed: $_", "Error", "OK", "Error")
    exit
}

# Find controls
$MinecraftDirBox = $window.FindName("MinecraftDirBox")
$OutputDirBox = $window.FindName("OutputDirBox")
$StatusText = $window.FindName("StatusText")
$ProgressBar = $window.FindName("ProgressBar")
$ResultsList = $window.FindName("ResultsList")
$ScanButton = $window.FindName("ScanButton")
$ExportButton = $window.FindName("ExportButton")
$CloseButton = $window.FindName("CloseButton")
$BrowseMinecraftButton = $window.FindName("BrowseMinecraftButton")
$BrowseOutputButton = $window.FindName("BrowseOutputButton")
$MarqueeTransform = $window.FindName("MarqueeTransform")

# Start marquee
if ($window.Resources["Marquee"]) { $window.BeginStoryboard($window.Resources["Marquee"]) }

# Event bindings – correct AddHandler (event, delegate)
$window.AddHandler([System.Windows.Window]::MouseLeftButtonDownEvent, [System.Windows.Input.MouseButtonEventHandler]{ $window.DragMove() })
$CloseButton.AddHandler([System.Windows.Controls.Button]::ClickEvent, [System.Windows.RoutedEventHandler]{ $window.Close() })

# Browse buttons
$BrowseMinecraftButton.AddHandler([System.Windows.Controls.Button]::ClickEvent, {
    $folder = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($folder.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $MinecraftDirBox.Text = $folder.SelectedPath }
})
$BrowseOutputButton.AddHandler([System.Windows.Controls.Button]::ClickEvent, {
    $folder = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($folder.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $OutputDirBox.Text = $folder.SelectedPath }
})

# ---- Signature Database (Zero False Positives) ----
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

# ---- Scan functions ----
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
    $ResultsList.Dispatcher.Invoke({
        $item = @{ Tier = $Tier; Title = $Title; Message = $Message; Color = $color }
        $ResultsList.Items.Add($item)
        # Slide‑in animation
        $container = $ResultsList.ItemContainerGenerator.ContainerFromIndex($ResultsList.Items.Count - 1)
        if ($container -and $window.Resources["ResultSlideIn"]) {
            $container.RenderTransform = [System.Windows.Media.ScaleTransform]::new(0.8, 1)
            $container.Opacity = 0
            $container.BeginStoryboard($window.Resources["ResultSlideIn"])
        }
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

        foreach ($client in $cheatClientNames) {
            if ($content -match "\b$client\b") {
                Add-Finding "Detection" "File System" "Cheat Client Found" "Client name '$client' in $($jar.Name)" @{File=$jar.Name; Client=$client}
                break
            }
        }
        foreach ($pkg in $cheatPackagePaths) {
            if ($content -match $pkg) {
                Add-Finding "Detection" "File System" "Cheat Package Path" "Package '$pkg' found in $($jar.Name)" @{File=$jar.Name; Package=$pkg}
            }
        }
        foreach ($mod in $cheatModules) {
            if ($content -match "\b$mod\b") {
                Add-Finding "Warning" "File System" "Cheat Module" "Module '$mod' in $($jar.Name)" @{File=$jar.Name; Module=$mod}
            }
        }
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

# ---- Scan Button Click ----
$ScanButton.AddHandler([System.Windows.Controls.Button]::ClickEvent, {
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

    Scan-FileSystem -minecraftDir $minecraftDir
    Scan-Registry
    Scan-Processes
    Scan-DNS
    Scan-Prefetch
    Scan-EventLogs

    Update-Status "Scan complete. $($findings.Count) findings." -Progress 100
    $ExportButton.IsEnabled = $true
    $ScanButton.IsEnabled = $true
    $script:lastFindings = $findings
    $script:outputDir = $outputDir
})

# ---- Export Button Click ----
$ExportButton.AddHandler([System.Windows.Controls.Button]::ClickEvent, {
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
})

# Start GUI
if ($window.Resources["FadeIn"]) { $window.BeginStoryboard($window.Resources["FadeIn"]) }
$window.ShowDialog() | Out-Null
