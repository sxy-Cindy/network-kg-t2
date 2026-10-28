# 用 UI Automation 选中 Protégé 的某个顶层页签并截图。
# 用法：
#   powershell -ExecutionPolicy Bypass -File protege\tools\gui_select_tab.ps1 -TabName Entities -Out ...
param(
    [string]$TabName = "Entities",
    [string]$Out = "D:\Study\kg-t2\protege\screenshots\protege-entities.png",
    [int]$Wait = 3
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

$proc = Get-Process Protege -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $proc) { Write-Output "Protege is not running"; exit 1 }
$root = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)
$cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::TabItem)
$tabs = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
$names = @()
foreach ($t in $tabs) { $names += $t.Current.Name }
Write-Output ("tabs=" + ($names -join " | "))
$target = $null
foreach ($t in $tabs) {
    if ($t.Current.Name -eq $TabName) { $target = $t; break }
}
if ($null -eq $target) { Write-Output "tab not found: $TabName"; exit 2 }
$pat = $target.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)
$pat.Select()
Start-Sleep -Seconds $Wait

$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Output "selected=$TabName screenshot=$Out"
