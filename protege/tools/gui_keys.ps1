# 向已打开的 Protégé 发送按键并截图。
# 用法：
#   powershell -ExecutionPolicy Bypass -File protege\tools\gui_keys.ps1 -Keys "^{TAB}" -Out ...
param(
    [string]$Keys = "^{TAB}",
    [string]$Out = "D:\Study\kg-t2\protege\screenshots\protege-t2.png",
    [int]$Wait = 2
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
$proc = Get-Process Protege -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $proc) { Write-Output "Protege is not running"; exit 1 }
[Microsoft.VisualBasic.Interaction]::AppActivate($proc.Id) | Out-Null
Start-Sleep -Milliseconds 800
[System.Windows.Forms.SendKeys]::SendWait($Keys)
Start-Sleep -Seconds $Wait
$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Output "keys=$Keys screenshot=$Out"
