# 打开桌面版 Protégé 并载入题目二的 OWL；若当前会话有可见桌面，则截一张图。
# 用法（PowerShell）：
#   powershell -ExecutionPolicy Bypass -File protege\tools\open_in_protege.ps1
$ErrorActionPreference = "Stop"
$exe  = "D:\tools\Protege-5.6.9\Protege.exe"
$file = "D:\Study\kg-t2\protege\owl\t2-threat-intel.owl"
$shot = "D:\Study\kg-t2\protege\screenshots\protege-t2.png"

$p = Start-Process -FilePath $exe -ArgumentList "`"$file`"" -PassThru
Start-Sleep -Seconds 45
$proc = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
if ($null -eq $proc) {
    Write-Output "Protege process exited before screenshot."
    exit 1
}
Write-Output ("pid={0} title={1}" -f $proc.Id, $proc.MainWindowTitle)

try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $bmp.Save($shot, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Output "screenshot=$shot"
} catch {
    Write-Output ("screenshot failed: {0}" -f $_.Exception.Message)
}
