# 对已打开的桌面版 Protégé 做一次点击并截图。
# 用法：
#   powershell -ExecutionPolicy Bypass -File protege\tools\gui_capture.ps1 -X 215 -Y 186 -Out protege\screenshots\entities.png
param(
    [int]$X = -1,
    [int]$Y = -1,
    [string]$Out = "D:\Study\kg-t2\protege\screenshots\protege-t2.png",
    [int]$Wait = 3
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
    [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, int e);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
}
"@
# 关键：进程若不声明 DPI 感知，GetSystemMetrics / SetCursorPos 都在 150% 缩放后的
# 虚拟坐标系（1707x1067）里，而真实屏幕是 2560x1600，点击会整体偏移。
[Win32]::SetProcessDPIAware() | Out-Null
$proc = Get-Process Protege -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $proc) { Write-Output "Protege is not running"; exit 1 }
[Win32]::ShowWindow($proc.MainWindowHandle, 9) | Out-Null
[Win32]::SetForegroundWindow($proc.MainWindowHandle) | Out-Null
try { [Microsoft.VisualBasic.Interaction]::AppActivate($proc.Id) | Out-Null } catch {}
Start-Sleep -Milliseconds 800
if ($X -ge 0 -and $Y -ge 0) {
    [Win32]::SetCursorPos($X, $Y) | Out-Null
    Start-Sleep -Milliseconds 200
    $pt = New-Object Win32+POINT
    [Win32]::GetCursorPos([ref]$pt) | Out-Null
    Write-Output ("cursor=({0},{1})" -f $pt.X, $pt.Y)
    [Win32]::mouse_event(2, 0, 0, 0, 0)  # left down
    [Win32]::mouse_event(4, 0, 0, 0, 0)  # left up
}
Start-Sleep -Seconds $Wait
$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Output "screenshot=$Out"
