$sig = @'
[DllImport("kernel32", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr LoadLibraryW(string p);
'@
Add-Type -MemberDefinition $sig -Name K32 -Namespace T

$log = Join-Path $env:TEMP 'fortesp2.log'
Remove-Item $log -ErrorAction SilentlyContinue

$h = [T.K32]::LoadLibraryW('C:\dev\fortesp\out\payload.dll')
$err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Output ("handle=" + $h)
Write-Output ("lasterror=" + $err)
if (Test-Path $log) { Write-Output "--- log ---"; Get-Content $log } else { Write-Output "NO LOG" }
