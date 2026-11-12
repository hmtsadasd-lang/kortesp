$sig = @'
[DllImport("kernel32", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tpl);
[DllImport("kernel32", SetLastError=true)]
public static extern bool CloseHandle(IntPtr h);
'@
Add-Type -MemberDefinition $sig -Name F -Namespace T

$path = Join-Path $env:TEMP 'fortesp_probe.log'
Remove-Item $path -ErrorAction SilentlyContinue

foreach ($mask in @([uint32]0x00100004, [uint32]0x40000000, [uint32]0x00000004)) {
    $h = [T.F]::CreateFileW($path, $mask, 3, [IntPtr]::Zero, 4, 0x80, [IntPtr]::Zero)
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Output ("mask=0x{0:X8} handle={1} err={2}" -f $mask, $h, $err)
    if ($h -ne [IntPtr](-1)) { [void][T.F]::CloseHandle($h); break }
}
if (Test-Path $path) { Write-Output ("created, size=" + (Get-Item $path).Length) } else { Write-Output "not created" }
