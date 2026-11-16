$p = 'C:\dev\fortesp\ring0\driver\dbutil_2_3.sys'
$b = [IO.File]::ReadAllBytes($p)

# UTF-16LE strings in the image
Write-Output '--- wide strings ---'
$s = -join ($b | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { "`n" } })
$s -split "`n" | Where-Object { $_.Length -ge 4 } | Sort-Object -Unique |
  Where-Object { $_ -match 'DBUtil|Device|dosdevice|DosDevices|\\\\' } | ForEach-Object { Write-Output ("  " + $_) }

# ASCII strings
Write-Output '--- ascii strings ---'
$a = -join ($b | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { "`n" } })
$a -split "`n" | Where-Object { $_.Length -ge 5 } | Sort-Object -Unique |
  Where-Object { $_ -match 'DBUtil|DosDevice|Physical|\\\\Device' } | ForEach-Object { Write-Output ("  " + $_) }

# hunt for candidate IOCTL codes: dwords in the .text that look like FILE_DEVICE_UNKNOWN ioctls
Write-Output '--- scanning for likely IOCTL constants ---'
$seen = @{}
for ($i = 0; $i -lt $b.Length - 4; $i++) {
    $v = [BitConverter]::ToUInt32($b, $i)
    # FILE_DEVICE_UNKNOWN(0x22) << 16 | (method<<2) | function
    if (($v -band 0xFFFF0000) -eq 0x00220000 -and ($v -band 0x3) -le 3) {
        $c = $v -band 0x3
        $m = ($v -band 0x3C00) -shr 2
        if ($m -ge 0 -and $m -le 3 -and $c -le 3 -and $v -ne 0x00220000) {
            if (-not $seen.ContainsKey($v)) {
                $seen[$v] = @()
                $seen[$v] += $i
            }
        }
    }
}
$seen.Keys | Sort-Object | ForEach-Object {
    Write-Output ("  IOCTL 0x{0:X8}  x{1}" -f $_, $seen[$_].Count)
}
