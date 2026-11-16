$ErrorActionPreference = 'Stop'
$dst = 'C:\dev\fortesp\ring0\driver\dbutil_2_3.sys'
$url = 'https://raw.githubusercontent.com/VoidSec/VulnerableWindowsDrivers/main/dbutil_2_3.sys'
$expected = '0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5'

Write-Output 'downloading...'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing -TimeoutSec 120

$len = (Get-Item $dst).Length
Write-Output ("size: " + $len + " bytes")

$hash = (Get-FileHash -Path $dst -Algorithm SHA256).Hash
Write-Output ("sha256: " + $hash)
if ($hash -eq $expected) {
    Write-Output 'HASH MATCH - matches the VoidSec/VulnerableWindowsDrivers listing'
} else {
    Write-Output ("HASH MISMATCH - expected " + $expected)
}

# PE sanity: MZ header, machine type, and the Authenticode signer
$fs = [IO.File]::OpenRead($dst)
$br = New-Object IO.BinaryReader($fs)
$fs.Position = 0
$mz = $br.ReadUInt16()
$fs.Position = 0x3C
$peOff = $br.ReadUInt32()
$fs.Position = $peOff
$pe = $br.ReadUInt32()
$machine = $br.ReadUInt16()
Write-Output ("MZ=0x{0:X4}  PE=0x{1:X4}  machine=0x{2:X4}" -f $mz, $pe, $machine)
$fs.Close()

$sig = Get-AuthenticodeSignature -FilePath $dst
Write-Output ("authenticode: " + $sig.Status + " / " + $sig.SignerCertificate.Subject)
Write-Output ("certificate thumbprint: " + $sig.SignerCertificate.Thumbprint)
