# Who may write the game directory: the real answer.
#
# "BUILTIN\Users: FullControl" in Get-Acl is not the same as "this process may
# write": the ACE may be denied later in the list, the token may be restricted,
# and an owner ACE from an older install may not match this account's SID.
# This asks the kernel to do the access check for the *current* token and for
# the pre-elevation one (the elevated token is a copy of the filtered one, so
# MembershipCheck on the same SID set answers for the unelevated case).
$dir = 'C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64'
"current identity: " + [Security.Principal.WindowsIdentity]::GetCurrent().Name
"elevated: " + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Acl {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool GetNamedSecurityInfoW(string name, int type, int info,
      out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr sd);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool AccessCheck(IntPtr sd, IntPtr token, uint access,
      IntPtr mapping, IntPtr privset, out uint granted, out bool status, IntPtr err);
  [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern IntPtr MapGenericMask(ref uint access, IntPtr mapping);
}
"@
$p = $dir
[IntPtr]$o=[IntPtr]::Zero; [IntPtr]$g=[IntPtr]::Zero; [IntPtr]$d=[IntPtr]::Zero
[IntPtr]$s=[IntPtr]::Zero; [IntPtr]$sd=[IntPtr]::Zero
# SE_FILE_OBJECT = 1, DACL_SECURITY_INFORMATION = 4
$r = [Acl]::GetNamedSecurityInfoW($p, 1, 4, [ref]$o, [ref]$g, [ref]$d, [ref]$s, [ref]$sd)
"GetNamedSecurityInfo: $r err=" + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
[IntPtr]$tok = [IntPtr]::Zero
"Acl::OpenProcessToken: " + [Acl]::OpenProcessToken([Acl]::GetCurrentProcess(), 8, [ref]$tok)
# FILE_ADD_FILE = 2, FILE_WRITE_DATA = 2 -> ask for DIR creation rights
$want = 0x2
[uint32]$got = 0
[bool]$ok = $false
$mapping = [Runtime.InteropServices.Marshal]::AllocHGlobal(16)   # GENERIC_MAPPING {rd,wr,ex,all}
$privset = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)    # PRIVILEGE_SET
$err = [Runtime.InteropServices.Marshal]::AllocHGlobal(4)
$res = [Acl]::AccessCheck($sd, $tok, $want, $mapping, $privset, [ref]$got, [ref]$ok, $err)
"AccessCheck(FILE_ADD_FILE): ok=$res granted=0x{0:X} status=$ok" -f $got
