# Driver image

`DBUtil_2_3.sys` is the **Dell BIOS Flash Utility driver**. It ships inside
Dell's BIOS update packages and is installed as a kernel service so the flash
tool can write the BIOS ROM from inside Windows.

It exposes a device `\\.\DBUtil_2_3` with IOCTLs that read and write
arbitrary physical memory. The weakness in it is **CVE-2021-21551** — the
access control on those IOCTLs is wrong, so any unprivileged process can use
it as a physical-memory read/write primitive. That is what
`ring0/src/r0.cpp` uses.

The driver is legitimately signed by Dell. It is on Microsoft's
vulnerable-driver blocklist because of the vulnerability, not because it is
malware.

---

## ⚠ Safety — read this before running anything

This driver **bugchecked this machine four times**. Two of those were our own
fault: the IOCTL table was swapped, so every "physical read" was a physical
*write* of a zero-filled buffer, and the CR3 scan stamped zeros over the start
of eight million pages. That is fixed and now self-verified at startup. The
driver is also old and does not handle being stopped or loaded twice.

**Never do these:**

| Don't | Why |
|---|---|
| `sc stop DBUtil_2_3` | The driver is `NOT_STOPPABLE` / `IGNORES_SHUTDOWN`. The stop fails, the service ends up half-deleted, and the driver stays loaded with no owner. |
| `sc delete` while running | Removes the service but leaves the driver loaded and unowned. |
| `copy /y` over the `.sys` while loaded | The on-disk image and the mapped image diverge. |
| Start a second instance | `IoCreateDevice(\Device\DBUtil_2_3)` fails on the second one and the driver half-initialises. |

**Do this instead:** load it once, leave it running, let a reboot unload it.
`run_r0.bat` already does this — it detects an already-loaded driver and
does not touch it.

If the driver is already loaded and you still want it gone, **reboot**. Do
not try to stop it.

---

## Getting it

`fetch_driver.ps1` downloads it and verifies it:

```bat
cd C:\dev\fortesp\ring0
powershell -ExecutionPolicy Bypass -File driver\fetch_driver.ps1
```

It checks:

- size 14840 bytes
- SHA256 `0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5`
  (matches the VoidSec/VulnerableWindowsDrivers listing)
- Authenticode `Valid`, signer `CN=Dell Inc.`, thumbprint
  `E308E5B7A6F8A24574E08DB9F9FA0AD939103910`

The file lands in `driver\dbutil_2_3.sys`.

### Where it comes from

It is the Dell BIOS flash utility driver. Any Dell BIOS update package
contains it — the IOCTL interface is identical across models and years — but
you do not need a Dell machine to use it. On this box (an Acer Aspire
A715-51G) there is no local copy, so it has to be downloaded.

`driver/analyze_sys.ps1` and `driver/disasm.bat` are the scripts that were
used to read the IOCTL codes and request layouts out of the shipped image.

---

## IOCTL interface

Read out of the driver's IRP dispatch, not guessed. Four primitives, and the
two pairs are **not** interchangeable:

| IOCTL | Meaning | Request layout | Length |
|---|---|---|---|
| `0x9B0C1F40` | **physical read** | `{ u64 header; u64 physaddr; u8 payload[]; }` | `0x10 + n` |
| `0x9B0C1F44` | **physical write** | `{ u64 header; u64 physaddr; u8 payload[]; }` | `0x10 + n` |
| `0x9B0C1EC4` | **kernel-VA read** | `{ u64 header; u64 va; u64 offset; u8 payload[]; }` | `0x18 + n` |
| `0x9B0C1EC8` | **kernel-VA write** | `{ u64 header; u64 va; u64 offset; u8 payload[]; }` | `0x18 + n` |

The physical pair maps the range with `MmMapIoSpace(..., MmNonCached)` and
copies in/out. The kernel-VA pair `memmove`s in the caller's thread context,
i.e. through the normal cached mapping.

**The distinction is a safety property, not a detail.** Writing kernel
structures through the non-cached physical mapping leaves stale lines in cores
that are reading the same structure; and using the physical *write* handler for
a read stamps the zero-filled request buffer into physical memory.

An earlier revision of this file had the two columns swapped (`0x9B0C1F44`
listed as read). That is what zeroed the first 8 bytes of every 4 KiB page
during the CR3 scan and produced the 0x50/0xEF bugchecks. `r0::init()` now
proves the direction before anything else runs: it reads a handful of low
physical addresses that carry non-zero firmware data and rejects an all-zero
result. Deliberately **no write probe** — guessing which handler is the write
is how you get a bugcheck, and the only writes the tool makes are the cloak's,
which are dry-run by default.

The kernel-VA write target is `va + offset` (offset is read as 32-bit; the code
passes 0). The rest of the driver's IOCTLs are port I/O and query handlers.

The request's first 8 bytes must be zero, or match the cached value from the
previous call. Leave the header zeroed.

---

## Blocklist

Two independent things can stop this driver, and they fail differently.

**1. Windows / HVCI blocklist — a load failure.** This box has Microsoft
vulnerable-driver blocklist enforcement off:

```
HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy
    VerifiedAndReputablePolicyState = 0x0
```

so `dbutil_2_3.sys` loads. If a Windows update or Memory Integrity turns
enforcement on, `sc start` fails. That is a **load failure, not a detection**:
the driver simply never appears, and `run_r0.bat` reports it.

**2. Easy Anti-Cheat — a *client* refusal.** Since mid-2026 EAC recognises this
binary and Fortnite will not launch while it is loaded, regardless of what the
kernel blocklist says. This is not a load failure; it is EAC naming the
driver. The only counter in this tree is the module-list cloak
(`cloak::apply(true)`), and that is necessary but probably not sufficient —
`\Device\DBUtil_2_3` and `\??\DBUtil_2_3` survive it.

Sequence that actually tells you something:

1. `--probe` with a working read path (driver only, no game).
2. `--cloak` dry run, review the two writes.
3. `--cloak-commit`, then launch Fortnite.
4. If EAC still names `DBUtil_2_3`, the module list was not the tell. Next
   cheapest move is running the driver under a random service name and random
   image name (defeats name matching, not hashing); after that the driver has
   to be replaced. `r0::Backend` is the seam — nothing above it knows which
   driver is in use.

---

## If you would rather not use a vulnerable driver

Two alternatives, both more work:

**A driver you build yourself.** Needs the Windows Driver Kit and a signing
certificate. This box has no MSVC and no WDK, so this means installing Visual
Studio Build Tools plus the WDK (multi-GB) and enabling test signing
(`bcdedit /set testsigning on`, which needs a reboot). The payoff: no CVE
dependency, no blocklist exposure, and an IOCTL interface you design.

**Keep using `--mock`.** `out\fortesp_r0.exe --mock` exercises the entire
stack — page walk, PEB/LDR module walk, the offset chain, FString decoding,
projection — against a synthetic target built in memory. It needs no driver
and no game. What it cannot do is prove the *offsets* against a real client,
because the synthetic target is built from the same `offsets.hpp`.
