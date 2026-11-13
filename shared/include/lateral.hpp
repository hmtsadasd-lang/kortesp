// Lateral movement inside the client, without a handle.
//
// Measured constraints (docs/SESSION_NOTES.md):
//   * every handle to the client is capped at 0x11F145 - no VM_WRITE, VM_READ,
//     VM_OPERATION, CREATE_THREAD - and SetSecurityInfo is refused even from
//     the object's owner, so a DLL cannot write itself into a remote call;
//   * the client is not PPL, has no mitigation policy beyond DEP, and loads
//     almost nothing from its own directory, so name hijacking in Win64 has
//     nowhere to land except the libraries that self-validate.
//
// What is left is the user-mode boundary itself: objects the client's own
// threads hand to other processes, and points where the client asks the OS to
// run something on its behalf. This header surveys those points from inside a
// process that the client is talking to, and reports which of them are open
// *here* - measured, not assumed. Every check is read-only; nothing is
// installed unless `arm()` is called for a specific vector.
//
// The vectors, and why each one is interesting:
//
//  1. window subclass / shell hooks - the client has an HWND in this desktop
//     and runs a message loop; SetWindowsHookEx from a process on the same
//     desktop gets loaded *into* every GUI process of that desktop, and the
//     client loads it as a module (a real, file-backed load).
//  2. window-property / WM_COPYDATA round trip - confirm the client's message
//     loop can be reached at all, which is the precondition for 1 and 7.
//  3. WndProc replacement in the client's process - needs remote write, so
//     expected closed; measured so the answer is on record.
//  4. named-pipe impersonation of the client's own token - what a pipe/server
//     on the box can obtain from the client when *it* connects to us.
//  5. DLL search-order observation in the client's loader (via a probe image
//     if one is already running there): which directory the client looks in
//     first for a bare name.
//  6. CWD / AppPaths / KnownDLLs - registry or object-manager names the
//     loader consults *before* the application directory.
//  7. IME / TS / input-startup: the client asks the OS for a text-input
//     server and a "hardware" input layer through its own window; those are
//     processes on this desktop, not in the client.
#pragma once
#include <windows.h>
#include <cstdint>

namespace lateral {

enum class state {
    closed,     // the OS refused it here
    open,       // the OS allowed it here
    unknown     // needs a probe image inside the client to answer
};

struct finding {
    const wchar_t* name;      // stable id
    state          st;
    const wchar_t* detail;    // one line, no formatting needed by the caller
};

// 16 slots is enough for the vectors in this file plus room for new ones.
void report(finding* out, int* count);

// Arm one vector by name. Returns false when the name is unknown or the OS
// refuses the operation; `stat` receives what the OS said.
bool arm(const wchar_t* name, const wchar_t* target_exe, DWORD* stat);

} // namespace lateral
