// Minimal libc bits the MinGW build needs when linking without the CRT
// (-nostdlib, same as the MSVC /NODEFAULTLIB payload build).
//
// GCC recognises the strlen/wcslen idiom in the inline helpers and lowers it
// to a call to the builtin, so the symbols have to exist.
#include <cstddef>
#include <cstdint>

extern "C" size_t strlen(const char* s) {
    size_t n = 0;
    while (s[n]) ++n;
    return n;
}

extern "C" size_t wcslen(const wchar_t* s) {
    size_t n = 0;
    while (s[n]) ++n;
    return n;
}
