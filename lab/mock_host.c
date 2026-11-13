/* Mock host for the decision-table lab.
 *
 * Stands in for the 32 bit anti-cheat service: the loader finds it by name,
 * opens it with PROCESS_ALL_ACCESS and injects the stub into it. The stub
 * then opens the mock game and reports the granted mask and the allocation
 * result back, which is exactly what the real stub does.
 *
 * Build:  gcc -m32 -O2 -o MockHost.exe mock_host.c
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    printf("mock_host: pid %lu, alive\n", GetCurrentProcessId());
    for (;;) Sleep(1000);
}
