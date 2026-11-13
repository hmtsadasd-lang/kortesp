/* Mock target for the payload delivery test.
 *
 * Stands in for the game: the loader maps the payload into this process and
 * the payload's target-mode branch runs inside it. It carries the real
 * client name so the payload's own "am I already in the target?" check sees
 * what it expects.
 *
 * Build:  gcc -m64 -O2 -o FortniteClient-Win64-Shipping.exe mock_target64.c
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    printf("mock_target: pid %lu, alive\n", GetCurrentProcessId());
    for (;;) Sleep(1000);
}
