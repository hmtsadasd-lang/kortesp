# GNU-as version of shared/src/stubs.asm (the original stays MASM for the
# MSVC solution). Same stubs, same calling convention, x64 only.
#
# The MASM originals read:
#     mov r10, rcx
#     mov eax, <the syscall number>   (edx / r8d / r9d / [rsp+..h])
# so the translation has to keep that direction: r10 gets a copy of the
# first argument and eax gets the number. Reversing the moves clobbers the
# first argument and every syscall then runs with a garbage handle.
    .intel_syntax noprefix

    .text

    .globl sc1
sc1:
    mov r10, rcx
    mov eax, edx
    syscall
    ret

    .globl sc2
sc2:
    mov r10, rcx
    mov eax, r8d
    syscall
    ret

    .globl sc3
sc3:
    mov r10, rcx
    mov eax, r9d
    syscall
    ret

    .globl sc4
sc4:
    mov r10, rcx
    mov eax, dword ptr [rsp+0x28]
    syscall
    ret

    .globl sc5
sc5:
    mov r10, rcx
    mov eax, dword ptr [rsp+0x30]
    syscall
    ret

    .globl sc6
sc6:
    mov r10, rcx
    mov eax, dword ptr [rsp+0x38]
    syscall
    ret

    .globl sc7
sc7:
    mov r10, rcx
    mov eax, dword ptr [rsp+0x40]
    syscall
    ret

    .globl sc9
sc9:
    mov r10, rcx
    mov eax, dword ptr [rsp+0x50]
    syscall
    ret

    .globl sc11
sc11:
    mov r10, rcx
    mov eax, dword ptr [rsp+0x60]
    syscall
    ret

    .globl __chkstk
__chkstk:
    push rcx
    push rax
    cmp rax, 0x1000
    lea rcx, [rsp+0x18]
    jb chk_last
chk_loop:
    sub rcx, 0x1000
    test qword ptr [rcx], rcx
    sub rax, 0x1000
    cmp rax, 0x1000
    ja chk_loop
chk_last:
    sub rcx, rax
    test qword ptr [rcx], rcx
    pop rax
    pop rcx
    ret
