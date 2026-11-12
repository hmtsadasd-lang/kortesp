.code

sc1 PROC
    mov r10, rcx
    mov eax, edx
    syscall
    ret
sc1 ENDP

sc2 PROC
    mov r10, rcx
    mov eax, r8d
    syscall
    ret
sc2 ENDP

sc3 PROC
    mov r10, rcx
    mov eax, r9d
    syscall
    ret
sc3 ENDP

sc4 PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+28h]
    syscall
    ret
sc4 ENDP

sc5 PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+30h]
    syscall
    ret
sc5 ENDP

sc6 PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+38h]
    syscall
    ret
sc6 ENDP

sc7 PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+40h]
    syscall
    ret
sc7 ENDP

sc9 PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+50h]
    syscall
    ret
sc9 ENDP

sc11 PROC
    mov r10, rcx
    mov eax, dword ptr [rsp+60h]
    syscall
    ret
sc11 ENDP

__chkstk PROC
    push rcx
    push rax
    cmp rax, 1000h
    lea rcx, [rsp+18h]
    jb  short chk_last
chk_loop:
    sub rcx, 1000h
    test qword ptr [rcx], rcx
    sub rax, 1000h
    cmp rax, 1000h
    ja  chk_loop
chk_last:
    sub rcx, rax
    test qword ptr [rcx], rcx
    pop rax
    pop rcx
    ret
__chkstk ENDP

END