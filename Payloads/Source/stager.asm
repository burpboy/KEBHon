; ============================================================================
; stager.asm — PIC shellcode, x86_64 Linux, direct syscalls
; Build: nasm -f bin -o stager.bin stager.asm
; ============================================================================
BITS 64
DEFAULT REL

%define SYS_write       1
%define SYS_execve      59
%define SYS_exit_group  231

global _start
section .text
_start:
    ; ---- banner: "stager:ok\n" ----
    mov     eax, SYS_write
    mov     edi, 1
    lea     rsi, [rel msg_banner]
    mov     edx, msg_banner_len
    syscall

    ; ---- argv = { "/bin/sh", "-c", "echo stager-ok", NULL } ----
    sub     rsp, 32
    lea     rax, [rel path_sh]
    mov     [rsp +  0], rax
    lea     rax, [rel arg_dash_c]
    mov     [rsp +  8], rax
    lea     rax, [rel arg_cmd]
    mov     [rsp + 16], rax
    mov     qword [rsp + 24], 0

    ; ---- execve("/bin/sh", argv, NULL) ----
    lea     rdi, [rel path_sh]
    mov     rsi, rsp
    xor     edx, edx
    mov     eax, SYS_execve
    syscall

    ; ---- fallback: exit_group(0) ----
    xor     edi, edi
    mov     eax, SYS_exit_group
    syscall

; ---- data (RIP-relative) ----
msg_banner:     db "stager:ok", 0x0A
msg_banner_len  equ $ - msg_banner
path_sh:        db "/bin/sh", 0
arg_dash_c:     db "-c", 0
arg_cmd:        db "echo stager-ok", 0