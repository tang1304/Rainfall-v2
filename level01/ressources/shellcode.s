section .text
global _start
_start:
mov rdi, 0xdeadbeef
mov rax, 0x401276
call rax