# Rainfall-v2

## Assembly

### Registers

General registers (64 bits) :

- rax, rbx, rcx, rdx — usage général (rax souvent = valeur de retour)
- rsi, rdi — souvent 1er et 2e arguments de fonction (convention System V)
- rbp — base pointer, pointe vers le début de la stack frame courante
- rsp — stack pointer, pointe vers le sommet de la pile (adresse la plus basse utilisée)
- r8-r15 — registres supplémentaires (64 bits uniquement)
- rip — instruction pointer, adresse de la prochaine instruction

## Resources

https://medium.com/@danielorihuelarodriguez/write-your-own-shellcode-754b80630e58

https://x64.syscall.sh/

https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/rop-chaining-return-oriented-programming#little-endian-converter

https://www.arsouyes.org/articles/2019/54_Shellcode/