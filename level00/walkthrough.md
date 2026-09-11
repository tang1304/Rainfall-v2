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


There is the `auth_loop` function calling gets() which reads from an input, and allocate 64 bytes. But it is known to be unsafe because of the lack of the buffer size control. So we can use this function to overflow the buffer and fill the stack with a payload we need.

## Tests

We can use gdb without the env vars here: `env -i gdb case`

![alt text](<./ressources/gets_ghidra.png>)

We want to find the address of the buffer allocated by gets() to write our shellcode in it. We can do that by setting a breakpoint on the `gets` call and printing the value of the `rdi` register which contains the address of the buffer.

```shell
env -i gdb -q case
(gdb) b *0x401596 #gets call
(gdb) run
(gdb) c
AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZzAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401630 in auth_loop ()
```
This segfault return is bad because it is stuck int the `auth_loop` ret. So we can'tuse this method to find the buffer address as in the previous Rainfall version. So the ret2shellcode method is not possible here. We need to find another way to get the buffer address.

To see the buffer address, we can use gdb to print the value of the `rdi` register after the `gets` call. This will give us the address of the buffer allocated by `gets()`.

```shell
env -i gdb -q case
(gdb) b *0x401596 #gets call
(gdb) run
(gdb) p/x $rdi
$1 = 0x7fffffffec60
```

## Ressources

https://medium.com/@danielorihuelarodriguez/write-your-own-shellcode-754b80630e58

https://x64.syscall.sh/