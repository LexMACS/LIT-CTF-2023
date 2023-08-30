#!/usr/bin/env python3
from randcrack import RandCrack
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from pwn import process
from tqdm import tqdm
from z3 import *
import random

n = 624
m = 397


umask = 0x80000000
lmask = 0x7fffffff
upper_mask = umask
lower_mask = lmask
def twist(MT):
    for i in range(0, n):
        x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
        xA = x >> 1
        if (x % 2) != 0:
            xA = xA ^ a
        MT[i] = MT[(i + m) % n] ^ xA


b = []
a = 0x9908B0DF

def xor(x, y):
	return ltb(btl(x)^btl(y))

proc = process("./s.py")
for i in range(78*2):
	proc.recv()
	proc.sendline(b'')
	val = proc.recvlineS(keepends=False)
	val = bytes.fromhex(val)
	val = [val[i:i+4] for i in range(0, len(val), 4)]
	val = val[::-1]
	for c in val:
		b.append(btl(c))

util = RandCrack()
def harden(x):
	xbit = util._to_bitarray(x)
	res = util._harden(xbit)
	return util._to_int(res)

def hardeninv(x):
	xbit = util._to_bitarray(x)
	inv = util._harden_inverse(xbit)
	return util._to_int(inv)

h = harden
hi = hardeninv

def s(*args, **keywords):
    """Solve the constraints `*args`.

    This is a simple function for creating demonstrations. It creates a solver,
    configure it using the options in `keywords`, adds the constraints
    in `args`, and invokes check.

    >>> a = Int('a')
    >>> solve(a > 0, a < 2)
    [a = 1]
    """
    s = Solver()
    s.set(**keywords)
    s.add(*args)
    if keywords.get('show', False):
        print(s)
    r = s.check()
    if r == unsat:
        return -1
    elif r == unknown:
        # fail
        return -2
        try:
            return s.model()
        except Z3Exception:
            return
    else:
        return s.model()

equations = []
for i in range(8):
	# this string is equal to m624
	string1 = f"(hi(b[{624+i}])^x{i%8})&0xffffffff"
	# mi = hi(bi)^hi(fi)
	string2 = f"(hi(b[{i+397}])^x{(i+397)%8}^(((((hi(b[{i}])^x{i%8}) & umask) + ((hi(b[{i+1}])^x{(i+1)%8}) & lmask))>>1)&0x7fffffff)^(a*((hi(b[{i+1}])^x{(i+1)%8})&1)))&0xffffffff"
	equation = string1+"=="+string2
	equations.append(equation)

init_z3_var = ', '.join([f"x{i}" for i in range(8)])+"=BitVecs('"+' '.join([f"x{i}" for i in range(8)])+"', 32)"
exec(init_z3_var)
solveString = "s(" + ",".join(equations) + ")"
result = eval(solveString)

if result != -1:
	res = result
	res = str(res)
	res = res[1:-1]
	res = res.split('\n')
	res = [c.strip() for c in res]
	for c in range(len(res)-1):
		res[c] = res[c][:-1]	
	for c in res:
		exec(c)
	resultArr = [x0, x1, x2, x3, x4, x5, x6, x7]
	resultArr = list(map(harden, resultArr))
	resultArr = list(map(ltb, resultArr))
	flg = b"".join(resultArr[::-1])
	print(flg)
else:
	print("fail!")


