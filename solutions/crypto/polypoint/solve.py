from math import lcm, gcd, ceil, floor, log10
import re
from sympy.matrices import Matrix
from sympy.ntheory.modular import crt
from sympy.core.numbers import Rational

LENGTH = 76

prog = re.compile(r"(\d+),(\d+)")
with open("encoded.txt", "r") as file:
    pairs = [(int(a), int(b)) for (a, b) in [(re.match(r"\((\d+),(\d+)\)", line) or 'this is to trick the type checker since match returns an Optional'.join).group(1, 2) for line in file.read().strip().splitlines()]]

def funny(x):
    res = []
    v = 1
    for i in range(10):
        v *= x
        res.append(v)
    return res

A = Matrix([funny(x) for (x, y) in pairs]).inv()
# adding this type somehow fixes Pyright
Y: Matrix = A*Matrix([[y] for (x, y) in pairs])
C = A*Matrix([[1] for (x, y) in pairs])
fs = []
gs = []
lo = 0
hi = 0x100**LENGTH
print(f"C: {C[0, 0]}\n?: {sum([1 / Rational(x) for (x, y) in pairs])}\nd: {log10(C[0, 0].q)}\n")
for i in range(1):
    y = Y[i, 0]
    c = C[i, 0]
    a = (y - (pow(10, 12) - 1)) / c
    b = (y - pow(10, 11)) / c
    lo = max(lo, min(a, b))
    hi = min(hi, max(a, b))
    g = lcm(y.q, c.q)
    f = y * g * pow(c * g, -1, g) % g
    fs.append(f)
    gs.append(g)
    print(f"c: {log10(abs(c))}\ng: {log10(g)}\n")
(f, g) = crt(gs, fs) or (-1, -1)
print(f"g: {log10(g)}\n")
lo = ceil(lo)
hi = ceil(hi)
if (hi - lo >= g):
    print(f"rip {(hi - lo) / g}")
k = ceil((lo - f) / g)
print(int.to_bytes(int(f + k*g), length=LENGTH))
