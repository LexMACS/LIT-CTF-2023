#!/usr/bin/env python3
import hashlib

def test(result, s):
	h = int(hashlib.sha1(s).hexdigest()[:4], 16)
	return h==result

def complement(i):
	return i%0x10000

def search(result, required):
	bruteForcer = [32, 32, 32, 32]
	while bruteForcer[0] < 127:
		testStr = required + bytes(bruteForcer)
		if test(result, testStr):
			return testStr
		i = len(bruteForcer) - 1
		bruteForcer[i] += 1
		while bruteForcer[i] >= 127:
			bruteForcer[i] = 32
			i -= 1
			bruteForcer[i] += 1
	print("none found :(")
	return -1

if __name__=='__main__':
	print(search(complement(-0x8000), b'a'))