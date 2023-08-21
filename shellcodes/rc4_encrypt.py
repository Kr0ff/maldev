# https://gist.githubusercontent.com/snovvcrash/3533d950be2d96cf52131e8393794d99/raw/35788127b846c99a72a9fa55b5a5db904764201c/rc4_encrypt.py
#!/usr/bin/env python3

import sys
from typing import Iterator
from base64 import b64encode

# Stolen from: https://gist.github.com/hsauers5/491f9dde975f1eaa97103427eda50071
def key_scheduling(key: bytes) -> list[int]:
	sched = [i for i in range(0, 256)]

	i = 0
	for j in range(0, 256):
		i = (i + sched[j] + key[j % len(key)]) % 256
		tmp = sched[j]
		sched[j] = sched[i]
		sched[i] = tmp

	return sched


def stream_generation(sched: list[int]) -> Iterator[bytes]:
	i, j = 0, 0
	while True:
		i = (1 + i) % 256
		j = (sched[i] + j) % 256
		tmp = sched[j]
		sched[j] = sched[i]
		sched[i] = tmp
		yield sched[(sched[i] + sched[j]) % 256]        


def encrypt(plaintext: bytes, key: bytes) -> bytes:
	sched = key_scheduling(key)
	key_stream = stream_generation(sched)
	
	ciphertext = b''
	for char in plaintext:
		enc = char ^ next(key_stream)
		ciphertext += bytes([enc])
		
	return ciphertext


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("Usage: python3 rc4_encrypt.py <path/to/file.bin>")
        sys.exit(1)
    
    _file = sys.argv[1]
    
	# msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
    with open(_file, 'rb') as f:
        result = encrypt(plaintext=f.read(), key=b'LK8mT&9o3zShqrc#V2c%tZ^qM#VhQ7DY4QyUxnEQ&6C9zn7i#TD&6j%LTz9QB')

    print(b64encode(result).decode())