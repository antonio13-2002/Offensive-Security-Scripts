#!/usr/bin/env python3
from pwn import *

context.terminal = ['xterm', '-e']
exe = ELF("./space_station", checksec=False)

r = gdb.debug([exe.path], gdbscript='''
    b main
    continue
''')

r.interactive()